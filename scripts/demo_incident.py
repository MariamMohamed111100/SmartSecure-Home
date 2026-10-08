#!/usr/bin/env python3
"""Plays the proposal's demo incident end to end: garage intruder, risk 85, siren.

    make demo-incident                  # or: python scripts/demo_incident.py [--speed 2]

Timeline (from the proposal):
    10:30:21  Motion detected - Garage      real simulators scenario `garage_intruder`
    10:30:24  Unknown face identified       security/alerts/vision   (played by this script)
    10:30:26  Port scan from 192.168.1.15   security/alerts/cyber    (played by this script)
    10:30:28  Risk Score = 85 (High)        security/risk + security/incidents (played)
    10:30:29  Garage lights ON              POST /devices/bulb_garage/command
    10:30:30  Alarm activated               POST /devices/siren_main/command

Until the vision, cyber and engine modules exist, this script plays THEIR roles. It uses the
broker's `admin` identity, so it proves the data path and the dashboard, not those modules'
ACLs. Push notifications belong to the engine and are not simulated here.
Afterwards it checks, through the API, that everything arrived and exits 1 if it did not.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ws_listen  # noqa: E402  (credential helpers shared with the websocket debug tool)

ROOT = Path(__file__).resolve().parent.parent
SCENARIO = "garage_intruder"


class Transport(Protocol):
    def trigger_scenario(self, name: str) -> None: ...
    def publish(self, topic: str, payload: dict) -> None: ...
    def api(self, method: str, path: str, body: dict | None = None,
            params: dict | None = None) -> tuple[int, Any]: ...
    def sleep(self, seconds: float) -> None: ...


class DockerTransport:
    """Real stack: docker compose + mTLS broker (as admin) + HTTPS API verified against our CA."""

    def __init__(self, base: str, ca: str) -> None:
        self.base = base
        self.ctx = ssl.create_default_context(cafile=ca)
        self.user, self.password = ws_listen.default_credentials()
        self.token: str | None = None
        self.env = {**os.environ, "MSYS_NO_PATHCONV": "1", "MSYS2_ARG_CONV_EXCL": "*"}
        self.mqtt_password = self._env_value("MQTT_PASSWORD_ADMIN")

    @staticmethod
    def _env_value(name: str) -> str:
        value = os.getenv(name)
        env_file = ROOT / ".env"
        if not value and env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith(name + "="):
                    value = line.split("=", 1)[1].strip()
        if not value:
            sys.exit(f"{name} not found: run ./scripts/setup.sh first")
        return value

    def _compose(self, *args: str, stdin: bytes | None = None) -> None:
        result = subprocess.run(["docker", "compose", "exec", "-T", *args], cwd=ROOT,
                                input=stdin, capture_output=True, env=self.env)
        if result.returncode != 0:
            sys.exit(f"docker compose exec {' '.join(args[:3])} failed:\n"
                     f"{result.stderr.decode(errors='replace')[-600:]}")

    def trigger_scenario(self, name: str) -> None:
        self._compose("simulators", "python", "scenario_runner.py", name)

    def publish(self, topic: str, payload: dict) -> None:
        self._compose(
            "mosquitto", "mosquitto_pub", "-h", "localhost", "-p", "8883",
            "--cafile", "/mosquitto/config/certs/ca.crt",
            "--cert", "/mosquitto/config/certs/admin.crt",
            "--key", "/mosquitto/config/certs/admin.key",
            "-u", "admin", "-P", self.mqtt_password, "-q", "1", "-t", topic, "-s",
            stdin=json.dumps(payload).encode(),
        )

    def _request(self, method: str, path: str, body: dict | None, token: str | None):
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            self.base + path, method=method, headers=headers,
            data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(request, context=self.ctx, timeout=15) as response:
                return response.status, json.loads(response.read() or b"null")
        except urllib.error.HTTPError as exc:
            return exc.code, None

    def api(self, method, path, body=None, params=None):
        if self.token is None:
            status, data = self._request(
                "POST", "/auth/login", {"username": self.user, "password": self.password}, None)
            if status != 200:
                sys.exit(f"API login failed (HTTP {status}). Is the stack up? (make up)")
            self.token = data["access_token"]
        if params:
            path += "?" + urllib.parse.urlencode(params)
        return self._request(method, path, body, self.token)

    def sleep(self, seconds: float) -> None:
        import time
        time.sleep(seconds)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def build_alert(source: str, type_: str, zone: str, severity: str, at: datetime, **data) -> dict:
    """The event envelope of CONTRACT section 2."""
    return {"id": str(uuid.uuid4()), "ts": _iso(at), "source": source, "type": type_,
            "zone": zone, "severity_hint": severity, "data": data}


def play(t: Transport, *, speed: float = 1.0, out=print) -> list[str]:
    """Run the incident. Returns the list of failed checks (empty = everything arrived)."""
    failures: list[str] = []
    run = uuid.uuid4().hex[:6]
    incident_id = f"incident-demo-{run}"

    def pause(seconds: float) -> None:
        t.sleep(seconds / speed)

    def body(path: str, **params):
        """The response body, but only for a successful (200) response."""
        status, data = t.api("GET", path, params=params or None)
        return data if status == 200 else None

    def poll(what: str, fetch, attempts: int = 30):
        """Retry every 0.5 s (about 15 s in total); record a failure if it never succeeds."""
        for _ in range(attempts):
            value = fetch()
            if value:
                return value
            t.sleep(0.5)
        failures.append(f"timed out waiting for: {what}")
        out(f"  FAIL  {what}")
        return None

    def latest_motion_id() -> str | None:
        events = body("/events", type="motion.night", zone="garage", limit=1)
        return events[0]["id"] if events else None

    out("== Demo incident: garage intruder (proposal timeline) ==")
    previous = latest_motion_id()

    def new_motion() -> str | None:
        current = latest_motion_id()
        return current if current not in (None, previous) else None

    out("  t+0s  Motion detected - Garage  (simulators scenario)")
    t.trigger_scenario(SCENARIO)
    motion = poll("the motion.night event to reach the API", new_motion)
    if not motion:
        return failures
    motion_event = body(f"/events/{motion}")
    if not motion_event:
        failures.append("could not read back the motion event")
        return failures
    base = datetime.fromisoformat(motion_event["ts"])      # the demo clock starts at the motion

    pause(3)
    face = build_alert("vision", "face.unknown", "garage", "high", base + timedelta(seconds=3),
                       confidence=0.93, snapshot=f"snapshots/demo-{run}.jpg")
    out("  t+3s  Unknown face identified   -> security/alerts/vision")
    t.publish("security/alerts/vision", face)

    pause(2)
    scan = build_alert("cyber", "cyber.port_scan", "network", "medium", base + timedelta(seconds=5),
                       src_ip="192.168.1.15", dst_ip="192.168.1.10", ports=[22, 80, 443, 8883])
    out("  t+5s  Port scan from 192.168.1.15 -> security/alerts/cyber")
    t.publish("security/alerts/cyber", scan)

    pause(2)
    decided = base + timedelta(seconds=7)
    actions = ["log", "notify", "lights_on", "siren"]
    out("  t+7s  Risk Score = 85 (High)    -> security/risk, security/incidents")
    t.publish("security/risk", {
        "ts": _iso(decided), "zone": "garage", "level": "high", "score": 85, "actions": actions,
        "factors": [{"type": "motion.night", "weight": 20}, {"type": "face.unknown", "weight": 40},
                    {"type": "cyber.port_scan", "weight": 25}]})
    t.publish("security/incidents", {
        "id": incident_id, "ts": _iso(decided), "zone": "garage", "level": "high", "score": 85,
        "trigger": "face.unknown", "events": [motion, face["id"], scan["id"]], "actions": actions,
        "summary": "Garage intruder: night motion + unknown face + port scan from 192.168.1.15"})

    pause(1)
    out("  t+8s  Garage lights ON          -> POST /devices/bulb_garage/command")
    status_a, _ = t.api("POST", "/devices/bulb_garage/command",
                        {"action": "on", "reason": incident_id})
    pause(1)
    out("  t+9s  Alarm activated           -> POST /devices/siren_main/command")
    status_b, _ = t.api("POST", "/devices/siren_main/command",
                        {"action": "on", "reason": incident_id})
    if (status_a, status_b) != (200, 200):
        failures.append(f"device commands rejected (HTTP {status_a}, {status_b})")

    out("\n== Checking what the API now holds ==")

    def check(name: str, ok: bool) -> None:
        out(("  PASS  " if ok else "  FAIL  ") + name)
        if not ok:
            failures.append(name)

    incident = poll("the incident to be stored", lambda: body(f"/incidents/{incident_id}"))
    if incident:
        stored = (incident["score"], incident["level"], incident["integrity_ok"])
        check("incident stored: score 85, High, integrity ok", stored == (85, "high", True))
        timeline = body(f"/incidents/{incident_id}/events")
        check("timeline replays 3 events in order: motion, face, port scan",
              [e["type"] for e in timeline or []] ==
              ["motion.night", "face.unknown", "cyber.port_scan"])
    risk = body("/risk") or []
    check("risk snapshot for the garage is 85 (High)",
          any(r["zone"] == "garage" and r["score"] == 85 and r["level"] == "high" for r in risk))

    def state_of(device_id: str):
        devices = body("/devices") or []
        return next((d["state"] for d in devices if d["device_id"] == device_id), {})

    poll("the garage light to report ON", lambda: state_of("bulb_garage").get("power") == "on")
    poll("the siren to report ON", lambda: state_of("siren_main").get("power") == "on")
    check("garage light is ON", state_of("bulb_garage").get("power") == "on")
    check("siren is ON", state_of("siren_main").get("power") == "on")
    audit = body("/audit", limit=20) or []
    check("both commands are in the audit trail with the incident id",
          sum(1 for a in audit if a["action"] == "device.command"
              and a["details"].get("reason") == incident_id) == 2)

    out("\n" + ("DEMO OK: everything arrived." if not failures else
                f"DEMO FAILED: {len(failures)} problem(s)."))
    return failures


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="https://localhost:8443")
    ap.add_argument("--ca", default=str(ROOT / "infra/certs/ca.crt"))
    ap.add_argument("--speed", type=float, default=1.0, help="2 = twice as fast")
    args = ap.parse_args()
    sys.exit(1 if play(DockerTransport(args.base, args.ca), speed=args.speed) else 0)


if __name__ == "__main__":
    main()
