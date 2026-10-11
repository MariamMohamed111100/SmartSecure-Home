"""The engine: events in -> risk score, correlation, incident, automated response out.

The class knows nothing about MQTT. It is fed `on_message(topic, payload)` and calls
`publish(topic, payload_dict, retain)`, so tests (and the in-process demo) drive it with no broker.

What it publishes (CONTRACT sections 1, 4.1, 4.3, 4.4):
    security/risk       retained snapshot, whenever score / level / zone / actions change
    security/incidents  the incident, re-sent with the same id whenever it changes
    home/<z>/<t>/<id>/cmd   commands to devices (on/off/lock/unlock/open/close)
    system/block        block an attacker IP at the firewall (cyber executes it)
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import ValidationError

from smartsecure_common import Event, topics

from .notify import Notifier
from .policy import LEVELS, Policy, attacker_ip
from .registry import DeviceRegistry
from .scoring import NON_PHYSICAL_ZONES, Scorer

log = logging.getLogger("engine")

Publish = Callable[[str, dict, bool], None]
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_INCIDENT_EVENTS = 200
SEEN_IDS = 4096
ALERT_SOURCES = ("vision", "cyber")           # security/alerts/<source> the engine listens to


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Incident:
    id: str
    opened: float
    trigger: str
    peak: int = 0
    event_ids: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)       # distinct action names, in order
    notes: list[str] = field(default_factory=list)         # what was done to which device
    closed: bool = False
    published: tuple | None = None


class Engine:
    def __init__(self, policy: Policy, publish: Publish, notifier: Notifier | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.policy, self._publish, self.clock = policy, publish, clock
        self.notifier = notifier or Notifier()
        self.scorer = Scorer(policy)
        self.registry = DeviceRegistry()
        self.lock = threading.RLock()
        self.incident: Incident | None = None
        self.attackers: dict[str, str] = {}                 # ip -> the event type that named it
        self.life_safety = False
        self.done: set[tuple] = set()                       # actions already taken (per episode)
        self.sirens_on: list[tuple[str, str, str]] = []
        self.last_zone = "network"
        self._risk_sent: tuple | None = None
        self._seen: OrderedDict[str, None] = OrderedDict()

    # ------------------------------------------------------------------ intake
    def on_message(self, topic: str, payload: bytes | str) -> None:
        """Entry point for every MQTT message. Never raises: a bad message is dropped."""
        try:
            self._route(topic, payload)
        except Exception:
            log.exception("could not process a message on %s", topic)

    def _route(self, topic: str, payload: bytes | str) -> None:
        parts = topic.split("/")
        is_device = len(parts) == 5 and parts[0] == "home" and parts[4] in ("event", "status")
        is_alert = (len(parts) == 3 and parts[:2] == ["security", "alerts"]
                    and parts[2] in ALERT_SOURCES)
        if not (is_device or is_alert):
            return
        raw = payload.encode() if isinstance(payload, str) else payload
        if len(raw) > MAX_PAYLOAD_BYTES:
            log.warning("dropped an oversized message on %s", topic)
            return
        try:
            body = json.loads(raw)
        except ValueError:
            log.warning("dropped a non-JSON message on %s", topic)
            return
        if not isinstance(body, dict):
            return
        if is_device and parts[4] == "status":
            online = body.get("online")
            if isinstance(online, bool):
                self.registry.update(parts[1], parts[2], parts[3], online)
            return
        try:
            event = Event.model_validate(body)
        except ValidationError as exc:
            log.warning("dropped an invalid event on %s: %s", topic, exc.errors()[:1])
            return
        if is_device and event.zone != parts[1]:           # same rule the API applies
            log.warning("dropped an event whose zone %r does not match its topic", event.zone)
            return
        self.handle_event(event)

    # ------------------------------------------------------------------ one event
    def handle_event(self, event: Event) -> None:
        with self.lock:
            if event.id in self._seen:                      # QoS 1 may deliver twice
                return
            self._seen[event.id] = None
            while len(self._seen) > SEEN_IDS:
                self._seen.popitem(last=False)

            now = self.clock()
            contrib = self.scorer.add_event(event.type, event.zone, event.id, now)
            self.scorer.correlate(now)
            if contrib:
                ip = attacker_ip(event.data.get("src_ip"), self.policy.never_block)
                if ip:
                    self.attackers.setdefault(ip, event.type)
            if event.type in self.policy.life_safety:
                self.life_safety = True

            score = self.scorer.score(now)
            level = self.policy.level_for(score)
            if self.incident is None and self.policy.rank(level) >= 1:
                self._open_incident(event, now)
            inc = self.incident
            if inc is not None:
                if contrib and contrib.event_id not in inc.event_ids:
                    inc.event_ids.append(contrib.event_id)
                inc.peak = max(inc.peak, score)

            reason = inc.id if inc else f"event:{event.type}"
            self._respond(level if inc else "low", event, reason)
            self._publish_state(now)

    def _open_incident(self, event: Event, now: float) -> None:
        stamp = datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.incident = Incident(id=f"incident-{stamp}-{uuid.uuid4().hex[:4]}", opened=now,
                                 trigger=event.type,
                                 event_ids=self.scorer.event_ids()[:MAX_INCIDENT_EVENTS])
        self._note("log", "incident opened")
        log.info("incident %s opened by %s", self.incident.id, event.type)

    # ------------------------------------------------------------------ responses
    def _respond(self, level: str, event: Event, reason: str) -> None:
        names: list[tuple[str, str]] = []
        for lvl in LEVELS[1:self.policy.rank(level) + 1]:
            names += [(a, lvl) for a in self.policy.responses[lvl]]
        names += [(a, "event") for a in self.policy.event_actions.get(event.type, ())]
        names.sort(key=lambda item: item[0] == "notify")        # notify last: it reports the rest
        for name, scope in names:
            handler = getattr(self, f"_do_{name}")
            handler(reason, event.zone, scope, level)

    def _note(self, action: str, text: str, record: bool = True) -> None:
        inc = self.incident
        if inc is None:
            return
        if record and action not in inc.actions:
            inc.actions.append(action)
        inc.notes.append(text)

    def _once(self, *key: str) -> bool:
        if key in self.done:
            return False
        self.done.add(key)
        return True

    def _command(self, device: tuple[str, str, str], action: str, reason: str) -> None:
        zone, dtype, did = device
        payload = {"id": uuid.uuid4().hex, "ts": iso(self.clock()), "action": action,
                   "reason": reason, "requested_by": "engine"}
        self._publish(topics.device_cmd(zone, dtype, did), payload, False)

    def _send_to(self, action_name: str, dtype: str, command: str, zone: str | None,
                 reason: str) -> None:
        targets = self.registry.find(dtype, zone)
        if not targets:
            self._note(action_name, f"{action_name}: no reachable {dtype} known", record=False)
            return
        done_any = []
        for device in targets:
            if self._once(action_name, device[2]):
                self._command(device, command, reason)
                done_any.append(device[2])
                if action_name == "siren":
                    self.sirens_on.append(device)
        if done_any:
            self._note(action_name, f"{action_name} -> {', '.join(done_any)}")

    def _zone(self, event_zone: str) -> str:
        inc_zone = self.scorer.main_zone()
        return inc_zone or (event_zone if event_zone not in NON_PHYSICAL_ZONES else "network")

    def _do_log(self, reason: str, zone: str, scope: str, level: str) -> None:
        if self.incident and "log" not in self.incident.actions:
            self.incident.actions.append("log")

    def _do_notify(self, reason: str, zone: str, scope: str, level: str) -> None:
        if not self.incident or not self._once("notify", level):
            return
        inc = self.incident
        summary = self._summary(inc, level, self._zone(zone))
        channels = self.notifier.send(f"{level.upper()} risk in {self._zone(zone)}", summary, level)
        self._note("notify", f"notify via {','.join(channels)} ({level})")

    def _do_lights_on(self, reason: str, zone: str, scope: str, level: str) -> None:
        self._send_to("lights_on", "bulb", "on", self._zone(zone), reason)

    def _do_siren(self, reason: str, zone: str, scope: str, level: str) -> None:
        self._send_to("siren", "siren", "on", None, reason)

    def _do_close_valve(self, reason: str, zone: str, scope: str, level: str) -> None:
        self._send_to("close_valve", "valve", "close", zone if zone not in NON_PHYSICAL_ZONES
                      else None, reason)

    def _do_unlock_doors(self, reason: str, zone: str, scope: str, level: str) -> None:
        """Only when people may have to get out (fire, smoke, gas). An intruder gets no help:
        for an intrusion at Critical the doors are left exactly as they are."""
        if not self.life_safety:
            if self._once("unlock_doors", "skipped"):
                self._note("unlock_doors", "doors left as they are: no fire/smoke/gas involved",
                           record=False)
            return
        self._send_to("unlock_doors", "lock", "unlock", None, reason)

    def _do_block_ip(self, reason: str, zone: str, scope: str, level: str) -> None:
        for ip, event_type in self.attackers.items():
            if not self._once("block_ip", ip):
                continue
            self._publish(topics.BLOCK, {
                "id": uuid.uuid4().hex, "ts": iso(self.clock()), "ip": ip,
                "reason": event_type, "window_seconds": self.policy.block_window_s}, False)
            self._note("block_ip", f"block_ip -> {ip} ({event_type})")

    # ------------------------------------------------------------------ time
    def tick(self, now: float | None = None) -> None:
        """Called every few seconds: expire old events and close the incident at risk 0."""
        with self.lock:
            now = self.clock() if now is None else now
            if self.scorer.score(now) == 0 and self.incident is not None:
                self._close_incident(now)
            self._publish_state(now)

    def _close_incident(self, now: float) -> None:
        inc = self.incident
        assert inc is not None
        for device in self.sirens_on:                       # silence what we started
            self._command(device, "off", inc.id)
        inc.closed = True
        self._note("log", "incident closed: risk decayed to 0", record=False)
        self._publish_incident(inc, now, self._zone("network"))
        log.info("incident %s closed", inc.id)
        self.incident = None
        self.attackers.clear()
        self.done.clear()
        self.sirens_on.clear()
        self.life_safety = False

    # ------------------------------------------------------------------ publishing
    def _summary(self, inc: Incident, level: str, zone: str) -> str:
        types = list(dict.fromkeys(f["type"] for f in self.scorer.factors(8)))
        what = ", ".join(types[:6]) or "no live events"
        text = f"{level.capitalize()} risk {inc.peak} in {zone}: {what}."
        acted = [a for a in inc.actions if a not in ("log", "notify")]
        if acted:
            text += " Actions: " + ", ".join(acted) + "."
        done = [n for n in inc.notes if "->" in n]
        if done:
            text += " " + "; ".join(done[-6:]) + "."
        if inc.closed:
            text += " Closed: risk decayed to 0."
        return text[:3900]

    def _publish_incident(self, inc: Incident, now: float, zone: str) -> None:
        level = self.policy.level_for(inc.peak)
        state = (inc.peak, zone, tuple(inc.event_ids), tuple(inc.actions), inc.closed)
        if state == inc.published:
            return
        inc.published = state
        self._publish(topics.INCIDENTS, {
            "id": inc.id, "ts": iso(now), "zone": zone, "level": level, "score": inc.peak,
            "trigger": inc.trigger, "events": inc.event_ids[:MAX_INCIDENT_EVENTS],
            "actions": list(inc.actions), "summary": self._summary(inc, level, zone)}, False)

    def _publish_state(self, now: float) -> None:
        score = self.scorer.score(now)
        level = self.policy.level_for(score)
        zone = self.scorer.main_zone() or (self.last_zone)
        self.last_zone = zone
        inc = self.incident
        if inc is not None:
            self._publish_incident(inc, now, zone)
        actions = tuple(inc.actions) if inc else ()
        state = (score, level, zone, actions)
        if state == self._risk_sent:
            return
        self._risk_sent = state
        self._publish(topics.RISK, {
            "ts": iso(now), "zone": zone, "level": level, "score": score,
            "factors": self.scorer.factors(), "actions": list(actions)}, True)
