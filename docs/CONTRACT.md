# Shared Contract (v1)

**Breaking this contract breaks someone else's module.** Change it only through a PR to this file,
approved by Person 1 and the owners of the affected modules. Code lives in
`libs/common/smartsecure_common`; use it instead of hand-writing topic strings.

## 1. MQTT topics

| Purpose | Topic | Publisher | QoS | Retain |
|---|---|---|---|---|
| Sensor/device event | `home/<zone>/<device_type>/<device_id>/event` | simulators / real devices | 1 | no |
| Command to device | `home/<zone>/<device_type>/<device_id>/cmd` | engine, api | 1 | no |
| Device state/online | `home/<zone>/<device_type>/<device_id>/status` | device (LWT = `offline`) | 1 | **yes** |
| Vision alert | `security/alerts/vision` | vision | 1 | no |
| Cyber alert | `security/alerts/cyber` | cyber | 1 | no |
| Engine alert | `security/alerts/engine` | engine | 1 | no |
| Risk state | `security/risk` | engine | 1 | yes |
| Incident updates | `security/incidents` | engine | 1 | no |
| Service heartbeat | `system/heartbeat/<service>` | every service (5 s) | 0 | no |

Topic tokens are lowercase `a-z 0-9 _` only. Zones are listed in `config/zones.yaml`.
Per-service permissions are enforced by `infra/mosquitto/acl.conf`, so a compromised service
cannot publish outside its lane. New topic = update the ACL in the same PR.

## 2. Event envelope (`contract/event.schema.json`)

```json
{
  "id": "uuid",
  "ts": "2026-10-06T10:30:26.120+00:00",
  "source": "vision",
  "type": "face.unknown",
  "zone": "garage",
  "severity_hint": "high",
  "data": {"confidence": 0.93, "snapshot": "snapshots/abc.jpg"}
}
```

Rules: `ts` is UTC ISO-8601 (never local time). `type` is `<domain>.<name>`, lowercase.
`severity_hint` is advisory; **only the engine decides the final score.**
`data` is free-form per type, but fields in the registry below are required.

## 3. Event type registry

| type | Producer | Required `data` | Score (config/risk_scores.yaml) |
|---|---|---|---|
| `face.unknown` | vision | `confidence`, `snapshot` | 40 |
| `person.detected` | vision | `confidence` | not scored |
| `vehicle.detected` | vision | `confidence` | not scored |
| `package.detected` | vision | `confidence` | not scored |
| `motion.night` | simulators | `sensor_id` | 20 |
| `lock.login_failed` | simulators | `lock_id`, `attempts` | 30 |
| `camera.disconnected` | simulators/vision | `camera_id` | 35 |
| `smoke.detected` | simulators/vision | `sensor_id` | 100 |
| `water.leak` | simulators | `sensor_id` | engine rule |
| `cyber.port_scan` | cyber | `src_ip`, `dst_ip`, `ports` | 25 |
| `cyber.brute_force` | cyber | `src_ip`, `target` | engine rule |
| `cyber.rogue_device` | cyber | `mac`, `ip` | engine rule |

Adding a type: add a row here, then (if scored) a line in `config/risk_scores.yaml`.

## 4. Commands (`.../cmd`)

`{"id": "uuid", "ts": "...", "action": "on|off|lock|unlock|close|open", "reason": "incident-42"}`
Devices must be idempotent and publish their new state to `.../status`.

## 5. REST/WebSocket
Owned by Person 2 via OpenAPI at `https://localhost:8443/docs` (served only while
`API_DOCS_ENABLED=true`, which the dev `.env` sets and production must not).
Auth: JWT bearer. Login with
`POST /auth/login {"username","password"}` (users come from `API_USERS`) to get a
token, then send `Authorization: Bearer <token>`. Use the `require_token`
dependency in `services/api/security.py`; `/health` stays public.
The frontend talks only to the API, never directly to MQTT.

## 6. Environment variables (all services)
`MQTT_HOST`, `MQTT_PORT`, `MQTT_USER`, `MQTT_PASSWORD`, `MQTT_CA_FILE`,
`MQTT_CLIENT_CERT`, `MQTT_CLIENT_KEY`. Nothing hardcoded.
The broker requires mutual TLS: every client presents a cert whose CN is its
username (`infra/certs/clients/<service>.crt`, issued by `scripts/gen-certs.sh`).
This is what makes the Raspberry Pi phase a config change.
