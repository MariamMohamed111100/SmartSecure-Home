# Engine (Person 6): risk, correlation, response

Listens to device events and the vision/cyber alerts, keeps a decaying risk score, opens an
incident, and reacts (lights, siren, IP block, notification). Rules live in
`config/risk_scores.yaml`; behaviour is described in `docs/CONTRACT.md` section 9.

    eng/policy.py    load + validate the YAML, strict attacker-IP checks
    eng/scoring.py   decaying score, repeat cap, correlation, main zone
    eng/registry.py  which devices exist (from retained `status` messages)
    eng/core.py      Engine: events in -> risk / incident / commands / block out (no MQTT inside)
    eng/notify.py    ntfy.sh / Telegram (optional, dry-run when unset)
    eng/service.py   MQTT glue: mTLS connect, re-subscribe on reconnect, 5 s tick, heartbeat

Run the tests: `pytest services/engine/tests -q` (no broker needed).
Try it: `make demo-incident` (the script stages vision + cyber; the engine decides).

Notifications (optional, free): set `NTFY_TOPIC` (install the ntfy app, subscribe to that topic)
or `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` in `.env`. Unset = messages are logged only.

Safety choices: Critical never locks anyone in; doors unlock only for fire/smoke/gas. The engine
cannot block loopback, multicast or link-local addresses, nor anything in `never_block`.
