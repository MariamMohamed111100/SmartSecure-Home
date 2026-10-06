# SmartSecure Home

AI-powered smart home security: AI vision + cybersecurity + IoT automation + digital twin,
correlated into one risk score with automated response. Developed fully simulated first,
then moved to Raspberry Pi hardware (milestone M4).

## Quick start (any laptop with Docker and openssl)

```bash
make setup     # REQUIRED on a fresh clone: random secrets -> .env, local CA + TLS certs, MQTT users
make up        # build and start everything
make smoke     # proves every service talks through the TLS broker, mTLS + ACLs, API auth
```

**Windows:** run everything from **Git Bash** (not PowerShell/cmd) — the scripts are bash and
already disable MSYS path conversion themselves. **Port 8080 taken?** set `DASHBOARD_PORT` in
`.env` (setup writes it, compose reads it).

| Thing | URL |
|---|---|
| Dashboard + same-origin `/api` proxy (reverse proxy → HTTPS API, no CORS) | http://localhost:8080 |
| API docs (HTTPS, self-signed CA in `infra/certs/ca.crt`) | https://localhost:8443/docs |
| MQTT broker (TLS only) | `localhost:8883` |
| Demo rig (`docker compose --profile demo up`): RTSP | `rtsp://localhost:8554` |
| Demo rig: ntfy push notifications | http://localhost:8090 |

Debug a topic live:
```bash
docker compose exec mosquitto mosquitto_sub -h localhost -p 8883 --cafile /mosquitto/config/certs/ca.crt \
  --cert /mosquitto/config/certs/admin.crt --key /mosquitto/config/certs/admin.key \
  -u admin -P "$(grep MQTT_PASSWORD_ADMIN .env | cut -d= -f2)" -t 'security/#' -v
```

## Security model
- **Mutual TLS MQTT** (`localhost:8883`, TLS 1.3 only): the broker requires a client
  certificate signed by the local CA; the CN is the MQTT username.
  **Every container mounts only its own client cert + CA certificate**, and private keys are
  served as Docker secrets (`/run/secrets/`, mode 0444) — never through a bind mount. The
  CA private key (`infra/ca/ca.key`) stays on the host, so a compromised service **cannot
  mint certificates** or impersonate another service, and per-service ACLs
  (`infra/mosquitto/acl.conf`) stop it reading/writing outside its lane. The smoke test
  asserts both directions: cert-less clients are refused *and* a service cannot read an
  engine-only topic.
- **JWT-protected API** (via the dashboard's `/api` reverse proxy, TLS verified against the local CA):
  `POST /auth/login` issues a token; everything but `/health` requires
  `Authorization: Bearer <token>`. Login attempts are rate-limited (5 failures/minute),
  passwords compare constant-time, and Swagger serves only with `API_DOCS_ENABLED=true`.
- **At-rest encryption (API, Person 2)**: persisted records are sealed with AES-256-GCM
  (`libs/common/smartsecure_common/crypto.py`, key `STORAGE_KEY`); tampering fails closed.
- **Fire safety policy**: `block_ip` fires from level **High** (so the demo pans out), and at
  **Critical** doors are *unlocked*, never locked (`config/risk_scores.yaml`).
- **Secrets never in git**: `.env`, certificates and MQTT passwords are git-ignored and
  excluded from Docker build contexts (`.dockerignore`). All files use LF line endings
  (`.gitattributes`). CI runs `gitleaks`, `pip-audit` and CodeQL so a leak or CVE fails a PR.
- **Dev CA caveat**: certificates are self-signed dev artifacts with finite lifetimes
  (CA 5y, leaves 397d). Rotate by deleting `infra/certs/*` (and `infra/ca/`, to re-key the
  CA) and re-running `./scripts/setup.sh`. Do not ship these to a real deployment.

## Repo layout

```
services/<module>/    one folder per module (own requirements.txt and main.py)
libs/common/          shared topics, event model, TLS MQTT helper (use it!)
contract/ config/     event schema, risk scores, zones
infra/                Mosquitto config + ACL, generated certs (git-ignored)
docker/               shared Python Dockerfile
scripts/              setup, smoke test, GitHub bootstrap
docs/                 CONTRACT, BRANCHING, STANDUP, DEMO_SCRIPT
```

## Module owners (Milestone 1)

Owner-side setup (one-time, manual): enable the `main` branch-protection rule and replace the
placeholder handles in `.github/CODEOWNERS` — see `docs/BRANCHING.md`.

| # | Module | Folder |
|---|---|---|
| 1 | Lead / DevOps / Security foundations | `infra/ docker/ scripts/ contract/` |
| 2 | Backend API | `services/api` |
| 3 | IoT simulation + scenarios | `services/simulators` |
| 4 | AI surveillance | `services/vision` |
| 5 | Cybersecurity | `services/cyber` |
| 6 | Risk, correlation, response | `services/engine` |
| 7 | Frontend / digital twin | `services/frontend` |

## How to add dependencies or a new service
1. Add packages to your `services/<module>/requirements.txt`.
2. New MQTT user? Add it to `scripts/setup.sh`, `scripts/gen-mqtt-passwd.sh` and `infra/mosquitto/acl.conf`.
3. Read `docs/CONTRACT.md` before inventing topic names.

## Timeline (Milestone 1: 7 days)
D1 contract + skeleton | D2 modules in isolation | D3 events on MQTT | **D4 first integration** |
D5 correlation + response + timeline | D6 hardening + feature freeze | D7 demo.

## Raspberry Pi readiness
Everything is configured via environment variables and talks only through MQTT/REST, so the Pi
phase swaps simulator drivers for real ones behind the hardware abstraction layer. All base images
used here (`python:3.12-slim`, `eclipse-mosquitto`, `postgres`, `nginx`) publish ARM64 variants.
