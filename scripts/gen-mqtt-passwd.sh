#!/usr/bin/env bash
# Builds infra/mosquitto/passwd from the MQTT_PASSWORD_* values in .env
set -euo pipefail
cd "$(dirname "$0")/.."
# Windows (Git Bash/MSYS): disable argument path conversion. Without this, MSYS
# rewrites the mount target "/work" into "C:/Program Files/Git/work" and the
# password file silently never appears inside the container.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' ;;
esac
# Windows: the `docker` CLI is not on PATH for Git Bash unless added manually.
if ! command -v docker >/dev/null 2>&1; then
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      for p in "/c/Program Files/Docker/Docker/resources/bin" \
               "${LOCALAPPDATA:-/c/Users/$USER/AppData/Local}/Programs/DockerDesktop/resources/bin"; do
        if [ -x "$p/docker.exe" ]; then export PATH="$p:$PATH"; break; fi
      done
      ;;
  esac
fi
set -a; . ./.env; set +a
USERS=(admin api simulators vision cyber engine)
OUT=infra/mosquitto/passwd
upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }   # ${u^^} needs bash 4
: > "$OUT"

if command -v mosquitto_passwd >/dev/null 2>&1; then
  for u in "${USERS[@]}"; do
    v="MQTT_PASSWORD_$(upper "$u")"; mosquitto_passwd -b "$OUT" "$u" "${!v}"
  done
else
  cmds=""
  for u in "${USERS[@]}"; do
    v="MQTT_PASSWORD_$(upper "$u")"; cmds+="mosquitto_passwd -b /work/passwd $u ${!v}; "
  done
  docker run --rm -v "$PWD/infra/mosquitto:/work" eclipse-mosquitto:2 sh -c "$cmds"
fi
chmod 600 "$OUT"   # owner-only; the broker entrypoint fixes ownership in-container
echo ">> MQTT users written: ${USERS[*]}"
