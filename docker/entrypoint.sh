#!/bin/sh
# Docker Compose on Linux mounts /run/secrets/* as root:root with mode 0400
# (service `uid`/`gid`/`mode` are unsupported and ignored), so the non-root
# app user cannot read them. Copy each secret to a world-readable path owned
# by app, then drop privileges and run the service.
set -e

KEYS=/run/app-secrets
mkdir -p "$KEYS"
for f in /run/secrets/*; do
    [ -e "$f" ] || continue
    cp "$f" "$KEYS/$(basename "$f")"
    chmod 0444 "$KEYS/$(basename "$f")"
done
chown -R app:app "$KEYS"

exec gosu app "$@"