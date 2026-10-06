#!/usr/bin/env bash
# Local CA + server certs for Mosquitto (MQTT/TLS) and the API (HTTPS). Idempotent.
set -euo pipefail
# Windows (Git Bash/MSYS): disable argument path conversion. Without this, MSYS
# rewrites OpenSSL's DN arguments (e.g. -subj "/CN=SmartSecure Dev CA/O=...")
# into "C:/Program Files/Git/CN=..." and openssl aborts.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' ;;
esac
cd "$(dirname "$0")/../infra/certs"

if [ ! -f ca.crt ]; then
  echo ">> Creating local CA"
  openssl ecparam -genkey -name prime256v1 -noout -out ca.key
  openssl req -x509 -new -key ca.key -sha256 -days 1825 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -subj "/CN=SmartSecure Dev CA/O=SmartSecure" -out ca.crt
fi

issue() {  # issue <name> <SAN list>
  local name="$1" san="$2"
  [ -f "$name.crt" ] && return 0
  echo ">> Issuing certificate: $name"
  openssl ecparam -genkey -name prime256v1 -noout -out "$name.key"
  openssl req -new -key "$name.key" -subj "/CN=$name/O=SmartSecure" -out "$name.csr"
  printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" "$san" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$name.crt" -days 397 -sha256 -extfile "$name.ext" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
}

issue_client() {  # client cert for mutual TLS; CN = MQTT username
  local name="$1"
  [ -f "clients/$name.crt" ] && return 0
  echo ">> Issuing client certificate: $name"
  mkdir -p clients
  openssl ecparam -genkey -name prime256v1 -noout -out "clients/$name.key"
  openssl req -new -key "clients/$name.key" -subj "/CN=$name/O=SmartSecure" -out "clients/$name.csr"
  printf "extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n" > "clients/$name.ext"
  openssl x509 -req -in "clients/$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "clients/$name.crt" -days 397 -sha256 -extfile "clients/$name.ext" 2>/dev/null
  rm -f "clients/$name.csr" "clients/$name.ext"
}

issue mosquitto "DNS:mosquitto,DNS:localhost,IP:127.0.0.1"
issue api       "DNS:api,DNS:localhost,IP:127.0.0.1"
for u in admin api simulators vision cyber engine; do issue_client "$u"; done

# Dev only: containers run as non-root users and must read the keys.
chmod 644 *.key *.crt clients/*.key clients/*.crt
echo ">> Certificates ready in infra/certs (CA: ca.crt, import it in your browser to trust the API)"
echo ">> Rotation: delete the files above and re-run ./scripts/setup.sh"
