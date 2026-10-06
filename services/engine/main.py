"""engine service: placeholder proving TLS, auth and ACLs work. Replace me."""
import time

from smartsecure_common import connect, start_heartbeat

SERVICE = "engine"

if __name__ == "__main__":
    client = connect(SERVICE)
    start_heartbeat(client, SERVICE)
    print(f"{SERVICE} started", flush=True)
    while True:
        time.sleep(60)
