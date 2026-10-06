"""cyber service: placeholder proving TLS, auth and ACLs work. Replace me.

Subscribes to ``system/block`` so the risk engine (P6) can instruct the
firewall to drop an attacker IP, e.g. after a port scan. The ACL in
infra/mosquitto/acl.conf allows only ``engine`` to publish here and only
``cyber`` to read it, keeping the command channel one-way and auditable.
"""
import time

from smartsecure_common import connect, start_heartbeat, topics

SERVICE = "cyber"


def on_block(client, userdata, message) -> None:
    print(f"[cyber] block request received: {message.payload.decode()}", flush=True)
    # P5: apply the block in Suricata. Reply with a status update on the
    # source's security/alerts/cyber topic so the engine closes the loop.


if __name__ == "__main__":
    client = connect(SERVICE)
    client.message_callback_add(topics.BLOCK, on_block)
    client.subscribe(topics.BLOCK, qos=1)
    start_heartbeat(client, SERVICE)
    print(f"{SERVICE} started, listening on {topics.BLOCK}", flush=True)
    while True:
        time.sleep(60)