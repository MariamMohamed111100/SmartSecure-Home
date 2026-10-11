"""MQTT glue: connect with mTLS, subscribe, feed the Engine, tick, heartbeat."""
from __future__ import annotations

import json
import logging
import threading
import time

from smartsecure_common import connect, start_heartbeat

from .core import Engine
from .policy import load_policy

log = logging.getLogger("engine")

SUBSCRIPTIONS = ("home/+/+/+/event", "home/+/+/+/status",
                 "security/alerts/vision", "security/alerts/cyber")
TICK_S = 5


def build(client) -> Engine:
    def publish(topic: str, payload: dict, retain: bool) -> None:
        client.publish(topic, json.dumps(payload), qos=1, retain=retain)
    return Engine(load_policy(), publish)


def run(service: str = "engine") -> None:
    client = connect(service)
    engine = build(client)
    previous = client.on_connect

    def on_connect(c, userdata, *args, **kwargs):      # re-subscribe on every (re)connect
        if previous:
            previous(c, userdata, *args, **kwargs)
        for topic in SUBSCRIPTIONS:
            c.subscribe(topic, qos=1)

    client.on_connect = on_connect
    client.on_message = lambda c, u, msg: engine.on_message(msg.topic, msg.payload)
    for topic in SUBSCRIPTIONS:
        client.subscribe(topic, qos=1)
    start_heartbeat(client, service)
    engine.tick()                                       # baseline retained risk 0
    log.info("%s started", service)
    stop = threading.Event()
    while not stop.wait(TICK_S):
        try:
            engine.tick()
        except Exception:
            log.exception("tick failed")
        time.sleep(0)
