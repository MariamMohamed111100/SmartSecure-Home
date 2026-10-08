import json
import time

import jwt
import pytest
from conftest import make_event
from starlette.websockets import WebSocketDisconnect


def _expired():
    return jwt.encode({"sub": "admin", "exp": 1}, "j" * 48, algorithm="HS256")


@pytest.mark.parametrize("query", ["", "?token=", "?token=junk"])
def test_websocket_rejects_missing_or_bad_tokens(client, query):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/events" + query):
            pass


def test_websocket_rejects_expired_token(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/events?token=" + _expired()):
            pass


def test_websocket_closes_1008_once_the_token_expires(client):
    from websocket_manager import manager

    short = jwt.encode({"sub": "admin", "exp": int(time.time()) + 2}, "j" * 48, algorithm="HS256")
    with client.websocket_connect("/ws/events?token=" + short) as ws:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            while True:
                ws.receive_text()
        assert exc_info.value.code == 1008
        deadline = time.time() + 5
        while manager.connections and time.time() < deadline:
            time.sleep(0.1)
        assert len(manager.connections) == 0, "expired connection must be dropped from the manager"


def _token(auth):
    return auth["Authorization"].split()[1]


def test_live_event_and_status_are_pushed(client, auth, feed):
    with client.websocket_connect("/ws/events?token=" + _token(auth)) as ws:
        feed("security/alerts/vision", make_event("live-event-01"))
        message = json.loads(ws.receive_text())
        assert message["kind"] == "event" and message["data"]["id"] == "live-event-01"
        feed("home/kitchen/valve/valve_main/status", {"online": True, "state": {"open": False}})
        message = json.loads(ws.receive_text())
        assert message["kind"] == "device_status" and message["data"]["state"] == {"open": False}


def test_rejected_messages_are_not_broadcast(client, auth, feed):
    with client.websocket_connect("/ws/events?token=" + _token(auth)) as ws:
        feed("home/garage/pir/x/event", make_event("bad-sev-0001", severity_hint="EXTREME"))
        feed("security/alerts/vision", make_event("live-event-02"))
        assert json.loads(ws.receive_text())["data"]["id"] == "live-event-02"


def test_every_client_gets_the_message_and_disconnects_are_cleaned_up(client, auth, feed):
    from websocket_manager import manager
    token = _token(auth)
    with client.websocket_connect("/ws/events?token=" + token) as a:
        with client.websocket_connect("/ws/events?token=" + token) as b:
            feed("security/alerts/cyber", make_event("live-event-03", source="cyber"))
            assert json.loads(a.receive_text())["data"]["id"] == "live-event-03"
            assert json.loads(b.receive_text())["data"]["id"] == "live-event-03"
    assert len(manager.connections) == 0
