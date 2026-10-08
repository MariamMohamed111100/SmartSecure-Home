"""`make demo-incident` against the real API code, fed by the real simulators (in-process)."""
import json
import pathlib
import sys
from datetime import datetime

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "scripts"))
import demo_incident  # noqa: E402


class InProcessTransport:
    """Same interface as DockerTransport, wired to the app under test instead of Docker."""

    def __init__(self, client, auth, feed, house, fake_mqtt, drop=()):
        self.client, self.auth, self.feed = client, auth, feed
        self.house, self.fake_mqtt, self.drop = house, fake_mqtt, set(drop)
        self.published, self.slept = [], []

    def trigger_scenario(self, name):
        self.house.play(name)

    def publish(self, topic, payload):
        self.published.append(topic)
        if topic not in self.drop:
            self.feed(topic, payload)

    def api(self, method, path, body=None, params=None):
        sent = len(self.fake_mqtt.published)
        response = self.client.request(method, path, json=body, params=params, headers=self.auth)
        for topic, payload in self.fake_mqtt.published[sent:]:     # the broker delivers commands
            start = len(self.house.bus.published)
            self.house.bus.publish(topic, json.dumps(payload))
            self.house.deliver(start)                              # ...and the device answers
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, None

    def sleep(self, seconds):
        self.slept.append(seconds)


@pytest.fixture
def transport(client, auth, feed, house, fake_mqtt):
    return InProcessTransport(client, auth, feed, house, fake_mqtt)


def test_the_demo_incident_passes_end_to_end(transport):
    lines = []
    failures = demo_incident.play(transport, out=lines.append)
    assert failures == [], "\n".join(lines)
    assert transport.published == ["security/alerts/vision", "security/alerts/cyber",
                                   "security/risk", "security/incidents"]
    assert "DEMO OK" in lines[-1]


def test_timeline_matches_the_proposal_offsets(transport, client, auth):
    demo_incident.play(transport, out=lambda _: None)
    incident = client.get("/incidents", headers=auth).json()[0]
    events = client.get(f"/incidents/{incident['id']}/events", headers=auth).json()
    first = datetime.fromisoformat(events[0]["ts"])
    offsets = [(datetime.fromisoformat(e["ts"]) - first).total_seconds() for e in events]
    assert offsets == [0.0, 3.0, 5.0]                           # 10:30:21 -> :24 -> :26
    assert [e["source"] for e in events] == ["sim.pir", "vision", "cyber"]


def test_speed_shortens_the_pauses(client, auth, feed, house, fake_mqtt):
    fast = InProcessTransport(client, auth, feed, house, fake_mqtt)
    demo_incident.play(fast, speed=2.0, out=lambda _: None)
    assert [s for s in fast.slept if s >= 0.5][:3] == [1.5, 1.0, 1.0]


def test_can_run_twice_and_both_incidents_are_kept(transport, client, auth):
    assert demo_incident.play(transport, out=lambda _: None) == []
    assert demo_incident.play(transport, out=lambda _: None) == []
    assert len(client.get("/incidents", headers=auth).json()) == 2


def test_the_demo_notices_when_an_incident_never_arrives(client, auth, feed, house, fake_mqtt):
    broken = InProcessTransport(client, auth, feed, house, fake_mqtt, drop={"security/incidents"})
    failures = demo_incident.play(broken, out=lambda _: None)
    assert any("incident" in f for f in failures)


def test_the_demo_notices_when_commands_are_refused(client, feed, house, fake_mqtt, auth):
    class Refused(InProcessTransport):
        def api(self, method, path, body=None, params=None):
            if path.endswith("/command"):
                return 403, None
            return super().api(method, path, body, params)

    failures = demo_incident.play(Refused(client, auth, feed, house, fake_mqtt),
                                  out=lambda _: None)
    assert any("commands rejected" in f for f in failures)
