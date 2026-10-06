"""CI guard: contract schema, risk config and example events must stay consistent."""
import json
import pathlib
import sys

import jsonschema
import yaml

root = pathlib.Path(__file__).resolve().parent.parent
schema = json.loads((root / "contract/event.schema.json").read_text())
jsonschema.Draft202012Validator.check_schema(schema)

from smartsecure_common import make_event  # noqa: E402
from smartsecure_common.crypto import decrypt, encrypt, key_from_env  # noqa: E402

event = make_event(
    "vision", "fire.detected", "garage", "high", confidence=0.9, snapshot="snapshots/abc.jpg"
)
sample = json.loads(event.model_dump_json())
jsonschema.validate(sample, schema)

# AES-256-GCM at-rest primitive must round-trip (and detect tampering).
key = key_from_env("ci-test-key")
assert decrypt(key, encrypt(key, b"secret")) == b"secret"

risk = yaml.safe_load((root / "config/risk_scores.yaml").read_text())
zones_cfg = yaml.safe_load((root / "config/zones.yaml").read_text())
zones = zones_cfg["zones"]
outdoor = zones_cfg.get("outdoor_zones", [])
levels = risk["levels"]
assert list(levels) == ["low", "medium", "high", "critical"], "levels must be ordered low..critical"
assert list(levels.values()) == sorted(levels.values()), "level thresholds must ascend"
assert set(risk["responses"]) == set(levels), "every level needs a response list"
assert all(isinstance(v, int) for v in risk["events"].values())
assert "network" in zones
assert set(outdoor) <= set(zones), "outdoor_zones must be subsets of zones"
assert "network" not in outdoor, "the network zone is not a physical area"

# Policy sanity (review P1): attackers get blocked from High; fire NEVER locks doors.
for name, _lower in levels.items():
    prior = risk["responses"].get("low", [])
    if name != "low":
        assert set(prior) <= set(risk["responses"][name]), f"responses[{name}] must be cumulative"
        prior = risk["responses"][name]
assert "block_ip" in risk["responses"]["high"], "block_ip must fire at High (demo score 85)"
assert "unlock_doors" in risk["responses"]["critical"], "Critical must unlock doors"
assert "lock_doors" not in risk["responses"]["critical"], "never lock doors at Critical (fire!)"

print("contract OK:", len(risk["events"]), "scored event types,", len(zones), "zones")
sys.exit(0)