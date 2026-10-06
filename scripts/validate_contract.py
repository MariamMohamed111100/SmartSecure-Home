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

event = make_event("vision", "face.unknown", "garage", "high", confidence=0.9)
sample = json.loads(event.model_dump_json())
jsonschema.validate(sample, schema)

risk = yaml.safe_load((root / "config/risk_scores.yaml").read_text())
zones = yaml.safe_load((root / "config/zones.yaml").read_text())["zones"]
levels = risk["levels"]
assert list(levels) == ["low", "medium", "high", "critical"], "levels must be ordered low..critical"
assert list(levels.values()) == sorted(levels.values()), "level thresholds must ascend"
assert set(risk["responses"]) == set(levels), "every level needs a response list"
assert all(isinstance(v, int) for v in risk["events"].values())
assert "network" in zones
print("contract OK:", len(risk["events"]), "scored event types,", len(zones), "zones")
sys.exit(0)
