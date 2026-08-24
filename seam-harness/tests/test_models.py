from __future__ import annotations

import pytest
from pydantic import ValidationError

from seam_harness.models import HarnessSpec, LeafDeps, BlindInterpreterDeps


def test_example_spec_is_valid() -> None:
    spec = HarnessSpec.model_validate_json(
        open("examples/essay/spec.json", encoding="utf-8").read()
    )
    assert spec.frame.demands[0].id == "D1"
    assert spec.policy.root_model == "fireworks:accounts/fireworks/models/kimi-k3"


def test_duplicate_demand_ids_are_rejected() -> None:
    with pytest.raises(ValidationError, match="demand IDs must be unique"):
        HarnessSpec.model_validate(
            {
                "frame": {
                    "title": "x",
                    "task": "x",
                    "product_intent": "x",
                    "demands": [
                        {"id": "D1", "statement": "one"},
                        {"id": "D1", "statement": "two"},
                    ],
                }
            }
        )


def test_leaf_context_cannot_carry_audit_probes_or_whole_frame() -> None:
    assert "held_out_probes" not in LeafDeps.model_fields
    assert "frame" not in LeafDeps.model_fields
    assert "probes" not in LeafDeps.model_fields


def test_blind_interpreter_context_cannot_carry_topology() -> None:
    assert "plan" not in BlindInterpreterDeps.model_fields
    assert "contracts" not in BlindInterpreterDeps.model_fields
    assert "leaves" not in BlindInterpreterDeps.model_fields
