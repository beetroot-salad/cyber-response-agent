"""Tests for the lint_vulture gate's view of the API's wire models: pydantic reads every field of a model, so the
gate counts each field (and `model_config`) as used, and nothing outside a model."""
from __future__ import annotations

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_vulture")

_MODELS = '''
from pydantic import BaseModel, ConfigDict


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str


class StartJob(_Request):
    alert_id: str


class ParkedBatch(BaseModel):
    batch_kind: str
    items: list[str] = []


class NotAModel:
    stray: int
    model_config = "not pydantic"
'''


def test_every_field_of_a_model_and_its_subclasses_counts_as_used():
    assert _GATE.wire_fields(_MODELS) == ["alert_id", "batch_kind", "items", "model_config", "reason"]


def test_a_class_that_is_not_a_model_lends_no_name():
    assert "stray" not in _GATE.wire_fields(_MODELS)


def test_the_real_wire_models_yield_their_fields():
    """Control on the real file: a field the gate once listed by hand is found."""
    assert "batch_kind" in _GATE.wire_fields(_GATE.WIRE_MODELS.read_text(encoding="utf-8"))
