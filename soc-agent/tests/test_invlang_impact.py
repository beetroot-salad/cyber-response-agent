"""Unit tests for impact-axis invlang checks (rules #29–#31) + CONCLUDE two-axis."""

from __future__ import annotations

import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    _check_conclude_two_axis,
    _check_impact_closure,
    _check_impact_prediction_structure,
    _check_impact_resolution_backrefs,
)


def _impact_pred(**over) -> dict:
    entry = {
        "id": "ip1",
        "dimension": "confidentiality",
        "claim": "session_total_bytes within 30d baseline mean ± 2σ",
        "on_match": "within",
        "on_mismatch": "exceeds",
        "on_indeterminate": "indeterminate",
        "escalation_on": "exceeds",
    }
    entry.update(over)
    return entry


def _impact_res(**over) -> dict:
    entry = {
        "prediction_ref": "ip1",
        "dimension": "confidentiality",
        "observed_value": "180GB",
        "verdict": "exceeds",
        "matched_predicate": "session_total_bytes within 30d baseline mean ± 2σ",
        "grounded_by_lead": "l-001",
        "grounding_kind": "telemetry-baseline",
        "anchor_id": "backup-30d-baseline",
        "anchor_kind": "session-volume-baseline",
        "authority_for_question": "partial",
        "as_of": "2026-04-23T14:32Z",
        "reasoning": "observed 3σ exceedance; predicate threshold was 2σ.",
    }
    entry.update(over)
    return entry


def _lead_with_impact(predictions=None, resolutions=None) -> dict:
    return {
        "id": "l-001", "loop": 1, "name": "volume-profile", "target": "v-001",
        "query_details": {}, "outcome": {
            "observations": {"vertices": [], "edges": []},
            "impact_resolutions": resolutions or [],
        },
        "impact_predictions": predictions or [],
        "resolutions": [],
    }


# ---------------------------------------------------------------------------
# Rule #29 — structure
# ---------------------------------------------------------------------------


class TestCheckImpactPredictionStructure:
    def test_well_formed_passes(self):
        merged = {"findings": [_lead_with_impact(predictions=[_impact_pred()])]}
        assert _check_impact_prediction_structure(merged) == []

    def test_missing_required_field_fails(self):
        pred = _impact_pred()
        pred.pop("on_match")
        merged = {"findings": [_lead_with_impact(predictions=[pred])]}
        errors = _check_impact_prediction_structure(merged)
        assert any("on_match" in e for e in errors)

    def test_bad_id_pattern_fails(self):
        merged = {"findings": [_lead_with_impact(predictions=[_impact_pred(id="lp1")])]}
        errors = _check_impact_prediction_structure(merged)
        assert any("^ip\\d+$" in e for e in errors)

    def test_duplicate_id_within_lead_fails(self):
        merged = {"findings": [_lead_with_impact(predictions=[
            _impact_pred(id="ip1"),
            _impact_pred(id="ip1"),
        ])]}
        errors = _check_impact_prediction_structure(merged)
        assert any("duplicate id" in e for e in errors)

    def test_unknown_dimension_fails(self):
        merged = {"findings": [_lead_with_impact(predictions=[
            _impact_pred(dimension="nonsense"),
        ])]}
        errors = _check_impact_prediction_structure(merged)
        assert any("dimension 'nonsense'" in e for e in errors)

    def test_compound_AND_claim_rejected(self):
        pred = _impact_pred(claim="bytes > X AND destination is external")
        merged = {"findings": [_lead_with_impact(predictions=[pred])]}
        errors = _check_impact_prediction_structure(merged)
        assert any("'AND'" in e for e in errors)

    def test_compound_semicolon_claim_rejected(self):
        pred = _impact_pred(claim="bytes > X; destination is external")
        merged = {"findings": [_lead_with_impact(predictions=[pred])]}
        errors = _check_impact_prediction_structure(merged)
        assert any("semicolon" in e for e in errors)


# ---------------------------------------------------------------------------
# Rule #30 — resolution back-refs + grounding
# ---------------------------------------------------------------------------


class TestCheckImpactResolutionBackrefs:
    def test_bare_ref_resolves_within_lead(self):
        merged = {"findings": [_lead_with_impact(
            predictions=[_impact_pred()],
            resolutions=[_impact_res(prediction_ref="ip1")],
        )]}
        assert _check_impact_resolution_backrefs(merged) == []

    def test_qualified_ref_resolves(self):
        merged = {"findings": [_lead_with_impact(
            predictions=[_impact_pred()],
            resolutions=[_impact_res(prediction_ref="l-001.ip1")],
        )]}
        assert _check_impact_resolution_backrefs(merged) == []

    def test_unknown_ref_fails(self):
        merged = {"findings": [_lead_with_impact(
            predictions=[_impact_pred()],
            resolutions=[_impact_res(prediction_ref="ip99")],
        )]}
        errors = _check_impact_resolution_backrefs(merged)
        assert any("does not resolve" in e for e in errors)

    def test_dimension_mismatch_fails(self):
        merged = {"findings": [_lead_with_impact(
            predictions=[_impact_pred(dimension="confidentiality")],
            resolutions=[_impact_res(dimension="availability")],
        )]}
        errors = _check_impact_resolution_backrefs(merged)
        assert any("does not match" in e for e in errors)

    def test_past_case_grounding_rejected(self):
        merged = {"findings": [_lead_with_impact(
            predictions=[_impact_pred()],
            resolutions=[_impact_res(grounding_kind="past-case")],
        )]}
        errors = _check_impact_resolution_backrefs(merged)
        assert any("past-case" in e for e in errors)

    def test_missing_reasoning_fails(self):
        res = _impact_res()
        res.pop("reasoning")
        merged = {"findings": [_lead_with_impact(
            predictions=[_impact_pred()],
            resolutions=[res],
        )]}
        errors = _check_impact_resolution_backrefs(merged)
        assert any("reasoning" in e for e in errors)

    def test_bad_verdict_fails(self):
        merged = {"findings": [_lead_with_impact(
            predictions=[_impact_pred()],
            resolutions=[_impact_res(verdict="maybe")],
        )]}
        errors = _check_impact_resolution_backrefs(merged)
        assert any("verdict 'maybe'" in e for e in errors)


# ---------------------------------------------------------------------------
# Rule #31 — closure at CONCLUDE
# ---------------------------------------------------------------------------


class TestCheckImpactClosure:
    def test_resolved_passes(self):
        merged = {
            "findings": [_lead_with_impact(
                predictions=[_impact_pred()],
                resolutions=[_impact_res()],
            )],
            "conclude": {"disposition": "benign"},
        }
        assert _check_impact_closure(merged) == []

    def test_orphaned_fails(self):
        merged = {
            "findings": [_lead_with_impact(predictions=[_impact_pred()], resolutions=[])],
            "conclude": {"disposition": "benign"},
        }
        errors = _check_impact_closure(merged)
        assert any("l-001.ip1" in e and "deferred_impact_predictions" in e for e in errors)

    def test_deferred_with_rationale_passes(self):
        merged = {
            "findings": [_lead_with_impact(predictions=[_impact_pred()], resolutions=[])],
            "conclude": {
                "disposition": "unclear",
                "deferred_impact_predictions": [
                    {"prediction_ref": "l-001.ip1",
                     "rationale": "baseline lookup timed out; follow-up scheduled"},
                ],
            },
        }
        assert _check_impact_closure(merged) == []

    def test_deferred_empty_rationale_fails(self):
        merged = {
            "findings": [_lead_with_impact(predictions=[_impact_pred()], resolutions=[])],
            "conclude": {
                "disposition": "unclear",
                "deferred_impact_predictions": [
                    {"prediction_ref": "l-001.ip1", "rationale": ""},
                ],
            },
        }
        errors = _check_impact_closure(merged)
        assert any("rationale" in e for e in errors)

    def test_no_conclude_block_skips(self):
        merged = {
            "findings": [_lead_with_impact(predictions=[_impact_pred()], resolutions=[])],
        }
        assert _check_impact_closure(merged) == []


# ---------------------------------------------------------------------------
# CONCLUDE two-axis
# ---------------------------------------------------------------------------


class TestCheckConcludeTwoAxis:
    def test_within_no_severity_passes(self):
        merged = {"conclude": {
            "disposition": "benign",
            "impact_verdict": "within",
            "impact_severity": None,
        }}
        assert _check_conclude_two_axis(merged) == []

    def test_none_no_severity_passes(self):
        merged = {"conclude": {
            "disposition": "benign",
            "impact_verdict": "none",
        }}
        assert _check_conclude_two_axis(merged) == []

    def test_exceeds_requires_severity(self):
        merged = {"conclude": {
            "disposition": "benign",
            "impact_verdict": "exceeds",
            "impact_severity": None,
        }}
        errors = _check_conclude_two_axis(merged)
        assert any("severity is required" in e for e in errors)

    def test_indeterminate_requires_severity(self):
        merged = {"conclude": {
            "disposition": "unclear",
            "impact_verdict": "indeterminate",
        }}
        errors = _check_conclude_two_axis(merged)
        assert any("severity is required" in e for e in errors)

    def test_exceeds_with_moderate_passes(self):
        merged = {"conclude": {
            "disposition": "benign",
            "impact_verdict": "exceeds",
            "impact_severity": "moderate",
        }}
        assert _check_conclude_two_axis(merged) == []

    def test_within_with_severity_fails(self):
        merged = {"conclude": {
            "disposition": "benign",
            "impact_verdict": "within",
            "impact_severity": "low",
        }}
        errors = _check_conclude_two_axis(merged)
        assert any("severity must be null" in e for e in errors)

    def test_bad_verdict_fails(self):
        merged = {"conclude": {"impact_verdict": "bogus"}}
        errors = _check_conclude_two_axis(merged)
        assert any("impact_verdict" in e for e in errors)

    def test_bad_severity_fails(self):
        merged = {"conclude": {
            "impact_verdict": "exceeds",
            "impact_severity": "catastrophic",
        }}
        errors = _check_conclude_two_axis(merged)
        assert any("impact_severity" in e for e in errors)
