"""Unit tests for prediction-discipline invlang checks (rules 11-14).

Covers: prediction coverage, partial authority cap, prediction lifecycle
(append-only at ID granularity), and rollup parent weight.
"""

from __future__ import annotations

import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    _check_partial_authority_cap,
    _check_prediction_coverage,
    _check_prediction_lifecycle,
    _check_rollup_parent_weight,
)


# ---------------------------------------------------------------------------
# Unit tests: _check_prediction_coverage (rule 3 / spec-rule 6)
# ---------------------------------------------------------------------------


def _coverage_fixture(
    predictions: list[str],
    resolutions: list[tuple[str, list[str]]],
) -> dict:
    """Build a merged companion with one hypothesis and N resolutions.

    resolutions is a list of (after_weight, matched_prediction_ids).
    """
    return {
        "hypothesize": {
            "hypotheses": [{
                "id": "h-001",
                "name": "?test",
                "predictions": [{"id": p, "claim": f"claim {p}"} for p in predictions],
            }],
        },
        "gather": [{
            "id": f"l-00{i+1}", "loop": 1, "name": f"lead-{i+1}", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{
                "hypothesis": "h-001", "after": after,
                "matched_prediction_ids": ids, "supporting_edges": [],
            }],
        } for i, (after, ids) in enumerate(resolutions)],
    }


class TestCheckPredictionCoverage:
    def test_pp_full_coverage_passes(self):
        merged = _coverage_fixture(["p1", "p2"], [("++", ["p1", "p2"])])
        assert _check_prediction_coverage(merged) == []

    def test_pp_partial_coverage_fails(self):
        merged = _coverage_fixture(["p1", "p2"], [("++", ["p1"])])
        errors = _check_prediction_coverage(merged)
        assert errors
        assert "p2" in errors[0]
        assert "++" in errors[0]

    def test_pp_across_multiple_resolutions_unions(self):
        merged = _coverage_fixture(
            ["p1", "p2"],
            [("+", ["p1"]), ("++", ["p2"])],
        )
        # Union across both resolutions covers {p1, p2} — the ++ is valid.
        assert _check_prediction_coverage(merged) == []

    def test_plus_does_not_require_coverage(self):
        merged = _coverage_fixture(["p1", "p2"], [("+", ["p1"])])
        assert _check_prediction_coverage(merged) == []

    def test_hypothesis_with_no_predictions_is_skipped(self):
        merged = _coverage_fixture([], [("++", [])])
        assert _check_prediction_coverage(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_partial_authority_cap (rule 6)
# ---------------------------------------------------------------------------


def _partial_consultation_fixture(after: str, supporting_edges: list[str]) -> dict:
    return {
        "gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {},
            "outcome": {
                "anchor_consultations": [{
                    "anchor_id": "approved-sources",
                    "anchor_kind": "approved-monitoring-sources",
                    "grounding_kind": "org-authority",
                    "result": "confirmed",
                    "as_of": "2026-04-17T00:00:00Z",
                    "authority_for_question": "partial",
                }],
                "observations": {"vertices": [], "edges": []},
            },
            "resolutions": [{
                "hypothesis": "h-001", "after": after,
                "matched_prediction_ids": [], "matched_refutation_ids": [],
                "supporting_edges": supporting_edges,
            }],
        }],
    }


def _partial_impact_resolution_fixture(after: str, supporting_edges: list[str]) -> dict:
    return {
        "gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {},
            "outcome": {
                "impact_resolutions": [{
                    "prediction_ref": "l-001.ip1",
                    "dimension": "confidentiality",
                    "verdict": "exceeds",
                    "grounding_kind": "telemetry-baseline",
                    "authority_for_question": "partial",
                    "as_of": "2026-04-17T00:00:00Z",
                    "reasoning": "...",
                }],
                "observations": {"vertices": [], "edges": []},
            },
            "resolutions": [{
                "hypothesis": "h-001", "after": after,
                "matched_prediction_ids": [], "matched_refutation_ids": [],
                "supporting_edges": supporting_edges,
            }],
        }],
    }


class TestCheckPartialAuthorityCap:
    def test_plus_with_partial_consultation_passes(self):
        merged = _partial_consultation_fixture("+", [])
        assert _check_partial_authority_cap(merged) == []

    def test_pp_with_partial_consultation_only_fails(self):
        merged = _partial_consultation_fixture("++", [])
        errors = _check_partial_authority_cap(merged)
        assert errors
        assert "partial" in errors[0]
        assert "++" in errors[0]

    def test_mm_with_partial_consultation_only_fails(self):
        merged = _partial_consultation_fixture("--", [])
        errors = _check_partial_authority_cap(merged)
        assert errors

    def test_pp_with_partial_consultation_and_supporting_edge_passes(self):
        merged = _partial_consultation_fixture("++", ["e-001"])
        assert _check_partial_authority_cap(merged) == []

    def test_full_authority_consultation_is_not_capped(self):
        merged = _partial_consultation_fixture("++", [])
        merged["gather"][0]["outcome"]["anchor_consultations"][0]["authority_for_question"] = "full"
        assert _check_partial_authority_cap(merged) == []

    def test_pp_with_partial_impact_resolution_only_fails(self):
        merged = _partial_impact_resolution_fixture("++", [])
        errors = _check_partial_authority_cap(merged)
        assert errors
        assert "partial" in errors[0]

    def test_pp_with_partial_impact_resolution_and_supporting_edge_passes(self):
        merged = _partial_impact_resolution_fixture("++", ["e-001"])
        assert _check_partial_authority_cap(merged) == []

    def test_pp_with_partial_authz_resolution_fails(self):
        merged = {
            "gather": [{
                "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
                "query_details": {},
                "outcome": {
                    "observations": {
                        "vertices": [],
                        "edges": [{
                            "id": "e-001",
                            "relation": "classified_as",
                            "source_vertex": "v-001",
                            "target_vertex": "v-002",
                            "authority": {"kind": "authoritative-source"},
                            "authorization_resolutions": [{
                                "verdict": "authorized",
                                "authority_for_question": "partial",
                                "anchor_kind": "iam",
                                "anchor_id": "x",
                                "grounding_kind": "org-authority",
                                "as_of": "2026-04-17",
                                "resolved_by_lead": "l-001",
                                "fulfills_contract": "h-001.ac1",
                            }],
                        }],
                    },
                },
                "resolutions": [{
                    "hypothesis": "h-001", "after": "++",
                    "matched_prediction_ids": [], "matched_refutation_ids": [],
                    "supporting_edges": [],
                }],
            }],
        }
        errors = _check_partial_authority_cap(merged)
        assert errors

    def test_mixed_partial_and_full_on_same_lead_passes(self):
        # Rule #14: cap applies only when every grounding entry on the lead
        # is partial. A co-located full-authority resolution is load-bearing
        # on its own and lifts the cap on `++`/`--`.
        merged = _partial_consultation_fixture("++", [])
        # Add a full-authority impact_resolution alongside the partial
        # anchor_consultation.
        merged["gather"][0]["outcome"]["impact_resolutions"] = [{
            "prediction_ref": "l-001.ip1",
            "dimension": "confidentiality",
            "verdict": "within",
            "grounding_kind": "telemetry-baseline",
            "authority_for_question": "full",
            "as_of": "2026-04-17T00:00:00Z",
            "reasoning": "observed value well within baseline",
        }]
        assert _check_partial_authority_cap(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_prediction_lifecycle (append-only on prediction IDs)
# ---------------------------------------------------------------------------


class TestCheckPredictionLifecycle:
    def _merged_with_predictions(self, prediction_ids: list[str], refutation_ids: list[str] | None = None) -> dict:
        h: dict = {
            "id": "h-001",
            "name": "?test",
            "predictions": [{"id": p, "claim": f"c{p}"} for p in prediction_ids],
        }
        if refutation_ids:
            h["refutation_shape"] = [{"id": r, "claim": f"r{r}"} for r in refutation_ids]
        return {"hypothesize": {"hypotheses": [h]}}

    def test_no_current_text_is_silent(self):
        proposed = self._merged_with_predictions(["p1", "p2"])
        assert _check_prediction_lifecycle(proposed, None) == []

    def test_no_change_passes(self):
        m = self._merged_with_predictions(["p1", "p2"])
        assert _check_prediction_lifecycle(m, m) == []

    def test_deleted_prediction_fails(self):
        current = self._merged_with_predictions(["p1", "p2", "p3"])
        proposed = self._merged_with_predictions(["p1", "p2"])  # p3 removed
        errors = _check_prediction_lifecycle(proposed, current)
        assert errors
        assert "p3" in errors[0]
        assert "h-001" in errors[0]

    def test_added_prediction_passes(self):
        current = self._merged_with_predictions(["p1"])
        proposed = self._merged_with_predictions(["p1", "p2"])  # p2 added
        assert _check_prediction_lifecycle(proposed, current) == []

    def test_deleted_refutation_fails(self):
        current = self._merged_with_predictions(["p1"], refutation_ids=["r1"])
        proposed = self._merged_with_predictions(["p1"], refutation_ids=[])
        errors = _check_prediction_lifecycle(proposed, current)
        assert errors
        assert "r1" in errors[0]
        assert "refutation" in errors[0].lower()

    def test_hypothesis_fully_removed_is_silent(self):
        # Block-level append-only handles this; we skip to avoid dup errors.
        current = self._merged_with_predictions(["p1", "p2"])
        proposed = {"hypothesize": {"hypotheses": []}}
        assert _check_prediction_lifecycle(proposed, current) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_rollup_parent_weight
# ---------------------------------------------------------------------------


def _hierarchy_fixture(parent_weight: str | None, child_weights: dict[str, str | None]) -> dict:
    hypotheses = [{"id": "h-001", "name": "?parent"}]
    for cid in child_weights:
        hypotheses.append({"id": cid, "name": f"?{cid}"})
    resolutions: list[dict] = []
    # One lead with resolutions for parent and each child (last one wins).
    if parent_weight is not None:
        resolutions.append({
            "hypothesis": "h-001", "after": parent_weight,
            "supporting_edges": ["e-001"], "matched_prediction_ids": [], "matched_refutation_ids": [],
        })
    for cid, w in child_weights.items():
        if w is None:
            continue
        resolutions.append({
            "hypothesis": cid, "after": w,
            "supporting_edges": ["e-001"], "matched_prediction_ids": [], "matched_refutation_ids": [],
        })
    return {
        "hypothesize": {"hypotheses": hypotheses},
        "gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {"observations": {"vertices": [], "edges": []}},
            "resolutions": resolutions,
        }],
    }


class TestCheckRollupParentWeight:
    def test_no_hierarchy_passes(self):
        merged = {"hypothesize": {"hypotheses": [{"id": "h-001"}]}, "gather": []}
        assert _check_rollup_parent_weight(merged) == []

    def test_parent_le_child_passes(self):
        merged = _hierarchy_fixture("+", {"h-001-001": "++", "h-001-002": "+"})
        assert _check_rollup_parent_weight(merged) == []

    def test_parent_gt_all_children_fails(self):
        merged = _hierarchy_fixture("++", {"h-001-001": "+", "h-001-002": "+"})
        errors = _check_rollup_parent_weight(merged)
        assert errors
        assert "h-001" in errors[0]
        assert "rollup" in errors[0].lower()

    def test_parent_unresolved_is_skipped(self):
        merged = _hierarchy_fixture(None, {"h-001-001": "+"})
        assert _check_rollup_parent_weight(merged) == []

    def test_parent_equal_to_max_child_passes(self):
        merged = _hierarchy_fixture("++", {"h-001-001": "++", "h-001-002": "+"})
        assert _check_rollup_parent_weight(merged) == []

    def test_parent_pp_with_all_children_refuted_fails(self):
        merged = _hierarchy_fixture("++", {"h-001-001": "--", "h-001-002": "--"})
        errors = _check_rollup_parent_weight(merged)
        assert errors
