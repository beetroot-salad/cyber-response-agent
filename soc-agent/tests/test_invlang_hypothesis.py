"""Unit tests for hypothesis-discipline invlang checks (rules 23-30).

Covers: sibling fork distinctness, hypothesis persistence, matched_prediction_ids
hypothesis scope, compound prediction claims, evaluation-prefixed classifications,
predictions leanness, prediction subject scope, refutation→prediction links.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    _check_attribute_prediction_structure,
    _check_classification_evaluation_prefix,
    _check_compound_prediction_claim,
    _check_hypothesis_fork_distinctness,
    _check_hypothesis_persistence,
    _check_integrity_peer_discipline,
    _check_prediction_id_hypothesis_scope,
    _check_prediction_subject_scope,
    _check_predictions_leanness,
    _check_refutation_prediction_links,
    _check_sibling_prediction_divergence,
)


class TestHypothesisForkDistinctness:
    """Rule #23 — sibling hypotheses may not share parent_vertex.classification."""

    @staticmethod
    def _h(hid, attached, classification):
        return {
            "id": hid,
            "name": f"?{classification}",
            "attached_to_vertex": attached,
            "proposed_edge": {
                "relation": "spawned",
                "parent_vertex": {"type": "process", "classification": classification},
            },
            "predictions": [{"id": "p1", "claim": "..."}],
        }

    def test_distinct_classifications_pass(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", "v-001", "runtime-descendant"),
            self._h("h-002", "v-001", "runtime-exec-injection"),
        ]}}
        assert _check_hypothesis_fork_distinctness(merged) == []

    def test_duplicate_classification_same_vertex_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", "v-001", "runtime-descendant"),
            self._h("h-002", "v-001", "runtime-descendant"),
        ]}}
        errors = _check_hypothesis_fork_distinctness(merged)
        assert len(errors) == 1
        assert "h-001" in errors[0] and "h-002" in errors[0]
        assert "runtime-descendant" in errors[0]

    def test_same_classification_different_vertex_passes(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", "v-001", "runtime-descendant"),
            self._h("h-002", "v-002", "runtime-descendant"),
        ]}}
        assert _check_hypothesis_fork_distinctness(merged) == []

    def test_same_classification_different_parent_passes(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001-001", "v-001", "x"),
            self._h("h-002-001", "v-001", "x"),
        ]}}
        assert _check_hypothesis_fork_distinctness(merged) == []

    def test_child_duplicates_under_same_parent_fail(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001-001", "v-001", "subcase-a"),
            self._h("h-001-002", "v-001", "subcase-a"),
        ]}}
        errors = _check_hypothesis_fork_distinctness(merged)
        assert len(errors) == 1
        assert "h-001-001" in errors[0] and "h-001-002" in errors[0]

    def test_missing_classification_skipped(self):
        merged = {"hypothesize": {"hypotheses": [
            {"id": "h-001", "attached_to_vertex": "v-001",
             "proposed_edge": {"parent_vertex": {"type": "process"}}},
            self._h("h-002", "v-001", "runtime-descendant"),
        ]}}
        assert _check_hypothesis_fork_distinctness(merged) == []

    def test_new_hypotheses_in_leads_participate(self):
        merged = {
            "hypothesize": {"hypotheses": [
                self._h("h-001", "v-001", "runtime-descendant"),
            ]},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {}, "resolutions": [],
                "new_hypotheses": [self._h("h-002", "v-001", "runtime-descendant")],
            }],
        }
        errors = _check_hypothesis_fork_distinctness(merged)
        assert len(errors) == 1


# ---------------------------------------------------------------------------
# Rule 24 — Hypothesis persistence at REPORT
# ---------------------------------------------------------------------------


class TestCheckHypothesisPersistence:
    """Rule #24 — declared hypotheses must reach `--` or appear in
    conclude.surviving_hypotheses[] when a conclude: block is present."""

    @staticmethod
    def _hypothesis(hid: str) -> dict:
        return {
            "id": hid,
            "name": f"?{hid}",
            "attached_to_vertex": "v-001",
            "proposed_edge": {
                "relation": "spawned",
                "parent_vertex": {"type": "process", "classification": f"cls-{hid}"},
            },
            "predictions": [{"id": "p1", "claim": "..."}],
        }

    @staticmethod
    def _resolution(hid: str, after: str) -> dict:
        return {
            "hypothesis": hid,
            "before": None,
            "after": after,
            "severity_of_test": "weak",
            "matched_prediction_ids": [],
            "matched_refutation_ids": ["r1"] if after == "--" else [],
            "reasoning": "...",
            "supporting_edges": ["e-001"],
        }

    def test_no_conclude_block_skips(self):
        merged = {"hypothesize": {"hypotheses": [self._hypothesis("h-001")]}}
        assert _check_hypothesis_persistence(merged) == []

    def test_hypothesis_refuted_passes(self):
        merged = {
            "hypothesize": {"hypotheses": [self._hypothesis("h-001")]},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {},
                "resolutions": [self._resolution("h-001", "--")],
            }],
            "conclude": {
                "termination": {"category": "adversarial-refuted"},
                "disposition": "benign",
                "confidence": "high",
                "surviving_hypotheses": [],
            },
        }
        assert _check_hypothesis_persistence(merged) == []

    def test_hypothesis_in_surviving_list_passes(self):
        merged = {
            "hypothesize": {"hypotheses": [self._hypothesis("h-001")]},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {},
                "resolutions": [self._resolution("h-001", "+")],
            }],
            "conclude": {
                "termination": {"category": "severity-ceiling"},
                "disposition": "unclear",
                "confidence": "medium",
                "surviving_hypotheses": ["h-001"],
            },
        }
        assert _check_hypothesis_persistence(merged) == []

    def test_silent_drop_fails(self):
        merged = {
            "hypothesize": {"hypotheses": [
                self._hypothesis("h-001"),
                self._hypothesis("h-002"),
            ]},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {},
                "resolutions": [self._resolution("h-001", "--")],
            }],
            "conclude": {
                "termination": {"category": "adversarial-refuted"},
                "disposition": "benign",
                "confidence": "high",
                "surviving_hypotheses": [],
            },
        }
        errors = _check_hypothesis_persistence(merged)
        assert len(errors) == 1
        assert "h-002" in errors[0]
        assert "surviving_hypotheses" in errors[0]

    def test_plus_weight_not_listed_fails(self):
        merged = {
            "hypothesize": {"hypotheses": [self._hypothesis("h-001")]},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {},
                "resolutions": [self._resolution("h-001", "+")],
            }],
            "conclude": {
                "termination": {"category": "exhaustion-escalation"},
                "disposition": "unclear",
                "confidence": "low",
                "surviving_hypotheses": [],
            },
        }
        errors = _check_hypothesis_persistence(merged)
        assert len(errors) == 1
        assert "h-001" in errors[0]

    def test_shelved_hypothesis_passes(self):
        merged = {
            "hypothesize": {"hypotheses": [self._hypothesis("h-001")]},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {},
                "resolutions": [],
                "shelved": ["h-001"],
            }],
            "conclude": {
                "termination": {"category": "trust-root"},
                "disposition": "benign",
                "confidence": "high",
                "surviving_hypotheses": [],
            },
        }
        assert _check_hypothesis_persistence(merged) == []

    def test_surviving_hypotheses_wrong_type_fails(self):
        merged = {
            "hypothesize": {"hypotheses": [self._hypothesis("h-001")]},
            "conclude": {
                "termination": {"category": "exhaustion-escalation"},
                "disposition": "unclear",
                "confidence": "low",
                "surviving_hypotheses": "h-001",  # must be a list
            },
        }
        errors = _check_hypothesis_persistence(merged)
        assert errors
        assert "list" in errors[0]

    def test_new_hypotheses_in_leads_participate(self):
        merged = {
            "hypothesize": {"hypotheses": []},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {},
                "resolutions": [],
                "new_hypotheses": [self._hypothesis("h-002")],
            }],
            "conclude": {
                "termination": {"category": "adversarial-refuted"},
                "disposition": "benign",
                "confidence": "high",
                "surviving_hypotheses": [],
            },
        }
        errors = _check_hypothesis_persistence(merged)
        assert len(errors) == 1
        assert "h-002" in errors[0]


# ---------------------------------------------------------------------------
# Rule 25 — Same-level sibling rollup (matched_prediction_ids scope)
# ---------------------------------------------------------------------------


class TestCheckPredictionIdHypothesisScope:
    """Rule #25 — matched_prediction_ids on a resolution for H must cite
    only IDs declared on H's own predictions[]."""

    @staticmethod
    def _h(hid: str, pred_ids: list[str]) -> dict:
        return {
            "id": hid,
            "name": f"?{hid}",
            "attached_to_vertex": "v-001",
            "proposed_edge": {
                "relation": "spawned",
                "parent_vertex": {"type": "process", "classification": f"cls-{hid}"},
            },
            "predictions": [{"id": pid, "claim": "..."} for pid in pred_ids],
        }

    @staticmethod
    def _lead(rid: str, hid: str, matched: list[str]) -> dict:
        return {
            "id": rid, "loop": 1, "name": "x", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{
                "hypothesis": hid,
                "before": None,
                "after": "+",
                "severity_of_test": "weak",
                "matched_prediction_ids": matched,
                "matched_refutation_ids": [],
                "reasoning": "...",
                "supporting_edges": ["e-001"],
            }],
        }

    def test_own_prediction_ids_pass(self):
        merged = {
            "hypothesize": {"hypotheses": [self._h("h-001", ["p1", "p2"])]},
            "findings": [self._lead("l-001", "h-001", ["p1"])],
        }
        assert _check_prediction_id_hypothesis_scope(merged) == []

    def test_foreign_prediction_id_fails(self):
        merged = {
            "hypothesize": {"hypotheses": [
                self._h("h-001", ["pA"]),
                self._h("h-002", ["pB"]),
            ]},
            "findings": [self._lead("l-001", "h-001", ["pB"])],
        }
        errors = _check_prediction_id_hypothesis_scope(merged)
        assert len(errors) == 1
        assert "h-001" in errors[0]
        assert "pB" in errors[0]

    def test_empty_matched_passes(self):
        merged = {
            "hypothesize": {"hypotheses": [self._h("h-001", ["p1"])]},
            "findings": [self._lead("l-001", "h-001", [])],
        }
        assert _check_prediction_id_hypothesis_scope(merged) == []

    def test_mixed_own_and_foreign_flags_only_foreign(self):
        merged = {
            "hypothesize": {"hypotheses": [
                self._h("h-001", ["p1"]),
                self._h("h-002", ["p2"]),
            ]},
            "findings": [self._lead("l-001", "h-001", ["p1", "p2"])],
        }
        errors = _check_prediction_id_hypothesis_scope(merged)
        assert len(errors) == 1
        # Only p2 should be named as a foreign citation (p1 is legitimately declared on h-001);
        # the error message quotes the foreign-id list distinctly from declared predictions.
        assert "['p2']" in errors[0]

    def test_undeclared_hypothesis_skipped(self):
        # Rule 4 (dangling-ref) owns the undeclared-hypothesis case; rule 25
        # stays silent to avoid double-reporting the same root cause.
        merged = {
            "hypothesize": {"hypotheses": [self._h("h-001", ["p1"])]},
            "findings": [self._lead("l-001", "h-999", ["p1"])],
        }
        assert _check_prediction_id_hypothesis_scope(merged) == []

    def test_new_hypotheses_predictions_counted(self):
        merged = {
            "hypothesize": {"hypotheses": []},
            "findings": [
                {
                    "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                    "query_details": {}, "outcome": {},
                    "resolutions": [],
                    "new_hypotheses": [self._h("h-002", ["pX"])],
                },
                self._lead("l-002", "h-002", ["pX"]),
            ],
        }
        assert _check_prediction_id_hypothesis_scope(merged) == []


# ---------------------------------------------------------------------------
# Rule 26 — Compound prediction claim
# ---------------------------------------------------------------------------


class TestCheckCompoundPredictionClaim:
    """Rule 26 — a predictions[].claim must not join multiple independent
    observable claims via `; `, ` AND `, or ` OR `."""

    @staticmethod
    def _h(hid: str, claims: list[str]) -> dict:
        return {
            "id": hid,
            "name": f"?m-{hid}",
            "attached_to_vertex": "v-001",
            "proposed_edge": {"relation": "r", "parent_vertex": {"type": "t", "classification": "c"}},
            "predictions": [{"id": f"p{i+1}", "claim": c} for i, c in enumerate(claims)],
        }

    def test_single_observable_claim_passes(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["attempt volume exceeds 3 per 5 minutes"]),
        ]}}
        assert _check_compound_prediction_claim(merged) == []

    def test_semicolon_separated_compound_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", [
                "SIEM shows ≤2 events in 5 min; all usernames are "
                "monitoring-pattern; no auth-success within 60s"
            ]),
        ]}}
        errors = _check_compound_prediction_claim(merged)
        assert len(errors) == 1
        assert "h-001" in errors[0] and "p1" in errors[0]
        assert "semicolon" in errors[0]

    def test_uppercase_AND_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["volume ≥5 AND usernames outside sentinel list"]),
        ]}}
        errors = _check_compound_prediction_claim(merged)
        assert len(errors) == 1
        assert "'AND'" in errors[0]

    def test_uppercase_OR_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["fixed-length identifiers OR variable-length chunks"]),
        ]}}
        errors = _check_compound_prediction_claim(merged)
        assert len(errors) == 1
        assert "'OR'" in errors[0]

    def test_lowercase_or_in_single_observable_passes(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["username matches monitor-probe or monitorprobe pattern"]),
        ]}}
        assert _check_compound_prediction_claim(merged) == []

    def test_one_complaint_per_prediction(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["a; b AND c"]),
        ]}}
        errors = _check_compound_prediction_claim(merged)
        assert len(errors) == 1

    def test_each_hypothesis_reported_independently(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["a; b"]),
            self._h("h-002", ["c OR d"]),
        ]}}
        errors = _check_compound_prediction_claim(merged)
        assert len(errors) == 2

    def test_non_dict_prediction_skipped(self):
        merged = {"hypothesize": {"hypotheses": [
            {"id": "h-001", "predictions": ["not a dict", {"id": "p1", "claim": "ok"}]},
        ]}}
        assert _check_compound_prediction_claim(merged) == []

    def test_new_hypotheses_in_leads_participate(self):
        merged = {
            "hypothesize": {"hypotheses": []},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {}, "resolutions": [],
                "new_hypotheses": [self._h("h-002", ["a; b"])],
            }],
        }
        errors = _check_compound_prediction_claim(merged)
        assert len(errors) == 1
        assert "h-002" in errors[0]


# ---------------------------------------------------------------------------
# Rule 27 — Evaluation-prefixed classification
# ---------------------------------------------------------------------------


class TestCheckClassificationEvaluationPrefix:
    """Rule 27 — classifications and hypothesis names must not start with
    authorization/intent prefixes."""

    @staticmethod
    def _h(hid: str, classification: str, name: str | None = None) -> dict:
        return {
            "id": hid,
            "name": name if name is not None else f"?{classification}",
            "attached_to_vertex": "v-001",
            "proposed_edge": {
                "relation": "r",
                "parent_vertex": {"type": "process", "classification": classification},
            },
            "predictions": [{"id": "p1", "claim": "..."}],
        }

    def test_mechanism_classification_passes(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", "scheduled-automation-health-check"),
            self._h("h-002", "runtime-exec-injection"),
            self._h("h-003", "adversary-controlled-monitoring-host"),
        ]}}
        assert _check_classification_evaluation_prefix(merged) == []

    @pytest.mark.parametrize("prefix", [
        "authorized-", "unauthorized-", "legitimate-", "illegitimate-",
        "malicious-", "benign-", "sanctioned-", "unsanctioned-",
        "compromised-", "adversarial-",
    ])
    def test_evaluation_prefixed_classification_fails(self, prefix):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", f"{prefix}monitoring-system"),
        ]}}
        errors = _check_classification_evaluation_prefix(merged)
        assert any(prefix in e for e in errors)

    def test_evaluation_prefixed_name_with_clean_classification_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", "monitoring-system", name="?authorized-monitoring-system"),
        ]}}
        errors = _check_classification_evaluation_prefix(merged)
        assert len(errors) == 1
        assert "?authorized-" in errors[0] and "h-001" in errors[0]

    def test_adversary_controlled_not_flagged(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", "adversary-controlled-tool"),
        ]}}
        assert _check_classification_evaluation_prefix(merged) == []

    def test_missing_classification_and_name_skipped(self):
        merged = {"hypothesize": {"hypotheses": [
            {"id": "h-001", "attached_to_vertex": "v-001", "proposed_edge": {"parent_vertex": {}}},
        ]}}
        assert _check_classification_evaluation_prefix(merged) == []

    def test_new_hypotheses_in_leads_participate(self):
        merged = {
            "hypothesize": {"hypotheses": []},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {}, "resolutions": [],
                "new_hypotheses": [self._h("h-002", "malicious-tool")],
            }],
        }
        errors = _check_classification_evaluation_prefix(merged)
        assert any("h-002" in e for e in errors)


# ---------------------------------------------------------------------------
# Rule 28 — Predictions leanness
# ---------------------------------------------------------------------------


class TestCheckPredictionsLeanness:
    """Rule 28 — hypotheses carry ≤ 2 predictions."""

    @staticmethod
    def _h(hid: str, n_preds: int) -> dict:
        return {
            "id": hid,
            "name": f"?m-{hid}",
            "attached_to_vertex": "v-001",
            "proposed_edge": {"relation": "r", "parent_vertex": {"type": "t", "classification": "c"}},
            "predictions": [
                {"id": f"p{i+1}", "claim": f"claim {i+1}"}
                for i in range(n_preds)
            ],
        }

    def test_one_prediction_passes(self):
        merged = {"hypothesize": {"hypotheses": [self._h("h-001", 1)]}}
        assert _check_predictions_leanness(merged) == []

    def test_two_predictions_passes(self):
        merged = {"hypothesize": {"hypotheses": [self._h("h-001", 2)]}}
        assert _check_predictions_leanness(merged) == []

    def test_three_predictions_fails(self):
        merged = {"hypothesize": {"hypotheses": [self._h("h-001", 3)]}}
        errors = _check_predictions_leanness(merged)
        assert len(errors) == 1
        assert "h-001" in errors[0] and "3 predictions" in errors[0]

    def test_zero_predictions_passes(self):
        merged = {"hypothesize": {"hypotheses": [self._h("h-001", 0)]}}
        assert _check_predictions_leanness(merged) == []

    def test_non_dict_predictions_not_counted(self):
        merged = {"hypothesize": {"hypotheses": [
            {
                "id": "h-001",
                "predictions": [
                    {"id": "p1", "claim": "a"},
                    {"id": "p2", "claim": "b"},
                    "stray string",
                    None,
                ],
            }
        ]}}
        assert _check_predictions_leanness(merged) == []

    def test_new_hypotheses_in_leads_participate(self):
        merged = {
            "hypothesize": {"hypotheses": []},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {}, "resolutions": [],
                "new_hypotheses": [self._h("h-002", 4)],
            }],
        }
        errors = _check_predictions_leanness(merged)
        assert len(errors) == 1
        assert "h-002" in errors[0]


# ---------------------------------------------------------------------------
# Rule 29 — Prediction subject scope
# ---------------------------------------------------------------------------


class TestCheckPredictionSubjectScope:
    """Rule 29 — predictions[].subject must be within the one-hop scope
    (proposed_parent | attached_vertex | proposed_edge)."""

    @staticmethod
    def _h(hid: str, preds: list[dict]) -> dict:
        return {
            "id": hid,
            "name": f"?m-{hid}",
            "attached_to_vertex": "v-001",
            "proposed_edge": {"relation": "r", "parent_vertex": {"type": "t", "classification": "c"}},
            "predictions": preds,
        }

    @pytest.mark.parametrize("subject", [
        "proposed_parent", "attached_vertex", "proposed_edge",
    ])
    def test_valid_subjects_pass(self, subject):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", [{"id": "p1", "subject": subject, "claim": "..."}]),
        ]}}
        assert _check_prediction_subject_scope(merged) == []

    def test_missing_subject_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", [{"id": "p1", "claim": "..."}]),
        ]}}
        errors = _check_prediction_subject_scope(merged)
        assert len(errors) == 1
        assert "missing required `subject`" in errors[0]

    def test_invalid_subject_fails(self):
        # A prediction claiming to test "monitoring-host container" is out of
        # scope — that's a lead masquerading as a prediction.
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", [{"id": "p1", "subject": "v-042", "claim": "..."}]),
        ]}}
        errors = _check_prediction_subject_scope(merged)
        assert len(errors) == 1
        assert "v-042" in errors[0] and "outside the hypothesis's one-hop" in errors[0]

    def test_multiple_predictions_each_checked(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", [
                {"id": "p1", "subject": "proposed_parent", "claim": "a"},
                {"id": "p2", "subject": "external_vertex", "claim": "b"},
            ]),
        ]}}
        errors = _check_prediction_subject_scope(merged)
        assert len(errors) == 1
        assert "p2" in errors[0]

    def test_new_hypotheses_in_leads_participate(self):
        merged = {
            "hypothesize": {"hypotheses": []},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {}, "resolutions": [],
                "new_hypotheses": [self._h("h-002", [
                    {"id": "p1", "subject": "wrong", "claim": "..."},
                ])],
            }],
        }
        errors = _check_prediction_subject_scope(merged)
        assert len(errors) == 1
        assert "h-002" in errors[0]


# ---------------------------------------------------------------------------
# Rule 30 — Refutation→prediction link
# ---------------------------------------------------------------------------


class TestCheckRefutationPredictionLinks:
    """Rule 30 — refutation_shape[].refutes_predictions must be non-empty
    and cite prediction ids declared on the same hypothesis."""

    @staticmethod
    def _h(hid: str, pred_ids: list[str], refutations: list[dict]) -> dict:
        return {
            "id": hid,
            "name": f"?m-{hid}",
            "attached_to_vertex": "v-001",
            "proposed_edge": {"relation": "r", "parent_vertex": {"type": "t", "classification": "c"}},
            "predictions": [
                {"id": pid, "subject": "proposed_parent", "claim": "..."}
                for pid in pred_ids
            ],
            "refutation_shape": refutations,
        }

    def test_valid_link_passes(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["p1"], [
                {"id": "r1", "refutes_predictions": ["p1"], "claim": "..."},
            ]),
        ]}}
        assert _check_refutation_prediction_links(merged) == []

    def test_missing_refutes_predictions_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["p1"], [
                {"id": "r1", "claim": "..."},
            ]),
        ]}}
        errors = _check_refutation_prediction_links(merged)
        assert len(errors) == 1
        assert "missing required `refutes_predictions`" in errors[0]

    def test_empty_list_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["p1"], [
                {"id": "r1", "refutes_predictions": [], "claim": "..."},
            ]),
        ]}}
        errors = _check_refutation_prediction_links(merged)
        assert len(errors) == 1
        assert "non-empty list" in errors[0]

    def test_foreign_prediction_id_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["p1"], [
                {"id": "r1", "refutes_predictions": ["p99"], "claim": "..."},
            ]),
        ]}}
        errors = _check_refutation_prediction_links(merged)
        assert len(errors) == 1
        assert "'p99'" in errors[0]
        assert "do not appear" in errors[0]

    def test_mixed_valid_and_foreign_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["p1", "p2"], [
                {"id": "r1", "refutes_predictions": ["p1", "p99"], "claim": "..."},
            ]),
        ]}}
        errors = _check_refutation_prediction_links(merged)
        assert len(errors) == 1
        # The foreign-id list quotes only p99; the declared-id list quotes p1 and p2.
        # Check the foreign list comes first and contains only p99.
        assert "refutes_predictions ['p99']" in errors[0]

    def test_sibling_prediction_id_is_foreign(self):
        # h-002.p1 is not the same as h-001.p1 — sibling boundaries matter.
        # This is the refutation analog of the rule-25 same-level rollup.
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", ["p1"], [
                {"id": "r1", "refutes_predictions": ["p2"], "claim": "..."},
            ]),
            self._h("h-002", ["p2"], []),
        ]}}
        errors = _check_refutation_prediction_links(merged)
        # h-001 complains because p2 isn't in its own predictions.
        assert any("h-001" in e and "p2" in e for e in errors)

    def test_new_hypotheses_in_leads_participate(self):
        merged = {
            "hypothesize": {"hypotheses": []},
            "findings": [{
                "id": "l-001", "loop": 1, "name": "x", "target": "v-001",
                "query_details": {}, "outcome": {}, "resolutions": [],
                "new_hypotheses": [self._h("h-002", ["p1"], [
                    {"id": "r1", "claim": "..."},
                ])],
            }],
        }
        errors = _check_refutation_prediction_links(merged)
        assert len(errors) == 1
        assert "h-002" in errors[0]


# ---------------------------------------------------------------------------
# Rule #32 — Integrity peer discipline
# ---------------------------------------------------------------------------


@pytest.mark.skip(reason="Rule #32 disabled (return [] short-circuit); tests preserved for one-line revert")
class TestCheckIntegrityPeerDiscipline:
    """Rule #32 (v2.12 narrowed) — reject invoker-identity anti-pattern.

    Fires only when sibling hypotheses share proposed_edge structure AND
    have predictions that subset-or-equal one another, where at least one
    carries an authorization_contract. Does not mandate waivers.
    """

    @staticmethod
    def _contract_h(
        hid: str,
        attached: str,
        parent_type: str,
        *,
        name: str | None = None,
        claims: list[str] | None = None,
    ) -> dict:
        return {
            "id": hid,
            "name": name if name is not None else f"?m-{hid}",
            "attached_to_vertex": attached,
            "proposed_edge": {
                "relation": "initiated_by",
                "parent_vertex": {"type": parent_type, "classification": "some-classification"},
            },
            "predictions": [
                {"id": f"p{i+1}", "claim": c}
                for i, c in enumerate(claims or ["p1 default"])
            ],
            "authorization_contract": [{
                "id": "ac1",
                "edge_ref": "proposed",
                "anchor_kind": "iam-policy",
                "predicate": "authorized iff role match",
                "on_unauthorized": "escalate",
                "on_indeterminate": "escalate",
            }],
        }

    @staticmethod
    def _peer_h(
        hid: str, attached: str, parent_type: str, *, claims: list[str] | None = None,
    ) -> dict:
        return {
            "id": hid,
            "name": f"?m-{hid}",
            "attached_to_vertex": attached,
            "proposed_edge": {
                "relation": "initiated_by",
                "parent_vertex": {"type": parent_type, "classification": "other-classification"},
            },
            "predictions": [
                {"id": f"p{i+1}", "claim": c}
                for i, c in enumerate(claims or ["p1 default"])
            ],
        }

    def test_single_hypothesis_with_contract_passes(self):
        """Solo contract-carrier — no peer, no rule fires."""
        merged = {"hypothesize": {"hypotheses": [
            self._contract_h("h-001", "v-001", "session"),
        ]}}
        assert _check_integrity_peer_discipline(merged) == []

    def test_waiver_optional_not_required(self):
        """v2.12 drops the waiver mandate — solo contract is fine without it."""
        merged = {"hypothesize": {"hypotheses": [
            self._contract_h("h-001", "v-001", "process"),
        ]}}
        assert _check_integrity_peer_discipline(merged) == []

    def test_peer_with_identical_predictions_flagged(self):
        """Anti-pattern: peer shares edge + predictions with contract-carrier."""
        merged = {"hypothesize": {"hypotheses": [
            self._contract_h("h-001", "v-001", "process", claims=["anchor says yes"]),
            self._peer_h("h-002", "v-001", "process", claims=["anchor says yes"]),
        ]}}
        errors = _check_integrity_peer_discipline(merged)
        assert len(errors) == 1
        assert "h-001" in errors[0] and "h-002" in errors[0]
        assert "invoker-identity anti-pattern" in errors[0]

    def test_peer_with_subset_predictions_flagged(self):
        """Anti-pattern variant: peer's predictions are a strict subset."""
        merged = {"hypothesize": {"hypotheses": [
            self._contract_h("h-001", "v-001", "process",
                             claims=["claim-a", "claim-b"]),
            self._peer_h("h-002", "v-001", "process", claims=["claim-a"]),
        ]}}
        errors = _check_integrity_peer_discipline(merged)
        assert len(errors) == 1

    def test_peer_with_divergent_predictions_passes(self):
        """Legitimate fork: peer predictions are distinct from contract-carrier's."""
        merged = {"hypothesize": {"hypotheses": [
            self._contract_h("h-001", "v-001", "process",
                             claims=["approved-source registry confirms triple"]),
            self._peer_h("h-002", "v-001", "process",
                         claims=["process ancestry traces to non-daemon parent"]),
        ]}}
        assert _check_integrity_peer_discipline(merged) == []

    def test_peer_without_contract_on_either_side_ignored(self):
        """Rule #32 only fires when at least one sibling has an authorization_contract."""
        merged = {"hypothesize": {"hypotheses": [
            self._peer_h("h-001", "v-001", "process", claims=["same claim"]),
            self._peer_h("h-002", "v-001", "process", claims=["same claim"]),
        ]}}
        assert _check_integrity_peer_discipline(merged) == []

    def test_different_attached_vertex_not_siblings(self):
        """Hypotheses on different vertices aren't siblings under this rule."""
        merged = {"hypothesize": {"hypotheses": [
            self._contract_h("h-001", "v-001", "process", claims=["same"]),
            self._peer_h("h-002", "v-777", "process", claims=["same"]),
        ]}}
        assert _check_integrity_peer_discipline(merged) == []

    def test_different_parent_vertex_type_not_siblings(self):
        """Hypotheses with different parent_vertex.type aren't under this rule."""
        merged = {"hypothesize": {"hypotheses": [
            self._contract_h("h-001", "v-001", "process", claims=["same"]),
            self._peer_h("h-002", "v-001", "identity", claims=["same"]),
        ]}}
        assert _check_integrity_peer_discipline(merged) == []

    def test_non_acting_entity_type_with_peer_still_flagged(self):
        """Rule fires on ALL parent types, not just acting-entity — the anti-pattern
        can occur anywhere siblings share an edge + predictions."""
        merged = {"hypothesize": {"hypotheses": [
            self._contract_h("h-001", "v-001", "endpoint", claims=["same"]),
            self._peer_h("h-002", "v-001", "endpoint", claims=["same"]),
        ]}}
        errors = _check_integrity_peer_discipline(merged)
        assert len(errors) == 1


# ---------------------------------------------------------------------------
# Rule #33 — attribute_predictions[] structure
# ---------------------------------------------------------------------------


class TestAttributePredictionStructure:
    """Rule #33 — attribute_predictions[] entries have id/target/attribute/claim."""

    @staticmethod
    def _h_with_attr_preds(attr_preds):
        return {"hypothesize": {"hypotheses": [{
            "id": "h-001",
            "name": "?scheduled-automation",
            "attached_to_vertex": "v-001",
            "proposed_edge": {
                "relation": "initiated_by",
                "parent_vertex": {"type": "process", "classification": "monitoring-daemon"},
            },
            "predictions": [{"id": "p1", "claim": "cadence is periodic within ±5s"}],
            "attribute_predictions": attr_preds,
        }]}}

    def test_valid_attribute_predictions_pass(self):
        merged = self._h_with_attr_preds([
            {"id": "ap1", "target": "proposed_parent", "attribute": "cmdline",
             "claim": "matches /monitord|nagios-plugin/"},
            {"id": "ap2", "target": "proposed_parent", "attribute": "user_loginuid",
             "claim": "system user (UID < 1000)"},
        ])
        assert _check_attribute_prediction_structure(merged) == []

    def test_absent_attribute_predictions_pass(self):
        # Optional field — omitting is legal.
        merged = {"hypothesize": {"hypotheses": [{
            "id": "h-001", "name": "?x", "attached_to_vertex": "v-001",
            "proposed_edge": {"relation": "r", "parent_vertex": {"type": "process", "classification": "x"}},
            "predictions": [{"id": "p1", "claim": "..."}],
        }]}}
        assert _check_attribute_prediction_structure(merged) == []

    def test_bad_id_pattern_fails(self):
        merged = self._h_with_attr_preds([
            {"id": "attr-1", "target": "proposed_parent", "attribute": "cmdline", "claim": "x"},
        ])
        errors = _check_attribute_prediction_structure(merged)
        assert errors and "ap\\d+" in errors[0]

    def test_duplicate_id_fails(self):
        merged = self._h_with_attr_preds([
            {"id": "ap1", "target": "proposed_parent", "attribute": "cmdline", "claim": "x"},
            {"id": "ap1", "target": "proposed_parent", "attribute": "pname", "claim": "y"},
        ])
        errors = _check_attribute_prediction_structure(merged)
        assert errors and "duplicate" in errors[0]

    def test_bad_target_fails(self):
        merged = self._h_with_attr_preds([
            {"id": "ap1", "target": "random_thing", "attribute": "cmdline", "claim": "x"},
        ])
        errors = _check_attribute_prediction_structure(merged)
        assert errors and "target" in errors[0]

    def test_missing_attribute_fails(self):
        merged = self._h_with_attr_preds([
            {"id": "ap1", "target": "proposed_parent", "claim": "x"},
        ])
        errors = _check_attribute_prediction_structure(merged)
        assert errors and "attribute" in errors[0]

    def test_empty_claim_fails(self):
        merged = self._h_with_attr_preds([
            {"id": "ap1", "target": "proposed_parent", "attribute": "cmdline", "claim": ""},
        ])
        errors = _check_attribute_prediction_structure(merged)
        assert errors and "claim" in errors[0]

    def test_non_list_attribute_predictions_fails(self):
        merged = {"hypothesize": {"hypotheses": [{
            "id": "h-001", "name": "?x", "attached_to_vertex": "v-001",
            "proposed_edge": {"relation": "r", "parent_vertex": {"type": "process", "classification": "x"}},
            "predictions": [{"id": "p1", "claim": "..."}],
            "attribute_predictions": "not-a-list",
        }]}}
        errors = _check_attribute_prediction_structure(merged)
        assert errors and "must be a list" in errors[0]


class TestRefutationCitesAttributePrediction:
    """Rule #33 extension — refutation_shape.refutes_predictions may cite ap* ids."""

    def test_refutation_citing_ap_id_passes(self):
        merged = {"hypothesize": {"hypotheses": [{
            "id": "h-001", "name": "?x", "attached_to_vertex": "v-001",
            "proposed_edge": {"relation": "r", "parent_vertex": {"type": "process", "classification": "x"}},
            "predictions": [{"id": "p1", "claim": "..."}],
            "attribute_predictions": [
                {"id": "ap1", "target": "proposed_parent", "attribute": "cmdline",
                 "claim": "matches /monitord/"},
            ],
            "refutation_shape": [
                {"id": "r1", "refutes_predictions": ["ap1"],
                 "claim": "cmdline is shell/curl-pipe pattern"},
            ],
        }]}}
        assert _check_refutation_prediction_links(merged) == []

    def test_refutation_citing_both_p_and_ap_ids_passes(self):
        merged = {"hypothesize": {"hypotheses": [{
            "id": "h-001", "name": "?x", "attached_to_vertex": "v-001",
            "proposed_edge": {"relation": "r", "parent_vertex": {"type": "process", "classification": "x"}},
            "predictions": [{"id": "p1", "claim": "cadence periodic"}],
            "attribute_predictions": [
                {"id": "ap1", "target": "proposed_parent", "attribute": "cmdline", "claim": "..."},
            ],
            "refutation_shape": [
                {"id": "r1", "refutes_predictions": ["p1", "ap1"],
                 "claim": "combined refutation"},
            ],
        }]}}
        assert _check_refutation_prediction_links(merged) == []

    def test_refutation_citing_foreign_ap_id_fails(self):
        merged = {"hypothesize": {"hypotheses": [{
            "id": "h-001", "name": "?x", "attached_to_vertex": "v-001",
            "proposed_edge": {"relation": "r", "parent_vertex": {"type": "process", "classification": "x"}},
            "predictions": [{"id": "p1", "claim": "..."}],
            "refutation_shape": [
                {"id": "r1", "refutes_predictions": ["ap99"],
                 "claim": "nonexistent attribute"},
            ],
        }]}}
        errors = _check_refutation_prediction_links(merged)
        assert errors and "ap99" in errors[0]


class TestResolutionCitesAttributePrediction:
    """Rule #33 extension — matched_prediction_ids may cite ap* ids."""

    @staticmethod
    def _merged_with_res(matched_ids):
        return {
            "hypothesize": {"hypotheses": [{
                "id": "h-001", "name": "?x", "attached_to_vertex": "v-001",
                "proposed_edge": {"relation": "r", "parent_vertex": {"type": "process", "classification": "x"}},
                "predictions": [{"id": "p1", "claim": "..."}],
                "attribute_predictions": [
                    {"id": "ap1", "target": "proposed_parent", "attribute": "cmdline", "claim": "..."},
                ],
            }]},
            "findings": [{
                "id": "l-001",
                "resolutions": [{
                    "hypothesis": "h-001",
                    "after": "+",
                    "matched_prediction_ids": matched_ids,
                }],
            }],
        }

    def test_matched_ap_id_passes(self):
        assert _check_prediction_id_hypothesis_scope(self._merged_with_res(["ap1"])) == []

    def test_matched_mixed_ids_pass(self):
        assert _check_prediction_id_hypothesis_scope(self._merged_with_res(["p1", "ap1"])) == []

    def test_matched_foreign_ap_id_fails(self):
        errors = _check_prediction_id_hypothesis_scope(self._merged_with_res(["ap99"]))
        assert errors and "ap99" in errors[0]


class TestCompoundAttributePredictionClaim:
    """Rule #26 extension — compound-claim discipline applies to attribute_predictions."""

    def test_and_in_attribute_claim_fails(self):
        merged = {"hypothesize": {"hypotheses": [{
            "id": "h-001", "name": "?x", "attached_to_vertex": "v-001",
            "proposed_edge": {"relation": "r", "parent_vertex": {"type": "process", "classification": "x"}},
            "predictions": [{"id": "p1", "claim": "..."}],
            "attribute_predictions": [
                {"id": "ap1", "target": "proposed_parent", "attribute": "cmdline",
                 "claim": "matches /monitord/ AND non-interactive"},
            ],
        }]}}
        errors = _check_compound_prediction_claim(merged)
        assert errors and "ap1" in errors[0] and "'AND'" in errors[0]


@pytest.mark.skip(reason="Rule #35 disabled (return [] short-circuit); tests preserved for one-line revert")
class TestSiblingPredictionDivergence:
    """Rule #35 — siblings must differ on at least one prediction signature."""

    @staticmethod
    def _h(
        hid: str,
        *,
        attached: str = "v-001",
        classification: str = "cls-default",
        predictions: list[tuple[str, str, str]] | None = None,  # (id, subject, claim)
        attribute_predictions: list[tuple[str, str, str, str]] | None = None,  # (id, target, attribute, claim)
    ) -> dict:
        h: dict = {
            "id": hid, "name": f"?{hid}", "attached_to_vertex": attached,
            "proposed_edge": {
                "relation": "spawned",
                "parent_vertex": {"type": "process", "classification": classification},
            },
        }
        if predictions:
            h["predictions"] = [
                {"id": pid, "subject": subj, "claim": claim}
                for pid, subj, claim in predictions
            ]
        if attribute_predictions:
            h["attribute_predictions"] = [
                {"id": apid, "target": tgt, "attribute": attr, "claim": claim}
                for apid, tgt, attr, claim in attribute_predictions
            ]
        return h

    def test_distinct_claims_pass(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", classification="cron-driven",
                    predictions=[("p1", "proposed_parent", "parent is cron")]),
            self._h("h-002", classification="interactive-shell",
                    predictions=[("p1", "proposed_parent", "parent is interactive bash")]),
        ]}, "findings": []}
        assert _check_sibling_prediction_divergence(merged) == []

    def test_identical_claims_fail(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", classification="cron-driven",
                    predictions=[("p1", "proposed_parent", "parent ran on a schedule")]),
            self._h("h-002", classification="systemd-timer",
                    predictions=[("p1", "proposed_parent", "parent ran on a schedule")]),
        ]}, "findings": []}
        errors = _check_sibling_prediction_divergence(merged)
        assert errors
        assert "h-001" in errors[0] and "h-002" in errors[0]
        assert "identical prediction signatures" in errors[0]

    def test_case_insensitive_paraphrase_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", classification="cron-driven",
                    predictions=[("p1", "proposed_parent", "Parent Ran On A Schedule")]),
            self._h("h-002", classification="systemd-timer",
                    predictions=[("p1", "proposed_parent", "parent ran on a schedule")]),
        ]}, "findings": []}
        errors = _check_sibling_prediction_divergence(merged)
        assert errors

    def test_different_subjects_same_claim_fail(self):
        # Subject differences alone without claim divergence still mean siblings
        # carry overlapping observable expectations on the prediction text — the
        # signature comparison treats (kind, subject, claim) as the unit.
        # Two hypotheses with identical (subject, claim) on every prediction fail.
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", classification="cron-driven",
                    predictions=[("p1", "proposed_parent", "ran on a schedule")]),
            self._h("h-002", classification="systemd-timer",
                    predictions=[("p1", "proposed_parent", "ran on a schedule")]),
        ]}, "findings": []}
        errors = _check_sibling_prediction_divergence(merged)
        assert errors

    def test_different_attached_vertex_passes(self):
        # Different attached_to_vertex → not in the same sibling group.
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", attached="v-001", classification="x",
                    predictions=[("p1", "proposed_parent", "same claim")]),
            self._h("h-002", attached="v-002", classification="x",
                    predictions=[("p1", "proposed_parent", "same claim")]),
        ]}, "findings": []}
        assert _check_sibling_prediction_divergence(merged) == []

    def test_attribute_predictions_diverge_passes(self):
        # ap* differences let two hypotheses with shared p* signatures still
        # discriminate via attribute_predictions.
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", classification="x",
                    predictions=[("p1", "proposed_parent", "same claim")],
                    attribute_predictions=[("ap1", "proposed_parent", "cmdline", "matches /a/")]),
            self._h("h-002", classification="y",
                    predictions=[("p1", "proposed_parent", "same claim")],
                    attribute_predictions=[("ap1", "proposed_parent", "cmdline", "matches /b/")]),
        ]}, "findings": []}
        assert _check_sibling_prediction_divergence(merged) == []

    def test_attribute_predictions_identical_fails(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", classification="x",
                    predictions=[],
                    attribute_predictions=[("ap1", "proposed_parent", "cmdline", "matches /a/")]),
            self._h("h-002", classification="y",
                    predictions=[],
                    attribute_predictions=[("ap1", "proposed_parent", "cmdline", "matches /a/")]),
        ]}, "findings": []}
        errors = _check_sibling_prediction_divergence(merged)
        assert errors

    def test_one_sibling_with_extra_prediction_passes(self):
        # h-002 has p1 in common with h-001 plus an extra p2 that diverges → not
        # identical signatures → passes (subset cases are handled by rule #32).
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", classification="x",
                    predictions=[("p1", "proposed_parent", "shared claim")]),
            self._h("h-002", classification="y",
                    predictions=[
                        ("p1", "proposed_parent", "shared claim"),
                        ("p2", "proposed_edge", "additional discriminator"),
                    ]),
        ]}, "findings": []}
        assert _check_sibling_prediction_divergence(merged) == []

    def test_empty_signature_skipped(self):
        # A hypothesis with no predictions/attribute_predictions is skipped — other
        # rules (leanness, refutation linkage) flag empty-prediction hypotheses.
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001", classification="x"),
            self._h("h-002", classification="y"),
        ]}, "findings": []}
        assert _check_sibling_prediction_divergence(merged) == []

    def test_hierarchical_children_pass_when_distinct(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001-001", classification="cron-A",
                    predictions=[("p1", "proposed_parent", "schedule A")]),
            self._h("h-001-002", classification="cron-B",
                    predictions=[("p1", "proposed_parent", "schedule B")]),
        ]}, "findings": []}
        assert _check_sibling_prediction_divergence(merged) == []

    def test_hierarchical_children_fail_when_identical(self):
        merged = {"hypothesize": {"hypotheses": [
            self._h("h-001-001", classification="cron-A",
                    predictions=[("p1", "proposed_parent", "shared")]),
            self._h("h-001-002", classification="cron-B",
                    predictions=[("p1", "proposed_parent", "shared")]),
        ]}, "findings": []}
        errors = _check_sibling_prediction_divergence(merged)
        assert errors
        assert "h-001-001" in errors[0] and "h-001-002" in errors[0]
