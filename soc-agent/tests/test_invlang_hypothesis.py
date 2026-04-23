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
    _check_classification_evaluation_prefix,
    _check_compound_prediction_claim,
    _check_hypothesis_fork_distinctness,
    _check_hypothesis_persistence,
    _check_prediction_id_hypothesis_scope,
    _check_prediction_subject_scope,
    _check_predictions_leanness,
    _check_refutation_prediction_links,
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
            "gather": [{
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
            "gather": [{
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
            "gather": [{
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
            "gather": [{
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
            "gather": [{
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
            "gather": [{
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
            "gather": [{
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
            "gather": [self._lead("l-001", "h-001", ["p1"])],
        }
        assert _check_prediction_id_hypothesis_scope(merged) == []

    def test_foreign_prediction_id_fails(self):
        merged = {
            "hypothesize": {"hypotheses": [
                self._h("h-001", ["pA"]),
                self._h("h-002", ["pB"]),
            ]},
            "gather": [self._lead("l-001", "h-001", ["pB"])],
        }
        errors = _check_prediction_id_hypothesis_scope(merged)
        assert len(errors) == 1
        assert "h-001" in errors[0]
        assert "pB" in errors[0]

    def test_empty_matched_passes(self):
        merged = {
            "hypothesize": {"hypotheses": [self._h("h-001", ["p1"])]},
            "gather": [self._lead("l-001", "h-001", [])],
        }
        assert _check_prediction_id_hypothesis_scope(merged) == []

    def test_mixed_own_and_foreign_flags_only_foreign(self):
        merged = {
            "hypothesize": {"hypotheses": [
                self._h("h-001", ["p1"]),
                self._h("h-002", ["p2"]),
            ]},
            "gather": [self._lead("l-001", "h-001", ["p1", "p2"])],
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
            "gather": [self._lead("l-001", "h-999", ["p1"])],
        }
        assert _check_prediction_id_hypothesis_scope(merged) == []

    def test_new_hypotheses_predictions_counted(self):
        merged = {
            "hypothesize": {"hypotheses": []},
            "gather": [
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
            "gather": [{
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
    legitimacy/intent prefixes."""

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
            "gather": [{
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
            "gather": [{
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
            "gather": [{
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
            "gather": [{
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
