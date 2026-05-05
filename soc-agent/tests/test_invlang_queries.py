"""Tests for investigation-language query classes — axes 1 and 2.

Uses in-memory Companion fixtures (no file I/O) to validate:
  - Default sort order for each class (Axis 1: --top N relies on correct ordering)
  - enumerate_hypothesis_tree (Axis 1: --enum-tree)
  - lead_discrimination_score (Axis 1: --discriminate-between)
  - weight_reversal_mining (Axis 2: Class 9)
  - lead_pair_synergy (Axis 2: Class 10)
  - post_failure_recovery (Axis 2: Class 11)
  - independent_datasource_metric (Axis 2: Class 12)
  - CLI _run_class dispatch + _apply_top slicing
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import pytest

# Ensure scripts/ is on the path so `invlang` package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from invlang.corpus import Companion, _looks_like_companion
from invlang.queries import (
    coarse_case_lookup,
    dead_lead_lookup,
    enumerate_hypothesis_tree,
    hypothesis_name_wildcard,
    independent_datasource_metric,
    lead_discrimination_score,
    lead_pair_synergy,
    lead_sequence_pattern,
    post_failure_recovery,
    refinement_chain_shapes,
    weight_reversal_mining,
)
from invlang.cli import _apply_top, _print_result, _print_section, _run_class, _run_ids


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def make_resolution(
    hypothesis_id: str,
    before: Any,
    after: str,
    severity: str = "moderate",
    reasoning: str = "",
) -> dict[str, Any]:
    r: dict[str, Any] = {
        "hypothesis": hypothesis_id,
        "before": before,
        "after": after,
        "severity_of_test": severity,
    }
    if reasoning:
        r["reasoning"] = reasoning
    return r


def make_lead(
    id: str,
    name: str,
    loop: int,
    system: str = "test-system",
    resolutions: list[dict[str, Any]] | None = None,
    failure_reason: str | None = None,
    attribute_updates: list[dict[str, Any]] | None = None,
    observations: dict[str, Any] | None = None,
    anchor_consultations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    lead: dict[str, Any] = {
        "id": id,
        "name": name,
        "loop": loop,
        "target": "v-001",
        "query_details": {"system": system, "template": "", "query": "", "time_window": "1h"},
    }
    outcome: dict[str, Any] = {}
    if failure_reason:
        outcome["failure_reason"] = failure_reason
    if attribute_updates:
        outcome["attribute_updates"] = attribute_updates
    if observations:
        outcome["observations"] = observations
    if anchor_consultations:
        outcome["anchor_consultations"] = anchor_consultations
    if resolutions:
        lead["resolutions"] = resolutions
    lead["outcome"] = outcome
    return lead


def make_hypothesis(
    id: str,
    name: str,
    weight: Any = None,
    status: str = "active",
) -> dict[str, Any]:
    h: dict[str, Any] = {"id": id, "name": name, "status": status}
    if weight is not None:
        h["weight"] = weight
    return h


def make_companion(
    case_id: str,
    hypotheses: list[dict[str, Any]],
    leads: list[dict[str, Any]],
    disposition: str = "benign",
    termination_category: str = "trust-root",
    confidence: str = "high",
    matched_archetype: str | None = None,
    prologue: dict[str, Any] | None = None,
) -> Companion:
    body: dict[str, Any] = {
        "prologue": prologue or {"vertices": [], "edges": []},
        "hypothesize": {"hypotheses": hypotheses},
        "findings": list(leads),
        "conclude": {
            "termination": {"category": termination_category, "rationale": "test"},
            "disposition": disposition,
            "confidence": confidence,
            "matched_archetype": matched_archetype,
        },
    }
    return Companion(case_id=case_id, source_path=Path("."), body=body)


# ---------------------------------------------------------------------------
# Axis 1: default sort order per class
# ---------------------------------------------------------------------------

class TestSortOrderClass1:
    def test_sorted_by_confidence_desc(self):
        corpus = [
            make_companion("low-case", [], [], confidence="low"),
            make_companion("high-case", [], [], confidence="high"),
            make_companion("medium-case", [], [], confidence="medium"),
        ]
        result = coarse_case_lookup(corpus)
        assert result["count"] == 3
        confidences = [h["confidence"] for h in result["hits"]]
        assert confidences == ["high", "medium", "low"]

    def test_unknown_confidence_sorts_last(self):
        corpus = [
            make_companion("unknown-case", [], [], confidence=None),
            make_companion("high-case", [], [], confidence="high"),
        ]
        result = coarse_case_lookup(corpus)
        confidences = [h["confidence"] for h in result["hits"]]
        assert confidences[0] == "high"


class TestSortOrderClass3:
    def test_sorted_by_max_depth_desc(self):
        # Case with deep chain
        deep = make_companion(
            "deep",
            [
                make_hypothesis("h-001", "?root"),
                make_hypothesis("h-001-001", "?child"),
                make_hypothesis("h-001-001-001", "?grandchild"),
            ],
            [],
        )
        # Case with shallow chain
        shallow = make_companion(
            "shallow",
            [make_hypothesis("h-001", "?only")],
            [],
        )
        result = refinement_chain_shapes([shallow, deep])
        assert result["hits"][0]["case_id"] == "deep"
        assert result["hits"][0]["max_depth"] == 3

    def test_equal_depth_sorted_by_descendant_count(self):
        wide = make_companion(
            "wide",
            [
                make_hypothesis("h-001", "?root"),
                make_hypothesis("h-001-001", "?c1"),
                make_hypothesis("h-001-002", "?c2"),
            ],
            [],
        )
        narrow = make_companion(
            "narrow",
            [
                make_hypothesis("h-002", "?root2"),
                make_hypothesis("h-002-001", "?c1"),
            ],
            [],
        )
        result = refinement_chain_shapes([narrow, wide])
        # wide has max_depth=2, descendant_count=3; narrow has max_depth=2, descendant_count=2
        assert result["hits"][0]["case_id"] == "wide"


class TestSortOrderClass4:
    def test_sorted_by_loop_asc(self):
        ld3 = make_lead("l-003", "lead-c", loop=3, failure_reason="timeout")
        ld1 = make_lead("l-001", "lead-a", loop=1, failure_reason="timeout")
        ld2 = make_lead("l-002", "lead-b", loop=2, failure_reason="timeout")
        corpus = [make_companion("c1", [], [ld3, ld1, ld2])]
        result = dead_lead_lookup(corpus)
        loops = [h["loop"] for h in result["hits"]]
        assert loops == [1, 2, 3]


class TestSortOrderClass5:
    def test_sorted_by_lead_count_desc(self):
        # 3 leads
        leads3 = [
            make_lead("l-001", "source-classification", loop=1),
            make_lead("l-002", "authentication-history", loop=2),
            make_lead("l-003", "process-lineage", loop=3),
        ]
        # 1 lead
        leads1 = [make_lead("l-001", "source-classification", loop=1)]
        corpus = [
            make_companion("one-lead", [], leads1),
            make_companion("three-leads", [], leads3),
        ]
        result = lead_sequence_pattern(corpus)
        assert result["hits"][0]["case_id"] == "three-leads"
        assert result["hits"][0]["lead_count"] == 3


class TestSortOrderClass6:
    def test_sorted_by_final_weight_desc(self):
        h_pp = make_hypothesis("h-001", "?monitoring-probe")
        h_mm = make_hypothesis("h-002", "?brute-force")
        h_p = make_hypothesis("h-003", "?credential-stuffing")
        corpus = [
            make_companion(
                "c1",
                [h_pp, h_mm, h_p],
                [make_lead("l-001", "auth-history", loop=1, resolutions=[
                    make_resolution("h-001", None, "++"),
                    make_resolution("h-002", None, "--"),
                    make_resolution("h-003", None, "+"),
                ])],
            )
        ]
        result = hypothesis_name_wildcard(corpus, "?*")
        weights = [h["final_weight"] for h in result["hits"]]
        # ++ should be first, then +, then --
        assert weights[0] == "++"
        assert weights[-1] == "--"


# ---------------------------------------------------------------------------
# Axis 1: enumerate_hypothesis_tree
# ---------------------------------------------------------------------------

class TestEnumerateHypothesisTree:
    def test_basic_hierarchy(self):
        corpus = [
            make_companion(
                "c1",
                [
                    make_hypothesis("h-001", "?root"),
                    make_hypothesis("h-001-001", "?child-one"),
                    make_hypothesis("h-001-002", "?child-two"),
                    make_hypothesis("h-002", "?another-root"),
                ],
                [],
            )
        ]
        result = enumerate_hypothesis_tree(corpus)
        assert result["count"] == 4
        tree = result["tree"]
        # h-001 should be a root with 2 children
        assert "h-001" in tree
        child_ids = [c["id"] for c in tree["h-001"]]
        assert "h-001-001" in child_ids
        assert "h-001-002" in child_ids
        # h-002 is a root with no children
        assert "h-002" in tree
        assert tree["h-002"] == []

    def test_flat_list_populated(self):
        corpus = [
            make_companion(
                "c1",
                [
                    make_hypothesis("h-001", "?root"),
                    make_hypothesis("h-001-001", "?child"),
                ],
                [],
            )
        ]
        result = enumerate_hypothesis_tree(corpus)
        assert len(result["flat"]) == 1
        flat_entry = result["flat"][0]
        assert flat_entry["parent_id"] == "h-001"
        assert flat_entry["child_id"] == "h-001-001"
        assert flat_entry["parent_name"] == "?root"
        assert flat_entry["child_name"] == "?child"

    def test_empty_corpus(self):
        result = enumerate_hypothesis_tree([])
        assert result["count"] == 0
        assert result["tree"] == {}
        assert result["flat"] == []

    def test_no_hypotheses(self):
        corpus = [make_companion("c1", [], [])]
        result = enumerate_hypothesis_tree(corpus)
        assert result["count"] == 0

    def test_only_flat_hypotheses(self):
        """No hierarchical IDs — all roots, no children."""
        corpus = [
            make_companion(
                "c1",
                [
                    make_hypothesis("h-001", "?a"),
                    make_hypothesis("h-002", "?b"),
                    make_hypothesis("h-003", "?c"),
                ],
                [],
            )
        ]
        result = enumerate_hypothesis_tree(corpus)
        assert result["count"] == 3
        assert result["flat"] == []
        for root_id in ["h-001", "h-002", "h-003"]:
            assert root_id in result["tree"]
            assert result["tree"][root_id] == []

    def test_deep_chain(self):
        """h-001 → h-001-001 → h-001-001-001."""
        corpus = [
            make_companion(
                "c1",
                [
                    make_hypothesis("h-001", "?root"),
                    make_hypothesis("h-001-001", "?child"),
                    make_hypothesis("h-001-001-001", "?grandchild"),
                ],
                [],
            )
        ]
        result = enumerate_hypothesis_tree(corpus)
        flat_parents = [f["parent_id"] for f in result["flat"]]
        assert "h-001" in flat_parents
        assert "h-001-001" in flat_parents
        # h-001-001-001 is a leaf (no children)
        assert "h-001-001-001" not in flat_parents


# ---------------------------------------------------------------------------
# Axis 1: lead_discrimination_score
# ---------------------------------------------------------------------------

class TestLeadDiscriminationScore:
    def _make_discriminating_corpus(self) -> list[Companion]:
        """Lead X: moves ?monitoring++ and ?brute-force--. Lead Y: neutral."""
        lead_x = make_lead(
            "l-001", "lead-x", loop=1, resolutions=[
                make_resolution("h-001", None, "++"),   # ?monitoring goes up
                make_resolution("h-002", None, "--"),   # ?brute-force goes down
            ]
        )
        lead_y = make_lead(
            "l-002", "lead-y", loop=2, resolutions=[
                make_resolution("h-001", "++", "++"),   # no change
                make_resolution("h-002", "--", "--"),   # no change
            ]
        )
        return [
            make_companion(
                "c1",
                [
                    make_hypothesis("h-001", "?monitoring-probe"),
                    make_hypothesis("h-002", "?brute-force"),
                ],
                [lead_x, lead_y],
            )
        ]

    def test_discrimination_sign(self):
        corpus = self._make_discriminating_corpus()
        result = lead_discrimination_score(corpus, "?*monitoring*", "?*brute*")
        assert result["count"] > 0
        hits = result["hits"]
        lead_x_hit = next(h for h in hits if h["lead_name"] == "lead-x")
        # mean_h1 = +2, mean_h2 = -2, discrimination = 2 - (-2) = 4
        assert lead_x_hit["discrimination_score"] > 0
        assert lead_x_hit["mean_signed_delta_h1"] > 0
        assert lead_x_hit["mean_signed_delta_h2"] < 0

    def test_neutral_lead_near_zero(self):
        corpus = self._make_discriminating_corpus()
        result = lead_discrimination_score(corpus, "?*monitoring*", "?*brute*")
        lead_y_hit = next(h for h in result["hits"] if h["lead_name"] == "lead-y")
        # lead-y: no change on either hypothesis → discrimination = 0
        assert lead_y_hit["discrimination_score"] == 0.0

    def test_sorted_by_abs_score_desc(self):
        corpus = self._make_discriminating_corpus()
        result = lead_discrimination_score(corpus, "?*monitoring*", "?*brute*")
        scores = [abs(h["discrimination_score"]) for h in result["hits"]]
        assert scores == sorted(scores, reverse=True)

    def test_case_must_have_both_patterns(self):
        """Cases with only one hypothesis pattern are excluded."""
        lead = make_lead("l-001", "any-lead", loop=1, resolutions=[
            make_resolution("h-001", None, "++"),
        ])
        corpus = [
            make_companion("only-monitoring", [make_hypothesis("h-001", "?monitoring-probe")], [lead]),
        ]
        result = lead_discrimination_score(corpus, "?*monitoring*", "?*brute*")
        # No case has both patterns → no result
        assert result["count"] == 0

    def test_result_metadata(self):
        corpus = self._make_discriminating_corpus()
        result = lead_discrimination_score(corpus, "?*monitoring*", "?*brute*")
        assert result["pattern1"] == "?*monitoring*"
        assert result["pattern2"] == "?*brute*"
        assert "hits" in result


# ---------------------------------------------------------------------------
# Axis 2: weight_reversal_mining (Class 9)
# ---------------------------------------------------------------------------

class TestWeightReversalMining:
    def _reversal_corpus(self) -> list[Companion]:
        lead = make_lead(
            "l-001", "auth-history", loop=1, resolutions=[
                make_resolution("h-001", "++", "--", reasoning="looked like monitoring but burst pattern refutes it"),
                make_resolution("h-002", "+", "-", reasoning="partial refutation"),
                make_resolution("h-003", None, "-", reasoning="no prior weight, new negative"),
                # NOT a reversal: already negative → more negative
                make_resolution("h-004", "-", "--", reasoning="deepening refutation"),
                # NOT a reversal: positive direction
                make_resolution("h-005", None, "++", reasoning="confirmed"),
            ]
        )
        hypotheses = [
            make_hypothesis("h-001", "?monitoring-probe"),
            make_hypothesis("h-002", "?monitoring-probe-variant"),
            make_hypothesis("h-003", "?credential-stuffing"),
            make_hypothesis("h-004", "?brute-force"),
            make_hypothesis("h-005", "?legitimate-access"),
        ]
        return [make_companion("c1", hypotheses, [lead])]

    def test_positive_to_negative_included(self):
        corpus = self._reversal_corpus()
        result = weight_reversal_mining(corpus)
        h_ids = {h["hypothesis_id"] for h in result["hits"]}
        assert "h-001" in h_ids  # ++ → --
        assert "h-002" in h_ids  # + → -
        assert "h-003" in h_ids  # null → -

    def test_negative_to_more_negative_excluded(self):
        corpus = self._reversal_corpus()
        result = weight_reversal_mining(corpus)
        h_ids = {h["hypothesis_id"] for h in result["hits"]}
        assert "h-004" not in h_ids  # - → -- (already negative, not a reversal)

    def test_positive_direction_excluded(self):
        corpus = self._reversal_corpus()
        result = weight_reversal_mining(corpus)
        h_ids = {h["hypothesis_id"] for h in result["hits"]}
        assert "h-005" not in h_ids  # null → ++ (positive direction)

    def test_reasoning_preserved(self):
        corpus = self._reversal_corpus()
        result = weight_reversal_mining(corpus)
        h001 = next(h for h in result["hits"] if h["hypothesis_id"] == "h-001")
        assert "burst pattern" in h001["reasoning"]

    def test_hypothesis_pattern_filter(self):
        corpus = self._reversal_corpus()
        result = weight_reversal_mining(corpus, hypothesis_pattern="?*monitoring*")
        names = {h["hypothesis_name"] for h in result["hits"]}
        # Only ?monitoring-probe and ?monitoring-probe-variant match
        assert all("monitoring" in n for n in names)

    def test_sorted_by_hypothesis_name_then_case(self):
        corpus = self._reversal_corpus()
        result = weight_reversal_mining(corpus)
        names = [h["hypothesis_name"] for h in result["hits"]]
        assert names == sorted(names)

    def test_empty_corpus(self):
        assert weight_reversal_mining([])["count"] == 0

    def test_reversals_only_excludes_null_to_negative(self):
        """--reversals-only must exclude null→negative first-scores."""
        corpus = self._reversal_corpus()
        result = weight_reversal_mining(corpus, reversals_only=True)
        h_ids = {h["hypothesis_id"] for h in result["hits"]}
        # h-001 (++→--) and h-002 (+→-) are true reversals
        assert "h-001" in h_ids
        assert "h-002" in h_ids
        # h-003 (null→-) is NOT a true reversal — excluded
        assert "h-003" not in h_ids

    def test_reversals_only_false_includes_all(self):
        """Default (reversals_only=False) still includes null→negative rows."""
        corpus = self._reversal_corpus()
        result = weight_reversal_mining(corpus, reversals_only=False)
        h_ids = {h["hypothesis_id"] for h in result["hits"]}
        assert "h-003" in h_ids

    def test_is_true_reversal_from_confirmed_positive(self):
        """before in {'+', '++'} → is_true_reversal=True (was explicitly confirmed)."""
        lead = make_lead("l-001", "auth-history", loop=1, resolutions=[
            make_resolution("h-001", "++", "--"),   # True reversal: was ++
            make_resolution("h-002", "+", "-"),     # True reversal: was +
            make_resolution("h-003", None, "-"),    # Not a true reversal: first scored negative
        ])
        corpus = [make_companion("c1", [
            make_hypothesis("h-001", "?a"),
            make_hypothesis("h-002", "?b"),
            make_hypothesis("h-003", "?c"),
        ], [lead])]
        result = weight_reversal_mining(corpus)
        by_id = {h["hypothesis_id"]: h for h in result["hits"]}
        assert by_id["h-001"]["is_true_reversal"] is True
        assert by_id["h-002"]["is_true_reversal"] is True
        assert by_id["h-003"]["is_true_reversal"] is False

    def test_is_true_reversal_field_present_on_all_hits(self):
        """Every hit must carry the is_true_reversal field."""
        corpus = self._reversal_corpus()
        result = weight_reversal_mining(corpus)
        assert all("is_true_reversal" in h for h in result["hits"])


# ---------------------------------------------------------------------------
# Axis 2: lead_pair_synergy (Class 10)
# ---------------------------------------------------------------------------

class TestLeadPairSynergy:
    def test_basic_synergy(self):
        """Two leads in same loop both move h-001 positively."""
        lead_a = make_lead("l-001", "lead-a", loop=1, resolutions=[
            make_resolution("h-001", None, "+"),  # delta +1
        ])
        lead_b = make_lead("l-002", "lead-b", loop=1, resolutions=[
            make_resolution("h-001", "+", "++"),  # delta +1
        ])
        corpus = [make_companion("c1", [make_hypothesis("h-001", "?test")], [lead_a, lead_b])]
        result = lead_pair_synergy(corpus)
        assert result["count"] == 1
        hit = result["hits"][0]
        assert set([hit["lead_a"], hit["lead_b"]]) == {"lead-a", "lead-b"}
        # combined = +1 + +1 = +2; max_individual = 1; synergy = 2 - 1 = 1
        assert hit["mean_synergy"] == 1.0

    def test_single_lead_loop_excluded(self):
        """Loops with only one lead produce no pairs."""
        lead_a = make_lead("l-001", "lead-a", loop=1, resolutions=[
            make_resolution("h-001", None, "+"),
        ])
        corpus = [make_companion("c1", [make_hypothesis("h-001", "?test")], [lead_a])]
        result = lead_pair_synergy(corpus)
        assert result["count"] == 0

    def test_no_shared_hypotheses_excluded(self):
        """Leads in same loop that touch different hypotheses — no shared h_id → not counted."""
        lead_a = make_lead("l-001", "lead-a", loop=1, resolutions=[
            make_resolution("h-001", None, "+"),
        ])
        lead_b = make_lead("l-002", "lead-b", loop=1, resolutions=[
            make_resolution("h-002", None, "+"),
        ])
        corpus = [
            make_companion(
                "c1",
                [make_hypothesis("h-001", "?a"), make_hypothesis("h-002", "?b")],
                [lead_a, lead_b],
            )
        ]
        result = lead_pair_synergy(corpus)
        assert result["count"] == 0

    def test_aggregation_across_cases(self):
        """Same pair in two cases → mean synergy computed."""
        def _case(case_id: str) -> Companion:
            lead_a = make_lead("l-001", "lead-a", loop=1, resolutions=[
                make_resolution("h-001", None, "+"),
            ])
            lead_b = make_lead("l-002", "lead-b", loop=1, resolutions=[
                make_resolution("h-001", "+", "++"),
            ])
            return make_companion(case_id, [make_hypothesis("h-001", "?test")], [lead_a, lead_b])

        corpus = [_case("c1"), _case("c2")]
        result = lead_pair_synergy(corpus)
        assert result["count"] == 1
        assert result["hits"][0]["case_count"] == 2
        assert result["hits"][0]["mean_synergy"] == 1.0

    def test_sorted_by_mean_synergy_desc(self):
        """Multiple pairs — higher synergy ranked first."""
        # High synergy pair (both move +2 on same hyp)
        lead_a = make_lead("l-001", "lead-a", loop=1, resolutions=[
            make_resolution("h-001", None, "++"),
        ])
        lead_b = make_lead("l-002", "lead-b", loop=1, resolutions=[
            make_resolution("h-001", "++", "++"),  # no additional change: abs(2+0) - max(2,0) = 0
        ])
        # No-synergy pair in loop 2
        lead_c = make_lead("l-003", "lead-c", loop=2, resolutions=[
            make_resolution("h-002", None, "+"),
        ])
        lead_d = make_lead("l-004", "lead-d", loop=2, resolutions=[
            make_resolution("h-002", "+", "+"),  # zero delta
        ])
        corpus = [
            make_companion(
                "c1",
                [make_hypothesis("h-001", "?x"), make_hypothesis("h-002", "?y")],
                [lead_a, lead_b, lead_c, lead_d],
            )
        ]
        result = lead_pair_synergy(corpus)
        synergies = [h["mean_synergy"] for h in result["hits"]]
        assert synergies == sorted(synergies, reverse=True)

    def test_opposing_sign_is_anti_synergistic(self):
        """Leads that pull the same hypothesis in opposite directions have negative synergy."""
        # lead_a: None → ++ (delta +2); lead_b: ++ → None/-- (delta -2)
        # combined = 0; abs(0) - max(2,2) = -2
        lead_a = make_lead("l-001", "lead-a", loop=1, resolutions=[
            make_resolution("h-001", None, "++"),  # delta +2
        ])
        lead_b = make_lead("l-002", "lead-b", loop=1, resolutions=[
            make_resolution("h-001", "++", "--"),  # delta -4: abs(combined)=abs(-2)=2; max=4 → -2
        ])
        corpus = [make_companion("c1", [make_hypothesis("h-001", "?test")], [lead_a, lead_b])]
        result = lead_pair_synergy(corpus)
        assert result["count"] == 1
        # combined = +2 + (-4) = -2; abs(-2) - max(2,4) = 2 - 4 = -2
        assert result["hits"][0]["mean_synergy"] < 0

    def test_both_negative_is_synergistic(self):
        """Both leads push hypothesis negative — they reinforce each other, positive synergy."""
        lead_a = make_lead("l-001", "lead-a", loop=1, resolutions=[
            make_resolution("h-001", None, "--"),  # delta -2
        ])
        lead_b = make_lead("l-002", "lead-b", loop=1, resolutions=[
            make_resolution("h-001", "--", "--"),  # delta 0 (already at --)
        ])
        corpus = [make_companion("c1", [make_hypothesis("h-001", "?test")], [lead_a, lead_b])]
        result = lead_pair_synergy(corpus)
        # combined = -2 + 0 = -2; abs(-2) - max(2,0) = 2 - 2 = 0 (no extra synergy, not anti)
        assert result["hits"][0]["mean_synergy"] == 0.0

        # Two leads both contributing -2 each
        lead_c = make_lead("l-003", "lead-c", loop=2, resolutions=[
            make_resolution("h-001", None, "--"),  # delta -2
        ])
        lead_d = make_lead("l-004", "lead-d", loop=2, resolutions=[
            make_resolution("h-001", None, "--"),  # delta -2
        ])
        corpus2 = [make_companion("c2", [make_hypothesis("h-001", "?test")], [lead_c, lead_d])]
        result2 = lead_pair_synergy(corpus2)
        # combined = -4; abs(-4) - max(2,2) = 4 - 2 = 2  → positive synergy
        assert result2["hits"][0]["mean_synergy"] == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# Axis 2: post_failure_recovery (Class 11)
# ---------------------------------------------------------------------------

class TestPostFailureRecovery:
    def test_basic_recovery(self):
        """Failed lead followed by successful lead — effectiveness recorded."""
        fail_lead = make_lead("l-001", "primary-source", loop=1, failure_reason="timeout")
        recovery_lead = make_lead("l-002", "fallback-source", loop=2, resolutions=[
            make_resolution("h-001", None, "++"),  # abs_delta = 2
        ])
        corpus = [
            make_companion("c1", [make_hypothesis("h-001", "?test")], [fail_lead, recovery_lead])
        ]
        result = post_failure_recovery(corpus)
        assert result["count"] == 1
        hit = result["hits"][0]
        assert hit["failed_lead"] == "primary-source"
        assert hit["typical_next_lead"] == "fallback-source"
        assert hit["mean_effectiveness_of_next"] == 2.0

    def test_failed_lead_at_end_has_no_next(self):
        """Failed lead with no successor — next_lead is None."""
        fail_lead = make_lead("l-001", "only-lead", loop=1, failure_reason="timeout")
        corpus = [make_companion("c1", [make_hypothesis("h-001", "?test")], [fail_lead])]
        result = post_failure_recovery(corpus)
        assert result["count"] == 1
        hit = result["hits"][0]
        assert hit["typical_next_lead"] is None
        assert hit["mean_effectiveness_of_next"] is None

    def test_aggregation_across_cases(self):
        """Same (failed_lead, next_lead) pair in two cases — mean computed."""
        def _case(case_id: str, delta_after: str) -> Companion:
            fail_lead = make_lead("l-001", "dead-lead", loop=1, failure_reason="adapter-error")
            recovery = make_lead("l-002", "recovery-lead", loop=2, resolutions=[
                make_resolution("h-001", None, delta_after),
            ])
            return make_companion(case_id, [make_hypothesis("h-001", "?test")], [fail_lead, recovery])

        corpus = [_case("c1", "++"), _case("c2", "+")]  # deltas: 2 and 1 → mean 1.5
        result = post_failure_recovery(corpus)
        recovery_hit = next(
            h for h in result["hits"]
            if h["failed_lead"] == "dead-lead" and h["typical_next_lead"] == "recovery-lead"
        )
        assert recovery_hit["case_count"] == 2
        assert recovery_hit["mean_effectiveness_of_next"] == pytest.approx(1.5)

    def test_system_filter(self):
        fail_lead = make_lead("l-001", "dead-lead", loop=1,
                              system="wazuh", failure_reason="timeout")
        recovery = make_lead("l-002", "recovery-lead", loop=2)
        fail_other = make_lead("l-003", "other-dead", loop=1,
                               system="splunk", failure_reason="timeout")
        recovery2 = make_lead("l-004", "other-recovery", loop=2)
        corpus = [
            make_companion("c1", [], [fail_lead, recovery]),
            make_companion("c2", [], [fail_other, recovery2]),
        ]
        result = post_failure_recovery(corpus, system="wazuh")
        assert all(h["system"] == "wazuh" for h in result["hits"])

    def test_sorted_non_null_before_null(self):
        """Hits with actual next leads come before no-successor entries."""
        fail_with_next = make_lead("l-001", "lead-a", loop=1, failure_reason="timeout")
        next_lead = make_lead("l-002", "next-lead", loop=2, resolutions=[
            make_resolution("h-001", None, "+"),
        ])
        fail_no_next = make_lead("l-003", "lead-b", loop=1, failure_reason="timeout")
        corpus = [
            make_companion("c1", [make_hypothesis("h-001", "?x")], [fail_with_next, next_lead]),
            make_companion("c2", [], [fail_no_next]),
        ]
        result = post_failure_recovery(corpus)
        # None effectiveness should appear last
        none_positions = [i for i, h in enumerate(result["hits"]) if h["mean_effectiveness_of_next"] is None]
        non_none_positions = [i for i, h in enumerate(result["hits"]) if h["mean_effectiveness_of_next"] is not None]
        if none_positions and non_none_positions:
            assert max(non_none_positions) < min(none_positions)


# ---------------------------------------------------------------------------
# Axis 2: independent_datasource_metric (Class 12)
# ---------------------------------------------------------------------------

class TestIndependentDatasourceMetric:
    def test_distinct_system_count(self):
        leads = [
            make_lead("l-001", "lead-a", loop=1, system="wazuh"),
            make_lead("l-002", "lead-b", loop=2, system="ad"),
            make_lead("l-003", "lead-c", loop=3, system="wazuh"),  # duplicate
        ]
        corpus = [make_companion("c1", [], leads)]
        result = independent_datasource_metric(corpus)
        assert result["count"] == 1
        hit = result["hits"][0]
        assert hit["distinct_system_count"] == 2  # wazuh + ad
        assert set(hit["systems"]) == {"wazuh", "ad"}

    def test_single_system(self):
        leads = [make_lead("l-001", "lead-a", loop=1, system="wazuh")]
        corpus = [make_companion("c1", [], leads)]
        result = independent_datasource_metric(corpus)
        assert result["hits"][0]["distinct_system_count"] == 1

    def test_hits_sorted_by_distinct_system_count_desc(self):
        leads_many = [
            make_lead("l-001", "a", loop=1, system="wazuh"),
            make_lead("l-002", "b", loop=2, system="ad"),
            make_lead("l-003", "c", loop=3, system="splunk"),
        ]
        leads_few = [make_lead("l-001", "a", loop=1, system="wazuh")]
        corpus = [
            make_companion("few", [], leads_few),
            make_companion("many", [], leads_many),
        ]
        result = independent_datasource_metric(corpus)
        assert result["hits"][0]["case_id"] == "many"
        assert result["hits"][1]["case_id"] == "few"

    def test_distribution_groups_by_termination_disposition_confidence(self):
        leads_a = [
            make_lead("l-001", "a", loop=1, system="wazuh"),
            make_lead("l-002", "b", loop=2, system="ad"),
        ]
        leads_b = [make_lead("l-001", "a", loop=1, system="wazuh")]
        corpus = [
            make_companion("c1", [], leads_a, disposition="benign",
                           termination_category="trust-root", confidence="high"),
            make_companion("c2", [], leads_b, disposition="benign",
                           termination_category="trust-root", confidence="high"),
        ]
        result = independent_datasource_metric(corpus)
        assert len(result["distribution"]) == 1
        dist_row = result["distribution"][0]
        assert dist_row["disposition"] == "benign"
        assert dist_row["termination_category"] == "trust-root"
        assert dist_row["case_count"] == 2
        assert dist_row["mean_distinct_systems"] == pytest.approx(1.5)

    def test_disposition_filter(self):
        leads = [make_lead("l-001", "a", loop=1, system="wazuh")]
        corpus = [
            make_companion("benign-case", [], leads, disposition="benign"),
            make_companion("tp-case", [], leads, disposition="true_positive"),
        ]
        result = independent_datasource_metric(corpus, disposition="benign")
        assert result["count"] == 1
        assert result["hits"][0]["case_id"] == "benign-case"

    def test_empty_corpus(self):
        result = independent_datasource_metric([])
        assert result["count"] == 0
        assert result["distribution"] == []


# ---------------------------------------------------------------------------
# CLI: _apply_top and _run_class dispatch
# ---------------------------------------------------------------------------

class TestApplyTop:
    def test_slices_hits(self):
        result = {"hits": list(range(10)), "count": 10}
        out = _apply_top(result, 3)
        assert out["hits"] == [0, 1, 2]
        assert out["count"] == 10  # count unchanged

    def test_slices_distribution(self):
        result = {"hits": [], "distribution": list(range(5)), "count": 0}
        out = _apply_top(result, 2)
        assert out["distribution"] == [0, 1]

    def test_none_returns_unchanged(self):
        result = {"hits": list(range(10)), "count": 10}
        out = _apply_top(result, None)
        assert out["hits"] == list(range(10))

    def test_top_larger_than_result(self):
        result = {"hits": [1, 2], "count": 2}
        out = _apply_top(result, 100)
        assert out["hits"] == [1, 2]


class TestRunClassDispatch:
    def _corpus(self) -> list[Companion]:
        leads = [
            make_lead("l-001", "auth-history", loop=1, system="wazuh",
                      failure_reason="timeout"),
            make_lead("l-002", "source-class", loop=2, system="ad"),
        ]
        hyps = [
            make_hypothesis("h-001", "?monitoring-probe"),
            make_hypothesis("h-001-001", "?monitoring-cron"),
        ]
        return [make_companion("c1", hyps, leads, confidence="high")]

    def _args(self, **kwargs) -> argparse.Namespace:
        defaults = dict(
            disposition=None,
            termination_category=None,
            confidence=None,
            matched_archetype=None,
            ceiling_test_kind=None,
            anchor_id=None,
            result=None,
            authority_for_question=None,
            system=None,
            failure_reason=None,
            contains=None,
            pattern=None,
            final_weight=None,
            phrase=None,
            case_sensitive=False,
            hypothesis_patterns=None,
            discriminate_between=None,
            hyp_pattern=None,
            reversals_only=False,
            top=None,
            json=False,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_class_9_returns_hits(self):
        result = _run_class(9, self._corpus(), self._args())
        assert "hits" in result

    def test_class_9_wrong_flag_warning(self, capsys):
        """Passing --hypothesis (class 8 flag) with --class 9 emits a note to stderr."""
        _run_class(9, self._corpus(), self._args(hypothesis_patterns=["?*test*"]))
        captured = capsys.readouterr()
        assert "--hyp-pattern" in captured.err

    def test_class_9_reversals_only_dispatch(self):
        lead = make_lead("l-001", "auth-history", loop=1, resolutions=[
            make_resolution("h-001", "++", "--"),  # true reversal
            make_resolution("h-002", None, "-"),   # not a true reversal
        ])
        corpus = [make_companion("c1", [
            make_hypothesis("h-001", "?a"),
            make_hypothesis("h-002", "?b"),
        ], [lead])]
        result = _run_class(9, corpus, self._args(reversals_only=True))
        assert all(h["is_true_reversal"] for h in result["hits"])
        assert result["count"] == 1

    def test_class_10_returns_hits(self):
        result = _run_class(10, self._corpus(), self._args())
        assert "hits" in result

    def test_class_11_returns_hits(self):
        result = _run_class(11, self._corpus(), self._args())
        assert "hits" in result

    def test_class_12_returns_hits_and_distribution(self):
        result = _run_class(12, self._corpus(), self._args())
        assert "hits" in result
        assert "distribution" in result

    def test_class_8_discriminate_dispatch(self):
        lead = make_lead("l-001", "auth-history", loop=1, resolutions=[
            make_resolution("h-001", None, "++"),
            make_resolution("h-002", None, "--"),
        ])
        corpus = [
            make_companion(
                "c1",
                [make_hypothesis("h-001", "?monitoring-probe"),
                 make_hypothesis("h-002", "?brute-force")],
                [lead],
            )
        ]
        result = _run_class(8, corpus, self._args(discriminate_between=["?*monitoring*", "?*brute*"]))
        assert "hits" in result
        assert result.get("pattern1") == "?*monitoring*"

    def test_top_applied_to_class_1(self):
        corpus = [
            make_companion("c1", [], [], confidence="high"),
            make_companion("c2", [], [], confidence="medium"),
            make_companion("c3", [], [], confidence="low"),
        ]
        result = _run_class(1, corpus, self._args())
        result_top2 = _apply_top(result, 2)
        assert len(result_top2["hits"]) == 2
        assert result_top2["hits"][0]["confidence"] == "high"


# ---------------------------------------------------------------------------
# Corpus loading: SCREEN-matched companions (v2.6 — missing hypothesize block)
# ---------------------------------------------------------------------------

class TestScreenMatchedCompanion:
    def test_looks_like_companion_without_hypothesize(self):
        """v2.6 SCREEN-matched companions omit hypothesize — corpus loader must accept them."""
        doc = {
            "prologue": {"vertices": [], "edges": []},
            "findings": [],
            "conclude": {"termination": {"category": "trust-root"}, "disposition": "benign"},
        }
        assert _looks_like_companion(doc) is True

    def test_looks_like_companion_with_hypothesize(self):
        """Standard v2.5 companions with hypothesize still accepted."""
        doc = {
            "prologue": {"vertices": [], "edges": []},
            "hypothesize": {"hypotheses": []},
            "findings": [],
            "conclude": {"termination": {"category": "trust-root"}, "disposition": "benign"},
        }
        assert _looks_like_companion(doc) is True

    def test_screen_matched_companion_has_empty_hypotheses(self):
        """SCREEN-matched in-memory Companion (no hypothesize key) yields empty hypotheses list."""
        body = {
            "prologue": {"vertices": [], "edges": []},
            "findings": [],
            "conclude": {
                "termination": {"category": "trust-root", "rationale": "screen matched"},
                "disposition": "benign",
                "confidence": "high",
                "matched_archetype": "misconfigured-automation",
            },
        }
        c = Companion(case_id="screen-case", source_path=Path("."), body=body)
        assert c.hypotheses == []
        assert list(c.iter_new_hypotheses()) == []

    def test_screen_matched_companion_usable_in_class_1(self):
        """SCREEN-matched companion (no hypothesize) loads into corpus and queries work."""
        body = {
            "prologue": {"vertices": [], "edges": []},
            "findings": [],
            "conclude": {
                "termination": {"category": "trust-root", "rationale": "screen matched"},
                "disposition": "benign",
                "confidence": "high",
                "matched_archetype": "misconfigured-automation",
            },
        }
        c = Companion(case_id="screen-case", source_path=Path("."), body=body)
        from invlang.queries import coarse_case_lookup
        result = coarse_case_lookup([c], disposition="benign")
        assert result["count"] == 1
        assert result["hits"][0]["matched_archetype"] == "misconfigured-automation"


# ---------------------------------------------------------------------------
# Class 13 — lead_exemplars (ANALYZE recall)
# ---------------------------------------------------------------------------

from invlang.queries import (
    _parse_vertex_where_spec,
    _vertex_where_match,
    authorization_calibration,
    lead_exemplars,
)


def _prologue_with_endpoint(classification: str, os: str = "linux") -> dict[str, Any]:
    return {
        "vertices": [
            {
                "id": "v-001",
                "kind": "endpoint",
                "classification": classification,
                "attributes": {"os": os, "role": "worker"},
            }
        ],
        "edges": [],
    }


class TestVertexWhereParser:
    def test_kind_only(self):
        assert _parse_vertex_where_spec("endpoint") == ("endpoint", {})

    def test_kind_with_attrs(self):
        assert _parse_vertex_where_spec("endpoint:classification=high,os=linux") == (
            "endpoint",
            {"classification": "high", "os": "linux"},
        )

    def test_wildcard_kind(self):
        assert _parse_vertex_where_spec("*:classification=*") == ("*", {"classification": "*"})

    def test_kind_with_trailing_colon_is_kind_only(self):
        assert _parse_vertex_where_spec("endpoint:") == ("endpoint", {})

    def test_kind_with_star_attrs_is_kind_only(self):
        # 'endpoint:*' should mean "any endpoint, no attribute predicates" —
        # matches the help-text example a Haiku agent would copy.
        assert _parse_vertex_where_spec("endpoint:*") == ("endpoint", {})

    def test_malformed_pair_raises(self):
        with pytest.raises(ValueError, match=r"--vertex-where"):
            _parse_vertex_where_spec("endpoint:classificationonly")

    def test_match_kind_only(self):
        c = make_companion("c", [], [], prologue=_prologue_with_endpoint("high-trust"))
        assert _vertex_where_match(c, [("endpoint", {})], "any")
        assert not _vertex_where_match(c, [("user", {})], "any")

    def test_match_classification(self):
        c = make_companion("c", [], [], prologue=_prologue_with_endpoint("high-trust"))
        specs = [("endpoint", {"classification": "high-trust"})]
        assert _vertex_where_match(c, specs, "any")
        assert _vertex_where_match(c, specs, "prologue")
        assert not _vertex_where_match(
            c,
            [("endpoint", {"classification": "untrusted"})],
            "any",
        )

    def test_match_attribute_fnmatch(self):
        c = make_companion("c", [], [], prologue=_prologue_with_endpoint("high-trust", os="linux-prod"))
        assert _vertex_where_match(c, [("endpoint", {"os": "linux*"})], "any")

    def test_match_presence_only(self):
        c = make_companion("c", [], [], prologue=_prologue_with_endpoint("high-trust"))
        assert _vertex_where_match(c, [("endpoint", {"role": "*"})], "any")

    def test_target_scope(self):
        prologue = _prologue_with_endpoint("high-trust")
        prologue["vertices"].append(
            {"id": "v-002", "kind": "user", "classification": "service-acct", "attributes": {}}
        )
        lead = make_lead("l-001", "ssh-login-history", 1)
        lead["target"] = "v-002"
        c = make_companion("c", [], [lead], prologue=prologue)
        # target scope: must match the lead's target vertex specifically
        assert _vertex_where_match(c, [("user", {})], "target", lead=lead)
        assert not _vertex_where_match(c, [("endpoint", {})], "target", lead=lead)

    def test_repeated_specs_and(self):
        prologue = _prologue_with_endpoint("high-trust")
        prologue["vertices"].append(
            {"id": "v-002", "kind": "user", "classification": "human", "attributes": {}}
        )
        c = make_companion("c", [], [], prologue=prologue)
        # AND: requires both an endpoint AND a user vertex
        specs = [("endpoint", {}), ("user", {})]
        assert _vertex_where_match(c, specs, "any")
        # Missing one of the two
        c2 = make_companion("c2", [], [], prologue=_prologue_with_endpoint("high"))
        assert not _vertex_where_match(c2, specs, "any")


class TestLeadExemplars:
    def _two_cases(self):
        # Case A: high-trust endpoint, ssh-login-history says authorized → benign
        h_a = make_hypothesis("h-001", "?monitoring-probe", weight="--")
        lead_a = make_lead(
            "l-001", "ssh-login-history", 1, system="wazuh",
            resolutions=[
                make_resolution("h-001", before=None, after="--", reasoning="seen as routine"),
            ],
            observations={
                "vertices": [{"id": "v-100", "kind": "process"}],
                "edges": [{"id": "e-100", "kind": "started-by"}],
            },
        )
        a = make_companion(
            "case-A", [h_a], [lead_a],
            disposition="benign",
            prologue=_prologue_with_endpoint("high-trust"),
        )
        a.created_at = "2026-04-01T00:00:00+00:00"

        # Case B: untrusted endpoint, same lead but yields ++ for a different hypothesis
        # AND a reversal: hypothesis went from + → -- (counts toward `surprises`)
        h_b1 = make_hypothesis("h-001", "?targeted-bruteforce")
        h_b2 = make_hypothesis("h-002", "?monitoring-probe")
        lead_b = make_lead(
            "l-001", "ssh-login-history", 1, system="wazuh",
            resolutions=[
                make_resolution("h-001", before=None, after="++", reasoning="auth fail burst"),
                make_resolution("h-002", before="+", after="--", reasoning="ruled out"),
            ],
            observations={"vertices": [], "edges": []},
        )
        b = make_companion(
            "case-B", [h_b1, h_b2], [lead_b],
            disposition="true_positive",
            prologue=_prologue_with_endpoint("untrusted"),
        )
        b.created_at = "2026-04-15T00:00:00+00:00"
        return [a, b]

    def test_basic_recall(self):
        corpus = self._two_cases()
        result = lead_exemplars(corpus, "ssh-login-history")
        assert result["count"] == 2
        assert result["displayed"] == 2
        # Most-recent first: case-B (2026-04-15) before case-A (2026-04-01)
        assert [h["case_id"] for h in result["hits"]] == ["case-B", "case-A"]

    def test_output_drops_scoped_ids(self):
        result = lead_exemplars(self._two_cases(), "ssh-login-history")
        for hit in result["hits"]:
            assert "lead_id" not in hit
            for r in hit["resolutions"]:
                assert "hypothesis_id" not in r
                assert "hypothesis" not in r
                assert "hypothesis_name" in r

    def test_summary_aggregates(self):
        result = lead_exemplars(self._two_cases(), "ssh-login-history")
        s = result["summary"]
        assert s["disposition_mix"] == {"benign": 1, "true_positive": 1}
        # 3 resolutions across 2 leads: --, ++, --
        assert s["assessment_mix"] == {"++": 1, "--": 2}
        # case-B has +→-- on ?monitoring-probe → 1 surprise
        assert s["surprises"] == 1
        # ?monitoring-probe appears in both cases (twice total)
        modal_names = [m["hypothesis_name"] for m in s["modal_hypothesis_outcome"]]
        assert "?monitoring-probe" in modal_names

    def test_vertex_where_filter_narrows(self):
        corpus = self._two_cases()
        result = lead_exemplars(
            corpus,
            "ssh-login-history",
            vertex_where=[("endpoint", {"classification": "high-trust"})],
        )
        assert result["count"] == 1
        assert result["hits"][0]["case_id"] == "case-A"

    def test_lead_pattern_no_match(self):
        result = lead_exemplars(self._two_cases(), "*nonexistent*")
        assert result["count"] == 0
        assert result["hits"] == []
        # Empty summary still has the keys
        assert result["summary"]["surprises"] == 0


# ---------------------------------------------------------------------------
# Class 14 — authorization_calibration (ANALYZE recall)
# ---------------------------------------------------------------------------


def _make_authz_lead(
    lead_id: str,
    contract_ref: str,
    verdict: str,
    edge_id: str = "e-100",
    anchor_kind: str = "iam-policy",
    authority: str = "full",
) -> dict[str, Any]:
    return make_lead(
        lead_id, "iam-policy-check", 1, system="iam",
        observations={
            "vertices": [],
            "edges": [{
                "id": edge_id,
                "kind": "executes",
                "authorization_resolutions": [{
                    "verdict": verdict,
                    "anchor_kind": anchor_kind,
                    "anchor_id": "policy-42",
                    "grounding_kind": "org-authority",
                    "authority_for_question": authority,
                    "as_of": "2026-04-01T00:00:00Z",
                    "fulfills_contract": contract_ref,
                    "conditioning_context": ["business-hours"],
                }],
            }],
        },
    )


class TestAuthorizationCalibration:
    def _corpus(self):
        # Hypothesis with one authorization_contract entry.
        h = {
            "id": "h-001",
            "name": "?operator-action",
            "authorization_contract": [
                {"predicate": "operator initiated this action via approved channel"}
            ],
        }
        c1 = make_companion(
            "case-1", [h],
            [_make_authz_lead("l-001", "h-001.ac1", "authorized")],
            disposition="benign",
            prologue=_prologue_with_endpoint("high-trust"),
        )
        c2 = make_companion(
            "case-2", [h],
            [_make_authz_lead("l-002", "h-001.ac1", "unauthorized", anchor_kind="oncall-schedule")],
            disposition="true_positive",
            prologue=_prologue_with_endpoint("untrusted"),
        )
        c3 = make_companion(
            "case-3", [h],
            [_make_authz_lead("l-003", "h-001.ac1", "indeterminate", authority="partial")],
            disposition="unclear",
            prologue=_prologue_with_endpoint("high-trust"),
        )
        return [c1, c2, c3]

    def test_distribution_by_verdict(self):
        result = authorization_calibration(self._corpus(), "?operator*")
        assert result["count"] == 3
        verdicts = {d["verdict"]: d for d in result["distribution"]}
        assert set(verdicts) == {"authorized", "unauthorized", "indeterminate"}
        assert verdicts["authorized"]["count"] == 1
        assert verdicts["authorized"]["disposition_mix"] == {"benign": 1}
        assert verdicts["unauthorized"]["disposition_mix"] == {"true_positive": 1}

    def test_predicate_substring_match(self):
        # Pattern that doesn't match the name but does match the predicate text.
        result = authorization_calibration(self._corpus(), "*approved channel*")
        assert result["count"] == 3

    def test_vertex_where_narrows(self):
        result = authorization_calibration(
            self._corpus(),
            "?operator*",
            vertex_where=[("endpoint", {"classification": "high-trust"})],
        )
        # case-1 (benign) and case-3 (unclear) — both high-trust
        assert result["count"] == 2

    def test_exemplars_capped(self):
        # 5 cases, all authorized — exemplars["authorized"] capped at 3
        h = {"id": "h-001", "name": "?op", "authorization_contract": [{"predicate": "x"}]}
        cases = [
            make_companion(
                f"c{i}", [h],
                [_make_authz_lead(f"l-{i}", "h-001.ac1", "authorized")],
                prologue=_prologue_with_endpoint("high"),
            )
            for i in range(5)
        ]
        result = authorization_calibration(cases, "?op")
        assert len(result["exemplars"]["authorized"]) == 3

    def test_no_match_returns_empty(self):
        result = authorization_calibration(self._corpus(), "?nothing-matches*")
        assert result["count"] == 0
        assert result["distribution"] == []
        assert result["exemplars"] == {}

    def test_surprises_detected_across_attribute_updates(self):
        # Same edge gets two different verdicts: first authorized, then unauthorized
        # via attribute_updates appended in a later lead.
        h = {"id": "h-001", "name": "?op", "authorization_contract": [{"predicate": "x"}]}
        first = _make_authz_lead("l-001", "h-001.ac1", "authorized", edge_id="e-100")
        # Second lead overrides the verdict via attribute_updates targeting the same edge.
        second = make_lead(
            "l-002", "policy-recheck", 2, system="iam",
            attribute_updates=[{
                "target_edge": "e-100",
                "authorization_resolutions": [{
                    "verdict": "unauthorized",
                    "anchor_kind": "iam-policy",
                    "anchor_id": "policy-42",
                    "grounding_kind": "org-authority",
                    "authority_for_question": "full",
                    "as_of": "2026-04-02T00:00:00Z",
                    "fulfills_contract": "h-001.ac1",
                }],
            }],
        )
        c = make_companion("flip", [h], [first, second], disposition="true_positive")
        result = authorization_calibration([c], "?op")
        assert result["surprises"] == 1


# ---------------------------------------------------------------------------
# CLI dispatch — classes 13/14/15
# ---------------------------------------------------------------------------


class TestCliDispatchNewClasses:
    def _ns(self, **overrides) -> argparse.Namespace:
        defaults = dict(
            disposition=None, termination_category=None, confidence=None,
            matched_archetype=None, ceiling_test_kind=None,
            anchor_id=None, result=None, authority_for_question=None,
            system=None, failure_reason=None, contains=None,
            pattern=None, final_weight=None, hyp_pattern=None, reversals_only=False,
            phrase=None, case_sensitive=False,
            hypothesis_patterns=None, discriminate_between=None,
            lead_pattern=None, contract_pattern=None,
            loop=None, max_age_days=180,
            vertex_where=[], vertex_scope="any",
            top=None,
        )
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_dispatch_class_13(self):
        h = make_hypothesis("h-001", "?probe", weight="-")
        lead = make_lead(
            "l-001", "ssh-login-history", 1,
            resolutions=[make_resolution("h-001", None, "-")],
        )
        c = make_companion("c", [h], [lead], prologue=_prologue_with_endpoint("high"))
        args = self._ns(lead_pattern="ssh*")
        result = _run_class(13, [c], args)
        assert result["count"] == 1
        assert "summary" in result

    def test_dispatch_class_14(self):
        h = {"id": "h-001", "name": "?op", "authorization_contract": [{"predicate": "x"}]}
        c = make_companion(
            "c", [h],
            [_make_authz_lead("l-001", "h-001.ac1", "authorized")],
            prologue=_prologue_with_endpoint("high"),
        )
        args = self._ns(contract_pattern="?op")
        result = _run_class(14, [c], args)
        assert result["count"] == 1

    def test_dispatch_class_15(self):
        # Class 15 with empty signature/prologue and no recent companions
        # should return an empty distribution but not crash.
        args = self._ns(loop=1)
        result = _run_class(15, [], args)
        assert result["distribution"] == {}
        assert "telemetry" in result


# ---------------------------------------------------------------------------
# CLI: _print_result formatter (covers the 71–114 missing chunk)
# ---------------------------------------------------------------------------

class TestPrintResult:
    def test_json_mode_dumps_raw(self, capsys):
        _print_result("ignored-label", {"count": 2, "hits": [1, 2]}, as_json=True)
        out = capsys.readouterr().out.strip()
        # Single-line JSON dump, label and decoration suppressed.
        import json as _json
        assert _json.loads(out) == {"count": 2, "hits": [1, 2]}

    def test_hits_list_under_limit(self, capsys):
        _print_result("L", {"count": 2, "hits": ["a", "b"]}, limit=10)
        out = capsys.readouterr().out
        assert "L → 2 hit(s)" in out
        assert "a" in out
        assert "b" in out
        assert "more)" not in out

    def test_hits_truncated_to_limit_shows_remaining(self, capsys):
        _print_result("L", {"count": 5, "hits": list(range(5))}, limit=2)
        out = capsys.readouterr().out
        assert "... (3 more)" in out

    def test_top_slice_header_suffix(self, capsys):
        _print_result("L", {"count": 10, "hits": [1, 2, 3]}, limit=10)
        # hits shorter than count → "[showing top 3 of 10]" header.
        out = capsys.readouterr().out
        assert "[showing top 3 of 10]" in out

    def test_distribution_dict_renders_kv(self, capsys):
        _print_result("L", {"count": 3, "distribution": {"a": 1, "b": 2}}, limit=10)
        out = capsys.readouterr().out
        assert "a: 1" in out
        assert "b: 2" in out

    def test_distribution_empty_dict_marked(self, capsys):
        _print_result("L", {"count": 0, "distribution": {}}, limit=10)
        assert "(empty)" in capsys.readouterr().out

    def test_distribution_dict_truncated(self, capsys):
        d = {f"k{i}": i for i in range(8)}
        _print_result("L", {"count": 8, "distribution": d}, limit=3)
        out = capsys.readouterr().out
        assert "... (5 more)" in out

    def test_tree_section(self, capsys):
        result = {
            "count": 1,
            "tree": {"h-001": [{"id": "h-001-001"}, {"id": "h-001-002"}]},
        }
        _print_result("L", result)
        out = capsys.readouterr().out
        assert "Tree (1 root(s)" in out
        assert "h-001-001" in out

    def test_tree_leaf_marker(self, capsys):
        _print_result("L", {"count": 1, "tree": {"h-001": []}})
        assert "(leaf)" in capsys.readouterr().out

    def test_summary_block(self, capsys):
        _print_result("L", {"count": 1, "summary": {"avg": 0.5, "n": 4}})
        out = capsys.readouterr().out
        assert "Summary:" in out
        assert "avg: 0.5" in out

    def test_exemplars_block(self, capsys):
        _print_result("L", {"count": 1, "exemplars": {"++": ["row-1"], "--": []}})
        out = capsys.readouterr().out
        assert "++ (1):" in out
        assert "row-1" in out
        assert "-- (0):" in out

    def test_matched_contracts_block(self, capsys):
        _print_result("L", {"count": 1, "matched_contracts": ["c-1", "c-2"]})
        out = capsys.readouterr().out
        assert "Matched contracts (2):" in out
        assert "c-1" in out

    def test_telemetry_and_surprises(self, capsys):
        _print_result("L", {
            "count": 1, "surprises": ["x"], "telemetry": {"runtime_ms": 12},
        })
        out = capsys.readouterr().out
        assert "Surprises:" in out
        assert "runtime_ms: 12" in out

    def test_matched_case_ids(self, capsys):
        ids = [f"case-{i}" for i in range(15)]
        _print_result("L", {"count": 15, "matched_case_ids": ids})
        out = capsys.readouterr().out
        assert "Matched case ids (15):" in out
        # First 10 only.
        assert "case-0" in out
        assert "case-9" in out

    def test_print_section_header(self, capsys):
        _print_section("Header Text")
        out = capsys.readouterr().out
        assert "Header Text" in out
        assert "=" * 72 in out


# ---------------------------------------------------------------------------
# CLI: _run_ids entry point (covers the 524–538 missing chunk)
# ---------------------------------------------------------------------------

class TestRunIds:
    def test_missing_file_emits_empty_stub(self, tmp_path, capsys):
        rc = _run_ids(str(tmp_path / "nope.md"))
        out = capsys.readouterr()
        assert rc == 0
        assert "(file not yet created" in out.err
        for kind in ("vertices", "edges", "hypotheses", "leads"):
            assert f"{kind}:" in out.out

    def test_existing_file_prints_grouped_ids(self, tmp_path, capsys):
        inv = tmp_path / "investigation.md"
        inv.write_text(
            "## CONTEXTUALIZE\n\n"
            "```invlang\n"
            ":V prologue.vertices [id|type|class|ident]\n"
            "v-001|endpoint|internal|1.2.3.4\n"
            "v-002|user|internal|alice\n"
            "```\n"
        )
        rc = _run_ids(str(inv))
        out = capsys.readouterr().out
        assert rc == 0
        assert "v-001" in out
        assert "v-002" in out
        # Groups for which there are no IDs render as "(none)".
        assert "(none)" in out
