"""Defender invlang cross-case query helpers (Classes 5/6/8).

Tests run against hand-constructed Companion objects, so the surface
under test is the query logic itself — the parser has its own coverage
in test_invlang_parser.py. Constructing the dicts inline also documents
the canonical companion shape these helpers expect.
"""

from __future__ import annotations

from pathlib import Path

from defender.skills.invlang.corpus import Companion
from defender.skills.invlang.queries import (
    hypothesis_name_wildcard,
    hypothesis_shape_match,
    lead_branch_effects,
    lead_sequence_pattern,
)


def _case(
    case_id: str,
    *,
    signature_id: str | None = "wazuh-rule-5710",
    hypotheses: list[dict] | None = None,
    leads: list[dict] | None = None,
    disposition: str | None = None,
    termination: str | None = None,
) -> Companion:
    body = {
        "prologue": {"vertices": [], "edges": []},
        "hypothesize": {"hypotheses": hypotheses or []},
        "findings": leads or [],
        "conclude": {
            "disposition": disposition,
            "termination": {"category": termination} if termination else {},
        },
    }
    return Companion(
        case_id=case_id,
        source_path=Path(f"/tmp/fake/{case_id}/investigation.md"),
        body=body,
        signature_id=signature_id,
    )


# ---------------------------------------------------------------------------
# Class 5: lead_sequence_pattern
# ---------------------------------------------------------------------------


def test_lead_sequence_pattern_emits_trace_per_case():
    corpus = [
        _case(
            "case-a",
            leads=[
                {"name": "auth-events", "outcome": {}},
                {"name": "user-activity", "outcome": {}},
            ],
            disposition="benign",
            termination="natural",
        ),
        _case(
            "case-b",
            leads=[
                {"name": "auth-events", "outcome": {"failure_reason": "empty_result"}},
            ],
            disposition="inconclusive",
            termination="natural",
        ),
    ]
    out = lead_sequence_pattern(corpus)
    assert out["count"] == 2
    traces = {h["case_id"]: h["trace"] for h in out["hits"]}
    assert traces["case-a"] == "auth-events→user-activity→natural:benign"
    assert traces["case-b"] == "auth-events:FAIL→natural:inconclusive"


def test_lead_sequence_pattern_contains_filter():
    corpus = [
        _case("case-a", leads=[{"name": "auth-events", "outcome": {}}], disposition="benign"),
        _case("case-b", leads=[{"name": "process-tree", "outcome": {}}], disposition="benign"),
    ]
    out = lead_sequence_pattern(corpus, contains="auth-events")
    assert out["count"] == 1
    assert out["hits"][0]["case_id"] == "case-a"


def test_lead_sequence_pattern_disposition_and_signature_filters_compose():
    corpus = [
        _case("case-a", signature_id="wazuh-rule-5710", disposition="benign"),
        _case("case-b", signature_id="wazuh-rule-5710", disposition="malicious"),
        _case("case-c", signature_id="wazuh-rule-100001", disposition="benign"),
    ]
    out = lead_sequence_pattern(corpus, disposition="benign", signature_id="wazuh-rule-5710")
    assert {h["case_id"] for h in out["hits"]} == {"case-a"}


def test_lead_sequence_pattern_sorts_by_lead_count_desc():
    corpus = [
        _case("short", leads=[{"name": "a", "outcome": {}}]),
        _case("long", leads=[{"name": "a", "outcome": {}}, {"name": "b", "outcome": {}}, {"name": "c", "outcome": {}}]),
    ]
    out = lead_sequence_pattern(corpus)
    assert [h["case_id"] for h in out["hits"]] == ["long", "short"]


# ---------------------------------------------------------------------------
# Class 6: hypothesis_name_wildcard
# ---------------------------------------------------------------------------


def test_hypothesis_name_wildcard_matches_fnmatch():
    corpus = [
        _case(
            "case-a",
            hypotheses=[
                {"id": "h-001", "name": "?brute-force", "weight": "+"},
                {"id": "h-002", "name": "?monitoring-probe", "weight": "+"},
            ],
            leads=[
                {"name": "auth-events", "resolutions": [
                    {"hypothesis": "h-001", "before": "+", "after": "--"},
                ]},
            ],
            disposition="benign",
        ),
    ]
    out = hypothesis_name_wildcard(corpus, "?brute*")
    assert out["count"] == 1
    hit = out["hits"][0]
    assert hit["name"] == "?brute-force"
    assert hit["final_weight"] == "--"
    # investigation-scoped id must not surface
    assert "hypothesis_id" not in hit


def test_hypothesis_name_wildcard_final_weight_filter():
    corpus = [
        _case(
            "case-a",
            hypotheses=[
                {"id": "h-001", "name": "?brute-force", "weight": "+"},
                {"id": "h-002", "name": "?monitoring-probe", "weight": "+"},
            ],
            leads=[
                {"name": "L", "resolutions": [
                    {"hypothesis": "h-001", "before": "+", "after": "++"},
                    {"hypothesis": "h-002", "before": "+", "after": "--"},
                ]},
            ],
        ),
    ]
    out = hypothesis_name_wildcard(corpus, "?*", final_weight="++")
    names = [h["name"] for h in out["hits"]]
    assert names == ["?brute-force"]


def test_hypothesis_name_wildcard_uses_initial_weight_when_unassessed():
    corpus = [
        _case(
            "case-a",
            hypotheses=[{"id": "h-001", "name": "?never-touched", "weight": "+"}],
            leads=[],
        ),
    ]
    out = hypothesis_name_wildcard(corpus, "?never*")
    assert out["hits"][0]["final_weight"] == "+"


def test_hypothesis_name_wildcard_sorts_by_final_weight_desc():
    corpus = [
        _case("c1", hypotheses=[{"id": "h-001", "name": "?h", "weight": "-"}]),
        _case("c2", hypotheses=[{"id": "h-001", "name": "?h", "weight": "++"}]),
        _case("c3", hypotheses=[{"id": "h-001", "name": "?h", "weight": "+"}]),
    ]
    out = hypothesis_name_wildcard(corpus, "?h")
    assert [h["case_id"] for h in out["hits"]] == ["c2", "c3", "c1"]


# ---------------------------------------------------------------------------
# Class 8: lead_branch_effects
# ---------------------------------------------------------------------------


def test_lead_branch_effects_aggregates_per_hypothesis():
    corpus = [
        _case(
            f"case-{i}",
            hypotheses=[
                {"id": "h-001", "name": "?monitoring-probe", "weight": "+"},
                {"id": "h-002", "name": "?brute-force", "weight": "+"},
            ],
            leads=[
                {"name": "auth-events", "outcome": {"observations": {"vertices": ["v1"], "edges": []}},
                 "resolutions": [
                     {"hypothesis": "h-001", "before": "+", "after": "--"},
                     {"hypothesis": "h-002", "before": "+", "after": "++"},
                 ]},
            ],
        )
        for i in range(4)
    ]
    out = lead_branch_effects(corpus, hypothesis_patterns=("?monitoring-probe", "?brute-force"))
    assert out["count"] == 1
    row = out["leads"][0]
    assert row["lead_name"] == "auth-events"
    assert row["n"] == 4
    assert row["per_hypothesis_effect"]["?monitoring-probe"]["--"] == 4
    assert row["per_hypothesis_effect"]["?brute-force"]["++"] == 4
    assert out["frontier"] == ["?monitoring-probe", "?brute-force"]


def test_lead_branch_effects_empty_rate_counts_missing_observations():
    corpus = [
        _case(
            "case-a",
            hypotheses=[{"id": "h-001", "name": "?h", "weight": "+"}],
            leads=[
                {"name": "L", "outcome": {"observations": {"vertices": [], "edges": []}}},
                {"name": "L", "outcome": {"observations": {"vertices": ["v1"], "edges": []}}},
                {"name": "L", "outcome": {}},  # no observations block → empty
            ],
        ),
    ]
    out = lead_branch_effects(corpus)
    row = next(r for r in out["leads"] if r["lead_name"] == "L")
    assert row["n"] == 3
    assert row["empty_rate"] == "2/3"


def test_lead_branch_effects_pattern_filter_excludes_unrelated_hypotheses():
    corpus = [
        _case(
            "case-a",
            hypotheses=[
                {"id": "h-001", "name": "?brute-force", "weight": "+"},
                {"id": "h-002", "name": "?config-error", "weight": "+"},
            ],
            leads=[
                {"name": "L", "outcome": {"observations": {"vertices": ["v"], "edges": []}},
                 "resolutions": [
                     {"hypothesis": "h-001", "before": "+", "after": "++"},
                     {"hypothesis": "h-002", "before": "+", "after": "--"},
                 ]},
            ],
        ),
    ]
    out = lead_branch_effects(corpus, hypothesis_patterns=("?brute*",))
    row = out["leads"][0]
    assert list(row["per_hypothesis_effect"].keys()) == ["?brute-force"]


def test_lead_branch_effects_frontier_scopes_n_and_empty_rate():
    """Codex P2: when `hypothesis_patterns` is supplied, `n` and
    `empty_rate` must reflect frontier-specific support only. A lead that
    appeared 4 times but only touched the frontier once should report n=1
    and empty_rate scoped to that single occurrence.
    """
    corpus = [
        # Two cases where the lead touched the frontier (resolutions → ?spray).
        _case(
            f"hit-{i}",
            hypotheses=[{"id": "h-001", "name": "?spray", "weight": "+"}],
            leads=[
                {"name": "L", "outcome": {"observations": {"vertices": ["v"], "edges": []}},
                 "resolutions": [{"hypothesis": "h-001", "before": "+", "after": "++"}]},
            ],
        )
        for i in range(2)
    ] + [
        # Three cases where the same lead ran but only touched an unrelated
        # hypothesis. Empty observations in two — under the buggy counter
        # these would have been reported as 2/5 empty for ?spray.
        _case(
            f"miss-{i}",
            hypotheses=[{"id": "h-002", "name": "?unrelated", "weight": "+"}],
            leads=[
                {"name": "L", "outcome": {},
                 "resolutions": [{"hypothesis": "h-002", "before": "+", "after": "+"}]},
            ],
        )
        for i in range(3)
    ]
    out = lead_branch_effects(corpus, hypothesis_patterns=("?spray",))
    row = next(r for r in out["leads"] if r["lead_name"] == "L")
    assert row["n"] == 2
    assert row["empty_rate"] == "0/2"
    assert list(row["per_hypothesis_effect"].keys()) == ["?spray"]


def test_lead_branch_effects_surfaces_tested_hypothesis_without_resolutions():
    """Codex P2: a lead with `tests_hypotheses` for a frontier hypothesis
    but no `resolutions[]` (e.g. empty/failed gather) must still appear
    with the hypothesis present and all-zero buckets. The empty_rate is
    where the "this lead bombed on ?H" signal lives, and it's worthless
    if the row gets stripped.
    """
    corpus = [
        _case(
            f"case-{i}",
            hypotheses=[{"id": "h-001", "name": "?spray", "weight": "+"}],
            leads=[
                {"name": "L",
                 "tests_hypotheses": ["h-001"],
                 "outcome": {"observations": {"vertices": [], "edges": []}}},
            ],
        )
        for i in range(3)
    ]
    out = lead_branch_effects(corpus, hypothesis_patterns=("?spray",))
    assert out["count"] == 1
    row = out["leads"][0]
    assert row["n"] == 3
    assert row["empty_rate"] == "3/3"
    assert row["per_hypothesis_effect"] == {"?spray": {"++": 0, "+": 0, "-": 0, "--": 0}}


def test_lead_branch_effects_min_support_drops_low_n_rows():
    corpus = [
        _case("a", leads=[{"name": "rare", "outcome": {}}]),
        _case("b", leads=[{"name": "common", "outcome": {}}]),
        _case("c", leads=[{"name": "common", "outcome": {}}]),
        _case("d", leads=[{"name": "common", "outcome": {}}]),
    ]
    out = lead_branch_effects(corpus, min_support=2)
    assert [r["lead_name"] for r in out["leads"]] == ["common"]


def test_lead_branch_effects_uncapped_ordering_is_deterministic():
    """Codex P3 follow-up: uncapped per_hypothesis_effect dicts must also
    have stable key order, since the seeding loop iterates the `matching`
    set (hash-order). Required for stable JSON output across runs.
    """
    hypotheses = [{"id": f"h-{i:03}", "name": f"?z{i}", "weight": "+"} for i in range(4)]
    resolutions = [
        {"hypothesis": h["id"], "before": "+", "after": "++"} for h in hypotheses
    ]
    corpus = [
        _case(
            "case-a",
            hypotheses=hypotheses,
            leads=[{"name": "L", "outcome": {}, "resolutions": resolutions}],
        ),
    ]
    # No cap (4 hypotheses <= default max), no frontier — exercises the seed
    # loop directly. Expected: keys in sorted name order.
    out = lead_branch_effects(corpus, max_hypotheses_per_lead=10)
    keys = list(out["leads"][0]["per_hypothesis_effect"].keys())
    assert keys == ["?z0", "?z1", "?z2", "?z3"]


def test_lead_branch_effects_capped_ordering_is_deterministic_under_ties():
    """Codex P3: when many touched hypotheses tie on bucket sum and we cap
    via max_hypotheses_per_lead, the retained K must be name-sorted, not
    set-iteration-ordered (which varies with PYTHONHASHSEED).
    """
    # 6 hypotheses, each gets exactly one `++` shift → all tie at count=1.
    hypotheses = [{"id": f"h-{i:03}", "name": f"?z{i}", "weight": "+"} for i in range(6)]
    resolutions = [
        {"hypothesis": h["id"], "before": "+", "after": "++"} for h in hypotheses
    ]
    corpus = [
        _case(
            "case-a",
            hypotheses=hypotheses,
            leads=[{"name": "L", "outcome": {}, "resolutions": resolutions}],
        ),
    ]
    out = lead_branch_effects(corpus, max_hypotheses_per_lead=3)
    kept = list(out["leads"][0]["per_hypothesis_effect"].keys())
    assert kept == ["?z0", "?z1", "?z2"], (
        f"capped output should be name-sorted under ties; got {kept}"
    )


def test_lead_branch_effects_caps_hypotheses_per_lead_without_patterns():
    """Without a frontier filter, runaway hypothesis tables stay terse."""
    hypotheses = [{"id": f"h-{i:03}", "name": f"?h{i}", "weight": "+"} for i in range(10)]
    resolutions = [{"hypothesis": h["id"], "before": "+", "after": "++"} for h in hypotheses]
    corpus = [
        _case(
            "case-a",
            hypotheses=hypotheses,
            leads=[{"name": "L", "outcome": {}, "resolutions": resolutions}],
        ),
    ]
    out = lead_branch_effects(corpus, max_hypotheses_per_lead=3)
    row = out["leads"][0]
    assert len(row["per_hypothesis_effect"]) == 3


def test_lead_branch_effects_ignores_unknown_assessment_shifts():
    """A malformed `after` value (e.g. None or 'abstain') must not crash;
    it just doesn't contribute to a bucket.
    """
    corpus = [
        _case(
            "case-a",
            hypotheses=[{"id": "h-001", "name": "?h", "weight": "+"}],
            leads=[
                {"name": "L", "outcome": {},
                 "resolutions": [
                     {"hypothesis": "h-001", "before": "+", "after": None},
                     {"hypothesis": "h-001", "before": "+", "after": "abstain"},
                     {"hypothesis": "h-001", "before": "+", "after": "++"},
                 ]},
            ],
        ),
    ]
    out = lead_branch_effects(corpus, hypothesis_patterns=("?h",))
    bucket = out["leads"][0]["per_hypothesis_effect"]["?h"]
    assert bucket == {"++": 1, "+": 0, "-": 0, "--": 0}


# ---------------------------------------------------------------------------
# hypothesis_shape_match
# ---------------------------------------------------------------------------


def _shape_case(
    case_id: str,
    *,
    signature_id: str = "wazuh-rule-5710",
    vertices: list[dict] | None = None,
    hypotheses: list[dict] | None = None,
    disposition: str = "benign",
    resolutions: list[dict] | None = None,
) -> Companion:
    leads = (
        [{"name": "L", "outcome": {}, "resolutions": resolutions}]
        if resolutions else []
    )
    body = {
        "prologue": {"vertices": vertices or [], "edges": []},
        "hypothesize": {"hypotheses": hypotheses or []},
        "findings": leads,
        "conclude": {"disposition": disposition},
    }
    return Companion(
        case_id=case_id,
        source_path=Path(f"/tmp/fake/{case_id}/investigation.md"),
        body=body,
        signature_id=signature_id,
    )


def _hyp(h_id: str, name: str, *, attached_to: str = "v-001",
         parent_type: str = "compute",
         parent_class: str = "bastion/internal/known-corp",
         rel: str = "attempted_auth", weight: str | None = None) -> dict:
    return {
        "id": h_id, "name": name,
        "anchor": attached_to,
        "proposed_edge": {
            "relation": rel,
            "parent_vertex": {"type": parent_type, "classification": parent_class},
        },
        "weight": weight,
        "status": "active",
    }


def test_hypothesis_shape_requires_at_least_one_filter():
    import pytest
    with pytest.raises(ValueError, match="at least one of"):
        hypothesis_shape_match([])


def test_hypothesis_shape_aggregates_by_name_across_cases():
    corpus = [
        _shape_case(
            "case-a",
            vertices=[{"id": "v-001", "type": "compute"}],
            hypotheses=[_hyp("h-001", "?routine-admin-source", weight="++")],
        ),
        _shape_case(
            "case-b",
            vertices=[{"id": "v-001", "type": "compute"}],
            hypotheses=[_hyp("h-001", "?routine-admin-source", weight="++")],
        ),
    ]
    out = hypothesis_shape_match(corpus, parent_type="compute")
    assert out["count"] == 1
    hit = out["hits"][0]
    assert hit["name"] == "?routine-admin-source"
    assert hit["n"] == 2
    assert hit["final_weight_distribution"]["++"] == 2
    assert hit["dispositions"] == {"benign": 2}
    assert hit["cases"] == ["case-a", "case-b"]


def test_hypothesis_shape_parent_class_glob():
    corpus = [
        _shape_case(
            "case-a",
            vertices=[{"id": "v-001", "type": "compute"}],
            hypotheses=[_hyp("h-001", "?bastion-h",
                              parent_class="bastion/internal/known-corp")],
        ),
        _shape_case(
            "case-b",
            vertices=[{"id": "v-001", "type": "compute"}],
            hypotheses=[_hyp("h-002", "?novel-h",
                              parent_class="ip-only/internet/novel")],
        ),
    ]
    out = hypothesis_shape_match(corpus, parent_class="bastion/*")
    assert {h["name"] for h in out["hits"]} == {"?bastion-h"}


def test_hypothesis_shape_resolves_attached_to_type_through_prologue():
    corpus = [
        _shape_case(
            "case-a",
            vertices=[{"id": "v-001", "type": "configuration"}],
            hypotheses=[_hyp("h-001", "?config-changed", attached_to="v-001",
                              parent_type="identity", rel="modified")],
        ),
        _shape_case(
            "case-b",
            vertices=[{"id": "v-001", "type": "compute"}],
            hypotheses=[_hyp("h-002", "?compute-auth", attached_to="v-001",
                              parent_type="identity", rel="attempted_auth")],
        ),
    ]
    out = hypothesis_shape_match(
        corpus, parent_type="identity", attached_to_type="configuration"
    )
    assert {h["name"] for h in out["hits"]} == {"?config-changed"}


def test_hypothesis_shape_uses_final_weight_from_resolutions():
    corpus = [
        _shape_case(
            "case-a",
            vertices=[{"id": "v-001", "type": "compute"}],
            hypotheses=[_hyp("h-001", "?h", weight="+")],
            resolutions=[{"hypothesis": "h-001", "before": "+", "after": "--"}],
        ),
    ]
    out = hypothesis_shape_match(corpus, parent_type="compute")
    hit = out["hits"][0]
    # initial '+' overridden by final '--'
    assert hit["final_weight_distribution"]["--"] == 1
    assert hit["final_weight_distribution"]["+"] == 0


def test_hypothesis_shape_match_filters_via_anchor_field():
    """Lock the canonical key: `hypothesis_shape_match` indexes off the
    parser's `anchor` field (not the legacy `attached_to_vertex`). Built
    by hand to bypass `_hyp`'s helper layer."""
    h = {
        "id": "h-001", "name": "?config-changed",
        "anchor": "v-001",
        "proposed_edge": {
            "relation": "modified",
            "parent_vertex": {"type": "identity",
                              "classification": "service-account/known-corp"},
        },
        "weight": None, "status": "active",
    }
    corpus = [_shape_case(
        "case-a",
        vertices=[{"id": "v-001", "type": "configuration"}],
        hypotheses=[h],
    )]
    out = hypothesis_shape_match(
        corpus, parent_type="identity", attached_to_type="configuration"
    )
    assert {hit["name"] for hit in out["hits"]} == {"?config-changed"}


def test_hypothesis_shape_filters_compose_with_and():
    corpus = [
        _shape_case(
            "case-a",
            vertices=[{"id": "v-001", "type": "compute"}],
            hypotheses=[_hyp("h-001", "?matches", parent_type="identity",
                              rel="modified")],
        ),
        _shape_case(
            "case-b",
            vertices=[{"id": "v-001", "type": "compute"}],
            hypotheses=[_hyp("h-002", "?wrong-rel", parent_type="identity",
                              rel="read")],
        ),
        _shape_case(
            "case-c",
            vertices=[{"id": "v-001", "type": "compute"}],
            hypotheses=[_hyp("h-003", "?wrong-type", parent_type="compute",
                              rel="modified")],
        ),
    ]
    out = hypothesis_shape_match(corpus, parent_type="identity", rel="modified")
    assert {h["name"] for h in out["hits"]} == {"?matches"}
