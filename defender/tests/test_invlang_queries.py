from __future__ import annotations

from pathlib import Path

import pytest

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
    signature_id: str | None = "5710",
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


def test_lead_sequence_pattern_disposition_and_signature_filters_compose():
    corpus = [
        _case("case-a", signature_id="5710", disposition="benign"),
        _case("case-b", signature_id="5710", disposition="malicious"),
        _case("case-c", signature_id="100001", disposition="benign"),
    ]
    out = lead_sequence_pattern(corpus, disposition="benign", signature_id="5710")
    assert {h["case_id"] for h in out["hits"]} == {"case-a"}


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
                {"name": "L", "outcome": {}},
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
    """Codex P2: when `hypothesis_patterns` is supplied, `n` and `empty_rate` must reflect frontier-specific support only."""
    corpus = [
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
    """Codex P2: a lead with `tests_hypotheses` for a frontier hypothesis but no `resolutions[]` (e.g."""
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


def _shape_case(
    case_id: str,
    *,
    signature_id: str = "5710",
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


def test_hypothesis_shape_resolves_attached_to_type_from_a_mid_run_vertex():
    """The anchor index spans the WHOLE document, not just the prologue."""
    body = {
        "prologue": {"vertices": [{"id": "v-001", "type": "compute"}], "edges": []},
        "hypothesize": {"hypotheses": []},
        "findings": [{
            "name": "L1",
            "outcome": {
                "observations": {
                    "vertices": [{"id": "v-002", "type": "configuration"}], "edges": [],
                }
            },
            "new_hypotheses": [
                _hyp("h-002", "?late-config-changed", attached_to="v-002",
                     parent_type="identity", rel="modified"),
            ],
        }],
        "conclude": {"disposition": "benign"},
    }
    corpus = [Companion(
        case_id="case-late",
        source_path=Path("/tmp/fake/case-late/investigation.md"),
        body=body,
        signature_id="5710",
    )]
    out = hypothesis_shape_match(
        corpus, parent_type="identity", attached_to_type="configuration"
    )
    assert {h["name"] for h in out["hits"]} == {"?late-config-changed"}


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
    assert hit["final_weight_distribution"]["--"] == 1
    assert hit["final_weight_distribution"]["+"] == 0


def test_hypothesis_shape_match_filters_via_anchor_field():
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


def test_hypothesis_vocabulary_counts_hypotheses_the_run_raised_mid_investigation():
    """`cli`'s vocabulary command counts BOTH declaration sites — the prologue's opening hypotheses and the ones a lead raised as it went."""
    from defender.skills.invlang.cli import _hypothesis_vocabulary

    corpus = [
        _case("case-a",
              hypotheses=[{"id": "h-001", "name": "?lateral-movement"}],
              leads=[{"name": "auth", "outcome": {},
                      "new_hypotheses": [{"id": "h-002", "name": "?stolen-token"}]}]),
        _case("case-b",
              hypotheses=[],
              leads=[{"name": "auth", "outcome": {},
                      "new_hypotheses": [{"id": "h-003", "name": "?stolen-token"},
                                         {"id": "h-004", "name": "?stolen-token"}]}]),
    ]
    out = _hypothesis_vocabulary(corpus, signature_id="", top_k=10)

    assert out["n_cases"] == 2
    counts = {row["name"]: row["count"] for row in out["vocabulary"]}
    assert counts == {"?stolen-token": 2, "?lateral-movement": 1}, (
        "a lead-raised hypothesis must count, and twice in one case is still one case")
