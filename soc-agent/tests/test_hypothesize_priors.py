"""Tests for topology-conditioned past-investigation priors.

Covers the new invlang corpus helpers (`hypothesis_topology`,
`lead_effectiveness_for_topology`, `peer_hypothesis_distribution_for_topology`)
and the hypothesize handler's `_format_priors` rendering.

Uses in-memory Companion fixtures — no file I/O, no Claude subprocess.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))
sys.path.insert(0, str(SOC_AGENT_ROOT))

from invlang.corpus import Companion, hypothesis_topology  # noqa: E402
from invlang.queries import (  # noqa: E402
    lead_effectiveness_for_hypothesis,
    lead_effectiveness_for_topology,
    peer_hypothesis_distribution_for_topology,
)
from scripts.handlers.hypothesize import _format_priors  # noqa: E402


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _prologue(
    vertices: list[dict[str, Any]] | None = None,
    edges: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {"vertices": vertices or [], "edges": edges or []}


def _companion(
    case_id: str,
    *,
    prologue: dict[str, Any],
    hypotheses: list[dict[str, Any]],
    leads: list[dict[str, Any]] | None = None,
) -> Companion:
    body = {
        "prologue": prologue,
        "hypothesize": {"hypotheses": hypotheses},
        "gather": list(leads or []),
        "conclude": {"disposition": "benign"},
    }
    return Companion(case_id=case_id, source_path=Path("."), body=body)


def _hyp(
    hid: str,
    name: str,
    attached_to: str,
    proposed_edge: Any,
) -> dict[str, Any]:
    return {
        "id": hid,
        "name": name,
        "attached_to_vertex": attached_to,
        "proposed_edge": proposed_edge,
    }


# ---------------------------------------------------------------------------
# hypothesis_topology — v2.8 structured shape
# ---------------------------------------------------------------------------


def test_hypothesis_topology_structured_shape():
    prologue = _prologue(
        vertices=[{"id": "v-001", "type": "process", "classification": "shell"}]
    )
    h = _hyp(
        "h-001",
        "?runtime-process",
        "v-001",
        {
            "relation": "spawned",
            "parent_vertex": {
                "type": "process",
                "classification": "in-container-runtime-descendant",
            },
        },
    )
    sib = _hyp("h-002", "?underlying-host", "v-001", {"relation": "spawned", "parent_vertex": {}})
    fp = hypothesis_topology(prologue, h, [h, sib])
    assert fp["attached_vertex"] == {"type": "process", "classification": "shell"}
    assert fp["relation"] == "spawned"
    assert fp["parent_vertex"] == {
        "type": "process",
        "classification": "in-container-runtime-descendant",
    }
    assert fp["peers"] == ("?underlying-host",)


def test_hypothesis_topology_missing_parent_returns_partial():
    prologue = _prologue(
        vertices=[{"id": "v-001", "type": "endpoint", "classification": "host"}]
    )
    # proposed_edge carries relation but omits parent_vertex — attached-vertex
    # fields still resolve, parent fields degrade to None.
    h = _hyp("h-001", "?orphan", "v-001", {"relation": "spawned"})
    fp = hypothesis_topology(prologue, h, [h])
    assert fp["attached_vertex"] == {"type": "endpoint", "classification": "host"}
    assert fp["relation"] == "spawned"
    assert fp["parent_vertex"] is None


# ---------------------------------------------------------------------------
# Tier ladder + lead_effectiveness_for_topology
# ---------------------------------------------------------------------------


def _make_resolution(hyp_id: str, before: Any, after: str) -> dict[str, Any]:
    return {"hypothesis": hyp_id, "before": before, "after": after}


def _build_ssh_case(
    case_id: str,
    *,
    source_class: str = "monitoring-host",
    hyp_name: str = "?monitoring-probe",
    lead_name: str = "auth-history",
    before: Any = None,
    after: str = "++",
) -> Companion:
    prologue = _prologue(
        vertices=[
            {"id": "v-001", "type": "endpoint", "classification": source_class},
            {"id": "v-002", "type": "endpoint", "classification": "internal-server"},
        ],
        edges=[
            {
                "id": "e-001",
                "relation": "attempted_auth",
                "source_vertex": "v-001",
                "target_vertex": "v-002",
            }
        ],
    )
    h = {
        "id": "h-001",
        "name": hyp_name,
        "attached_to_vertex": "v-002",
        "proposed_edge": {
            "relation": "attempted_auth",
            "parent_vertex": {"type": "endpoint", "classification": source_class},
        },
    }
    lead = {
        "id": "l-001",
        "name": lead_name,
        "tests": [{"id": "t1"}],
        "resolutions": [_make_resolution("h-001", before, after)],
        "outcome": {},
    }
    return _companion(case_id, prologue=prologue, hypotheses=[h], leads=[lead])


def test_topology_match_tier_ladder_exact():
    corpus = [
        _build_ssh_case("exact-match", source_class="monitoring-host"),
        _build_ssh_case(
            "different-source",
            source_class="workstation",
            hyp_name="?laptop-probe",
        ),
    ]
    fp = {
        "attached_vertex": {"type": "endpoint", "classification": "internal-server"},
        "relation": "attempted_auth",
        "parent_vertex": {"type": "endpoint", "classification": "monitoring-host"},
        "peers": (),
    }
    result = lead_effectiveness_for_topology(corpus, fp)
    assert result["tier_used"] == 0
    assert result["tier_label"] == "exact"
    assert result["count"] == 1
    assert result["hits"][0]["lead_name"] == "auth-history"


def test_topology_match_tier_ladder_drops_parent_class():
    # Query parent-class ("unknown-monitoring-flavor") won't match exactly;
    # dropping it (tier 1) hits both cases whose parent-type is "endpoint".
    corpus = [
        _build_ssh_case("case-a", source_class="monitoring-host"),
        _build_ssh_case("case-b", source_class="backup-server"),
    ]
    fp = {
        "attached_vertex": {"type": "endpoint", "classification": "internal-server"},
        "relation": "attempted_auth",
        "parent_vertex": {"type": "endpoint", "classification": "unknown-monitoring-flavor"},
        "peers": (),
    }
    result = lead_effectiveness_for_topology(corpus, fp)
    assert result["tier_used"] == 1
    assert result["tier_label"] == "dropped parent-class"
    assert result["count"] == 1  # same lead_name in both cases


def test_topology_match_tier_ladder_name_glob_fallback():
    # No topology match — different relations — but parent classification slug
    # appears in a hypothesis name somewhere in the corpus, so tier 4 hits.
    corpus = [_build_ssh_case("case", hyp_name="?monitoring-probe-variant")]
    fp = {
        "attached_vertex": {"type": "file", "classification": "log"},
        "relation": "modified",
        "parent_vertex": {"type": "process", "classification": "monitoring"},
        "peers": (),
    }
    result = lead_effectiveness_for_topology(corpus, fp)
    assert result["tier_used"] == 4
    assert result["tier_label"] == "name-glob fallback"
    assert result["count"] >= 1


def test_topology_match_no_hits_returns_empty_banner():
    corpus = [_build_ssh_case("case", hyp_name="?monitoring-probe")]
    fp = {
        "attached_vertex": {"type": "container", "classification": "pod"},
        "relation": "executed",
        "parent_vertex": {"type": "process", "classification": "nothing-matches-this-slug"},
        "peers": (),
    }
    result = lead_effectiveness_for_topology(corpus, fp)
    assert result["hits"] == []
    assert result["count"] == 0
    assert result["tier_used"] == 4
    assert result["tier_label"] == "no match"


# ---------------------------------------------------------------------------
# Normalized ranking vs count-weighted
# ---------------------------------------------------------------------------


def test_topology_ranking_uses_normalized_score():
    """Lead B (few occurrences, strong mean) should rank above lead A (many
    occurrences, weak mean) — opposite of the count-weighted class-8 sort."""
    # Lead A: appears 5 times with small deltas (before=None → after=+; |Δ|=1)
    # Lead B: appears 2 times with large deltas (before=None → after=++; |Δ|=2)
    prologue = _prologue(
        vertices=[
            {"id": "v-001", "type": "endpoint", "classification": "internal-server"},
            {"id": "v-002", "type": "endpoint", "classification": "monitoring-host"},
        ],
        edges=[
            {
                "id": "e-001",
                "relation": "attempted_auth",
                "source_vertex": "v-002",
                "target_vertex": "v-001",
            }
        ],
    )
    structured_edge = {
        "relation": "attempted_auth",
        "parent_vertex": {"type": "endpoint", "classification": "monitoring-host"},
    }
    cases = []
    # Five cases with lead A
    for i in range(5):
        h = {
            "id": f"h-{i}",
            "name": "?monitoring-probe",
            "attached_to_vertex": "v-001",
            "proposed_edge": structured_edge,
        }
        lead_a = {
            "id": "l-a",
            "name": "lead-a",
            "tests": [{"id": "t1"}],
            "resolutions": [_make_resolution(f"h-{i}", None, "+")],
            "outcome": {},
        }
        cases.append(_companion(f"a{i}", prologue=prologue, hypotheses=[h], leads=[lead_a]))
    # Two cases with lead B
    for i in range(2):
        h = {
            "id": f"h-b{i}",
            "name": "?monitoring-probe",
            "attached_to_vertex": "v-001",
            "proposed_edge": structured_edge,
        }
        lead_b = {
            "id": "l-b",
            "name": "lead-b",
            "tests": [{"id": "t1"}],
            "resolutions": [_make_resolution(f"h-b{i}", None, "++")],
            "outcome": {},
        }
        cases.append(_companion(f"b{i}", prologue=prologue, hypotheses=[h], leads=[lead_b]))

    fp = {
        "attached_vertex": {"type": "endpoint", "classification": "internal-server"},
        "relation": "attempted_auth",
        "parent_vertex": {"type": "endpoint", "classification": "monitoring-host"},
        "peers": (),
    }
    result = lead_effectiveness_for_topology(cases, fp)
    assert result["tier_used"] == 0
    names = [h["lead_name"] for h in result["hits"]]
    assert names[0] == "lead-b", (
        f"expected lead-b first (higher per-occurrence mean), got ordering: {names}"
    )
    # Sanity: the normalized scores should reflect this.
    row_b = next(r for r in result["hits"] if r["lead_name"] == "lead-b")
    row_a = next(r for r in result["hits"] if r["lead_name"] == "lead-a")
    assert row_b["mean_branching_delta"] > row_a["mean_branching_delta"]
    assert row_a["branching_support"] == 5
    assert row_b["branching_support"] == 2


# ---------------------------------------------------------------------------
# Tier-4 agreement with name-glob baseline
# ---------------------------------------------------------------------------


def test_lead_effectiveness_for_topology_tier4_exposes_normalized_fields():
    corpus = [_build_ssh_case("case")]
    fp = {
        "attached_vertex": {"type": "file", "classification": "log"},
        "relation": "modified",
        "parent_vertex": {"type": "process", "classification": "monitoring"},
        "peers": (),
    }
    topo = lead_effectiveness_for_topology(corpus, fp)
    assert topo["tier_used"] == 4
    row = topo["hits"][0]
    # New normalized fields exist on every row from _lead_effectiveness_rows.
    assert "mean_branching_delta" in row
    assert "fidelity_rate" in row
    assert row["branching_support"] == 1
    # Count-weighted parity: same lead should also appear in the name-glob
    # baseline output, with matching count-weighted score.
    baseline = lead_effectiveness_for_hypothesis(corpus, "?*monitoring*")
    baseline_row = next(r for r in baseline["hits"] if r["lead_name"] == row["lead_name"])
    assert baseline_row["branching_delta"] == row["branching_delta"]


# ---------------------------------------------------------------------------
# Peer-hypothesis distribution
# ---------------------------------------------------------------------------


def test_peer_hypothesis_distribution():
    # Three cases, all attaching ?A and varying peers:
    #   case-1: peers = [?B]
    #   case-2: peers = [?B]
    #   case-3: peers = [?C]
    prologue = _prologue(
        vertices=[
            {"id": "v-001", "type": "endpoint", "classification": "server"},
            {"id": "v-002", "type": "endpoint", "classification": "source"},
        ],
        edges=[
            {
                "id": "e-001",
                "relation": "attempted_auth",
                "source_vertex": "v-002",
                "target_vertex": "v-001",
            }
        ],
    )

    structured_edge = {
        "relation": "attempted_auth",
        "parent_vertex": {"type": "endpoint", "classification": "source"},
    }

    def _case(case_id: str, peer_name: str, peer_final: str) -> Companion:
        h_a = {
            "id": "h-a",
            "name": "?A",
            "attached_to_vertex": "v-001",
            "proposed_edge": structured_edge,
        }
        h_peer = {
            "id": "h-peer",
            "name": peer_name,
            "attached_to_vertex": "v-001",
            "proposed_edge": structured_edge,
        }
        lead = {
            "id": "l-001",
            "name": "some-lead",
            "tests": [{"id": "t1"}],
            "resolutions": [
                _make_resolution("h-a", None, "++"),
                _make_resolution("h-peer", None, peer_final),
            ],
            "outcome": {},
        }
        return _companion(case_id, prologue=prologue, hypotheses=[h_a, h_peer], leads=[lead])

    corpus = [
        _case("c1", "?B", "++"),
        _case("c2", "?B", "-"),
        _case("c3", "?C", "++"),
    ]
    fp = {
        "attached_vertex": {"type": "endpoint", "classification": "server"},
        "relation": "attempted_auth",
        "parent_vertex": {"type": "endpoint", "classification": "source"},
        "peers": (),
    }
    result = peer_hypothesis_distribution_for_topology(corpus, fp)
    assert result["tier_used"] == 0
    hits = {h["classification"]: h for h in result["hits"]}
    # Topology is a position, not a named pick; classifications at the same
    # position (including ?A itself) are all in-scope. ?A appears in every
    # in-scope case so its peer_count equals the case count — the caller
    # reads this as "this classification has been proposed here before, so
    # the current pick isn't novel."
    assert set(hits.keys()) == {"?A", "?B", "?C"}
    assert hits["?A"]["peer_count"] == 3
    assert hits["?B"]["peer_count"] == 2
    assert hits["?B"]["final_weight_histogram"]["++"] == 1
    assert hits["?B"]["final_weight_histogram"]["-"] == 1
    assert hits["?C"]["peer_count"] == 1
    assert hits["?C"]["final_weight_histogram"]["++"] == 1


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------


def test_format_priors_stamps_tier_and_label():
    priors = [
        {
            "name": "?monitoring-probe",
            "fingerprint": {},
            "tier_used": 2,
            "tier_label": "also dropped parent-type",
            "leads": [
                {
                    "lead_name": "auth-history",
                    "mean_branching_delta": 0.75,
                    "fidelity_rate": 0.66,
                    "branching_support": 3,
                    "fidelity_support": 2,
                }
            ],
            "peers": [
                {
                    "classification": "?adversary-in-approved-source",
                    "peer_count": 2,
                    "final_weight_histogram": {"++": 0, "+": 0, "null": 0, "-": 1, "--": 1},
                }
            ],
        }
    ]
    out = _format_priors(priors)
    assert "## Past-investigation priors" in out
    assert "?monitoring-probe (tier 2 — also dropped parent-type)" in out
    assert "auth-history" in out
    assert "score=0.750" in out
    assert "n=3" in out
    assert "?adversary-in-approved-source" in out
    assert "-=1" in out


def test_format_priors_empty_frontier_prints_banner():
    out = _format_priors([])
    assert "## Past-investigation priors" in out
    assert "(no frontier extracted)" in out


def test_format_priors_empty_leads_prints_no_corpus_match():
    priors = [
        {
            "name": "?monitoring-probe",
            "fingerprint": {},
            "tier_used": 4,
            "tier_label": "no match",
            "leads": [],
            "peers": [],
        }
    ]
    out = _format_priors(priors)
    assert "(no corpus matches at any tier)" in out
