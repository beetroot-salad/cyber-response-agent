"""Tests for the PLAN-time advisory retrieval adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.skills.invlang import advisory
from defender.skills.invlang.advisory import (
    CAVEAT,
    CLASS_HYPOTHESIS_VOCAB,
    CLASS_LEAD_DISCRIMINATION,
    CLASS_SIMILAR_CASES,
    advisory_recall,
)
from defender.skills.invlang.corpus import Companion, LoadReport


@pytest.fixture(autouse=True)
def _clear_cache():
    advisory.clear_cache()
    yield
    advisory.clear_cache()


def _case(
    case_id: str,
    *,
    signature_id: str | None = "5710",
    hypotheses=None,
    leads=None,
    disposition=None,
    termination="natural",
) -> Companion:
    body = {
        "prologue": {"vertices": [], "edges": []},
        "hypothesize": {"hypotheses": hypotheses or []},
        "findings": leads or [],
        "conclude": {
            "disposition": disposition,
            "termination": {"category": termination},
        },
    }
    return Companion(
        case_id=case_id,
        source_path=Path(f"/tmp/fake/{case_id}/investigation.md"),
        body=body,
        signature_id=signature_id,
    )


def _stub_corpus(monkeypatch, corpus: list[Companion], *, scanned: int | None = None):
    """Monkeypatch the cached loader to return a hand-crafted corpus."""
    report = LoadReport(
        root=Path("/tmp/fake"),
        scanned=scanned if scanned is not None else len(corpus),
        loaded=len(corpus),
    )
    monkeypatch.setattr(
        advisory,
        "_cached_load",
        lambda _root: (tuple(corpus), report),
    )


def _benign_case(case_id: str, *, signature_id="5710") -> Companion:
    return _case(
        case_id,
        signature_id=signature_id,
        hypotheses=[
            {"id": "h-001", "name": "?credential-spray-scan", "weight": "+"},
            {"id": "h-002", "name": "?monitoring-probe", "weight": "+"},
        ],
        leads=[
            {"name": "auth-history-from-source",
             "outcome": {"observations": {"vertices": ["v1"], "edges": []}},
             "resolutions": [
                 {"hypothesis": "h-001", "before": "+", "after": "++"},
             ]},
            {"name": "cmdb-source-lookup", "outcome": {},
             "resolutions": [
                 {"hypothesis": "h-002", "before": "+", "after": "--"},
             ]},
        ],
        disposition="benign",
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_advisory_recall_returns_all_three_sections_when_signature_has_cases(monkeypatch):
    corpus = [_benign_case(f"case-{i}") for i in range(4)]
    _stub_corpus(monkeypatch, corpus)

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=("?credential-spray-scan", "?monitoring-probe"),
    )

    assert set(out.sections) == {
        CLASS_SIMILAR_CASES,
        CLASS_HYPOTHESIS_VOCAB,
        CLASS_LEAD_DISCRIMINATION,
    }
    assert out.telemetry["cases_for_signature"] == 4
    assert all(not s.empty for s in out.sections.values())


def test_top_k_truncates_similar_cases_and_hypothesis_vocab(monkeypatch):
    corpus = [_benign_case(f"case-{i}") for i in range(10)]
    _stub_corpus(monkeypatch, corpus)

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=("?credential-spray-scan",),
        top_k=3,
    )
    assert len(out.sections[CLASS_SIMILAR_CASES].hits) == 3
    # 2 unique hypothesis names in the fixture; top_k=3 caps but won't pad.
    assert len(out.sections[CLASS_HYPOTHESIS_VOCAB].hits) == 2


def test_hypothesis_vocab_aggregates_with_weight_histogram(monkeypatch):
    """Each row is per-name with a {++, +, -, --} histogram, not per-case."""
    corpus = [
        _case(
            "c1",
            signature_id="5710",
            hypotheses=[{"id": "h-001", "name": "?spray", "weight": "+"}],
            leads=[{"name": "L", "resolutions": [
                {"hypothesis": "h-001", "before": "+", "after": "++"}
            ]}],
        ),
        _case(
            "c2",
            signature_id="5710",
            hypotheses=[{"id": "h-001", "name": "?spray", "weight": "+"}],
            leads=[{"name": "L", "resolutions": [
                {"hypothesis": "h-001", "before": "+", "after": "--"}
            ]}],
        ),
        _case(
            "c3",
            signature_id="5710",
            hypotheses=[{"id": "h-001", "name": "?spray", "weight": "+"}],
            leads=[],  # ?spray unassessed → unresolved
        ),
    ]
    _stub_corpus(monkeypatch, corpus)

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        classes=(CLASS_HYPOTHESIS_VOCAB,),
    )
    row = out.sections[CLASS_HYPOTHESIS_VOCAB].hits[0]
    assert row["name"] == "?spray"
    assert row["n"] == 3
    assert row["buckets"] == {"++": 1, "+": 1, "-": 0, "--": 1}
    assert row["unresolved"] == 0  # initial weight `+` counts as a final-bucket hit


# ---------------------------------------------------------------------------
# Loud-empty
# ---------------------------------------------------------------------------


def test_loud_empty_when_signature_has_no_cases(monkeypatch):
    corpus = [_benign_case("c1", signature_id="sig-OTHER")]
    _stub_corpus(monkeypatch, corpus)

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=("?spray",),
    )
    assert out.telemetry["cases_for_signature"] == 0
    for section in out.sections.values():
        assert section.empty
        assert "no cases" in section.note

    md = out.as_markdown()
    assert "No past cases for 5710" in md
    # Loud-empty short-circuits per-section rendering — one banner, not three.
    assert "### Similar cases" not in md
    assert CAVEAT in md


def test_loud_empty_at_class_level_when_frontier_has_no_match(monkeypatch):
    corpus = [_benign_case(f"case-{i}") for i in range(3)]
    _stub_corpus(monkeypatch, corpus)

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=("?nonexistent-hypothesis",),
    )
    section = out.sections[CLASS_LEAD_DISCRIMINATION]
    assert section.empty
    assert "no leads touched frontier" in section.note
    md = out.as_markdown()
    assert "_no leads touched frontier" in md


# ---------------------------------------------------------------------------
# Class subsetting + validation
# ---------------------------------------------------------------------------


def test_classes_subset_only_runs_requested(monkeypatch):
    corpus = [_benign_case(f"case-{i}") for i in range(2)]
    _stub_corpus(monkeypatch, corpus)

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        classes=(CLASS_SIMILAR_CASES,),
    )
    assert set(out.sections) == {CLASS_SIMILAR_CASES}


def test_unknown_class_raises():
    with pytest.raises(ValueError, match="unknown advisory classes"):
        advisory_recall(
            "/tmp/fake",
            signature_id="x",
            classes=("not-a-real-class",),
        )


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------


def test_as_markdown_renders_expected_sections_in_order(monkeypatch):
    corpus = [_benign_case(f"case-{i}") for i in range(2)]
    _stub_corpus(monkeypatch, corpus)

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=("?credential-spray-scan",),
    )
    md = out.as_markdown()
    # Order matters: similar → vocab → discrimination.
    sim_idx = md.index("### Similar cases")
    voc_idx = md.index("### Hypothesis vocabulary")
    dis_idx = md.index("### Lead discrimination")
    assert sim_idx < voc_idx < dis_idx
    assert CAVEAT in md
    # Frontier surfaces in the discrimination header for context.
    assert "?credential-spray-scan" in md.split("### Lead discrimination", 1)[1]


def test_as_json_roundtrips_telemetry_and_sections(monkeypatch):
    corpus = [_benign_case(f"case-{i}") for i in range(2)]
    _stub_corpus(monkeypatch, corpus)

    out = advisory_recall("/tmp/fake", signature_id="5710")
    parsed = json.loads(out.as_json())
    assert parsed["signature_id"] == "5710"
    assert parsed["caveat"] == CAVEAT
    assert parsed["telemetry"]["cases_loaded"] == 2
    assert set(parsed["sections"]) == set(out.sections)


def test_telemetry_carries_parse_health(monkeypatch):
    corpus = [_benign_case(f"case-{i}") for i in range(2)]
    _stub_corpus(monkeypatch, corpus, scanned=5)  # 3 files didn't load

    out = advisory_recall("/tmp/fake", signature_id="5710")
    t = out.telemetry
    assert t["cases_scanned"] == 5
    assert t["cases_loaded"] == 2
    assert t["cases_for_signature"] == 2


# ---------------------------------------------------------------------------
# Empty-frontier degeneracy
# ---------------------------------------------------------------------------


def test_empty_frontier_falls_back_to_top_k_leads(monkeypatch):
    """Without a frontier, Class 8 surfaces the most-used leads as a
    baseline view — useful for ORIENT-only or pre-PREDICT consumers."""
    corpus = [_benign_case(f"case-{i}") for i in range(4)]
    _stub_corpus(monkeypatch, corpus)

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=(),
        top_k=3,
    )
    section = out.sections[CLASS_LEAD_DISCRIMINATION]
    assert not section.empty
    md = out.as_markdown()
    assert "no frontier — top recurring leads" in md
