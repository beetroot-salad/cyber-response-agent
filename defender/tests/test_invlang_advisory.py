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


def _stub_loader(corpus: list[Companion], *, scanned: int | None = None):
    """Build a `load_fn` that returns a hand-crafted corpus."""
    report = LoadReport(
        root=Path("/tmp/fake"),
        scanned=scanned if scanned is not None else len(corpus),
        loaded=len(corpus),
    )
    return lambda _root: (tuple(corpus), report)


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




def test_advisory_recall_returns_all_three_sections_when_signature_has_cases():
    corpus = [_benign_case(f"case-{i}") for i in range(4)]

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=("?credential-spray-scan", "?monitoring-probe"),
        load_fn=_stub_loader(corpus),
    )

    assert set(out.sections) == {
        CLASS_SIMILAR_CASES,
        CLASS_HYPOTHESIS_VOCAB,
        CLASS_LEAD_DISCRIMINATION,
    }
    assert out.telemetry["cases_for_signature"] == 4
    assert all(not s.empty for s in out.sections.values())


def test_top_k_truncates_similar_cases_and_hypothesis_vocab():
    corpus = [_benign_case(f"case-{i}") for i in range(10)]

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=("?credential-spray-scan",),
        top_k=3,
        load_fn=_stub_loader(corpus),
    )
    assert len(out.sections[CLASS_SIMILAR_CASES].hits) == 3
    assert len(out.sections[CLASS_HYPOTHESIS_VOCAB].hits) == 2


def test_hypothesis_vocab_aggregates_with_weight_histogram():
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
            leads=[],
        ),
    ]

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        classes=(CLASS_HYPOTHESIS_VOCAB,),
        load_fn=_stub_loader(corpus),
    )
    row = out.sections[CLASS_HYPOTHESIS_VOCAB].hits[0]
    assert row["name"] == "?spray"
    assert row["n"] == 3
    assert row["buckets"] == {"++": 1, "+": 1, "-": 0, "--": 1}
    assert row["unresolved"] == 0




def test_loud_empty_when_signature_has_no_cases():
    corpus = [_benign_case("c1", signature_id="sig-OTHER")]

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=("?spray",),
        load_fn=_stub_loader(corpus),
    )
    assert out.telemetry["cases_for_signature"] == 0
    for section in out.sections.values():
        assert section.empty
        assert "no cases" in section.note

    md = out.as_markdown()
    assert "No past cases for 5710" in md
    assert "### Similar cases" not in md
    assert CAVEAT in md


def test_loud_empty_at_class_level_when_frontier_has_no_match():
    corpus = [_benign_case(f"case-{i}") for i in range(3)]

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=("?nonexistent-hypothesis",),
        load_fn=_stub_loader(corpus),
    )
    section = out.sections[CLASS_LEAD_DISCRIMINATION]
    assert section.empty
    assert "no leads touched frontier" in section.note
    md = out.as_markdown()
    assert "_no leads touched frontier" in md




def test_classes_subset_only_runs_requested():
    corpus = [_benign_case(f"case-{i}") for i in range(2)]

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        classes=(CLASS_SIMILAR_CASES,),
        load_fn=_stub_loader(corpus),
    )
    assert set(out.sections) == {CLASS_SIMILAR_CASES}


def test_unknown_class_raises():
    with pytest.raises(ValueError, match="unknown advisory classes"):
        advisory_recall(
            "/tmp/fake",
            signature_id="x",
            classes=("not-a-real-class",),
        )




def test_as_markdown_renders_expected_sections_in_order():
    corpus = [_benign_case(f"case-{i}") for i in range(2)]

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=("?credential-spray-scan",),
        load_fn=_stub_loader(corpus),
    )
    md = out.as_markdown()
    sim_idx = md.index("### Similar cases")
    voc_idx = md.index("### Hypothesis vocabulary")
    dis_idx = md.index("### Lead discrimination")
    assert sim_idx < voc_idx < dis_idx
    assert CAVEAT in md
    assert "?credential-spray-scan" in md.split("### Lead discrimination", 1)[1]


def test_as_json_roundtrips_telemetry_and_sections():
    corpus = [_benign_case(f"case-{i}") for i in range(2)]

    out = advisory_recall(
        "/tmp/fake", signature_id="5710", load_fn=_stub_loader(corpus)
    )
    parsed = json.loads(out.as_json())
    assert parsed["signature_id"] == "5710"
    assert parsed["caveat"] == CAVEAT
    assert parsed["telemetry"]["cases_loaded"] == 2
    assert set(parsed["sections"]) == set(out.sections)


def test_telemetry_carries_parse_health():
    corpus = [_benign_case(f"case-{i}") for i in range(2)]

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        load_fn=_stub_loader(corpus, scanned=5),
    )
    t = out.telemetry
    assert t["cases_scanned"] == 5
    assert t["cases_loaded"] == 2
    assert t["cases_for_signature"] == 2




def test_empty_frontier_falls_back_to_top_k_leads():
    """Without a frontier, Class 8 surfaces the most-used leads as a
    baseline view — useful for ORIENT-only or pre-PREDICT consumers."""
    corpus = [_benign_case(f"case-{i}") for i in range(4)]

    out = advisory_recall(
        "/tmp/fake",
        signature_id="5710",
        frontier=(),
        top_k=3,
        load_fn=_stub_loader(corpus),
    )
    section = out.sections[CLASS_LEAD_DISCRIMINATION]
    assert not section.empty
    md = out.as_markdown()
    assert "no frontier — top recurring leads" in md
