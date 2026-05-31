"""haiku.py — classification logic with ZERO live calls.

The live model call (`_run_haiku`) is monkeypatched to replay the saved verdict
fixture captured from a real run. This tests everything around the model:
stream-json parsing, verdict parsing, the structural gate (script owns identity),
and edge tagging. The end-to-end 8/8 accuracy was proven live once and recorded
in fixtures/haiku_verdicts_raw.txt; here we lock the wiring that consumes it.
"""
from __future__ import annotations

import flowmap.haiku as haiku
from flowmap.haiku import _assistant_text, _parse_verdicts, classify_candidates
from flowmap.orchestration import seed_orchestration


# --------------------------------------------------------------------------- #
# Pure parsing units
# --------------------------------------------------------------------------- #


def test_assistant_text_concats_and_filters(fixtures_dir):
    stream = (fixtures_dir / "stream_sample.jsonl").read_text()
    parts = _assistant_text(stream)
    # thinking blocks, user msgs, garbage, and result lines are excluded
    assert parts == ["first part", "second part", "string-form content"]


def test_parse_verdicts_plain_json(fixtures_dir):
    raw = (fixtures_dir / "haiku_verdicts_raw.txt").read_text()
    vs = _parse_verdicts(raw)
    assert len(vs) == 8
    assert vs[2]["kind"] == "dispatch"


def test_parse_verdicts_tolerates_code_fence():
    fenced = '```json\n{"verdicts":[{"index":0,"kind":"dispatch"}]}\n```'
    vs = _parse_verdicts(fenced)
    assert vs == [{"index": 0, "kind": "dispatch"}]


def test_parse_verdicts_tolerates_preamble_prose():
    msg = 'Here is my analysis:\n{"verdicts":[{"index":0,"kind":"reference"}]}'
    vs = _parse_verdicts(msg)
    assert vs[0]["kind"] == "reference"


def test_parse_verdicts_raises_on_no_json():
    import pytest
    with pytest.raises(ValueError):
        _parse_verdicts("no json at all here")


# --------------------------------------------------------------------------- #
# classify_candidates with the replayed fixture (no live call)
# --------------------------------------------------------------------------- #


def _patch_haiku(monkeypatch, fixtures_dir):
    raw = (fixtures_dir / "haiku_verdicts_raw.txt").read_text()
    monkeypatch.setattr(haiku, "_run_haiku", lambda system, user: raw)
    return raw


def test_classify_reproduces_recorded_8_of_8(defender_root, fixtures_dir, monkeypatch):
    _patch_haiku(monkeypatch, fixtures_dir)
    g, cands = seed_orchestration(defender_root, defender_root / "defender")
    summary = classify_candidates(g, cands)

    assert summary["dispatch"] == 2
    assert summary["reference"] == 6
    assert summary["dropped"] == 0

    # the two dispatch edges are the gather 'follow it' sites (lines 282, 461)
    disp_refs = sorted(e.ref.split(":")[-1] for e in g.edges if e.kind == "dispatches")
    assert disp_refs == ["282", "461"]
    # the line-402 trap ("the gather subagent reads this") is NOT an edge
    assert not any(e.ref.endswith(":402") for e in g.edges if e.kind == "dispatches")


def test_classify_tags_edges_as_llm(defender_root, fixtures_dir, monkeypatch):
    _patch_haiku(monkeypatch, fixtures_dir)
    g, cands = seed_orchestration(defender_root, defender_root / "defender")
    classify_candidates(g, cands)
    for e in g.edges:
        if e.kind == "dispatches":
            assert e.confidence == "llm"
            assert e.via == "skill-marker"
            assert e.resolved_by == "haiku"


def test_structural_gate_drops_out_of_range_index(defender_root, fixtures_dir, monkeypatch):
    """Haiku may only accept/reject seeded candidates; an invented index is dropped."""
    bad = '{"verdicts":[{"index":0,"kind":"dispatch"},{"index":999,"kind":"dispatch"}]}'
    monkeypatch.setattr(haiku, "_run_haiku", lambda system, user: bad)
    g, cands = seed_orchestration(defender_root, defender_root / "defender")
    summary = classify_candidates(g, cands)
    assert summary["dropped"] == 1  # the index-999 verdict could not mint a node


def test_missing_verdict_becomes_gap(defender_root, fixtures_dir, monkeypatch):
    """A candidate with no verdict is reported as a gap, never silently dropped."""
    partial = '{"verdicts":[{"index":0,"kind":"reference"}]}'
    monkeypatch.setattr(haiku, "_run_haiku", lambda system, user: partial)
    g, cands = seed_orchestration(defender_root, defender_root / "defender")
    classify_candidates(g, cands)
    assert sum(gp.kind == "unclassified-dispatch" for gp in g.gaps) == len(cands) - 1


def test_classify_empty_candidates_no_call(monkeypatch):
    """No candidates -> no model call at all (cost guard)."""
    def _boom(system, user):
        raise AssertionError("should not call the model with zero candidates")
    monkeypatch.setattr(haiku, "_run_haiku", _boom)
    from flowmap.model import Graph
    summary = classify_candidates(Graph(), [])
    assert summary == {"dispatch": 0, "reference": 0, "dropped": 0}
