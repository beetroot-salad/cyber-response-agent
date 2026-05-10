"""verify_forward.py verdict parser + run-context loader."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
LEARNING_DIR = HERE.parent / "learning"
sys.path.insert(0, str(LEARNING_DIR))

import verify_forward as vf  # type: ignore[import-not-found]


def test_parse_verdict_good():
    assert vf.parse_verdict("reasoning here\n\nVERDICT: GOOD\n") == "GOOD"


def test_parse_verdict_bad():
    assert vf.parse_verdict("blah\nVERDICT: BAD") == "BAD"


def test_parse_verdict_takes_last_when_multiple():
    text = "VERDICT: GOOD\nmore reasoning\nVERDICT: BAD\n"
    assert vf.parse_verdict(text) == "BAD"


def test_parse_verdict_missing_raises():
    with pytest.raises(SystemExit, match="no VERDICT line"):
        vf.parse_verdict("just reasoning, no verdict")


def test_parse_verdict_unrecognized_raises():
    with pytest.raises(SystemExit, match="unrecognized"):
        vf.parse_verdict("VERDICT: MAYBE")


def test_load_run_context(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    rid = "run-T"
    (runs / rid).mkdir(parents=True)
    (runs / rid / "investigation.md").write_text("transcript body\n")
    import yaml
    (runs / rid / "source_refs.yaml").write_text(
        yaml.safe_dump({"normalized_disposition": "benign"})
    )
    monkeypatch.setattr(vf, "RUNS_DIR", runs)
    transcript, disp = vf.load_run_context(rid)
    assert "transcript body" in transcript
    assert disp == "benign"


def test_load_run_context_missing_disposition(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "rid").mkdir(parents=True)
    (runs / "rid" / "investigation.md").write_text("x")
    import yaml
    (runs / "rid" / "source_refs.yaml").write_text(yaml.safe_dump({}))
    monkeypatch.setattr(vf, "RUNS_DIR", runs)
    with pytest.raises(SystemExit, match="missing normalized_disposition"):
        vf.load_run_context("rid")


def test_render_user_prompt_substitutes(monkeypatch, tmp_path):
    prompt = tmp_path / "vf.md"
    prompt.write_text("T={transcript} L={lesson} D={disposition}")
    monkeypatch.setattr(vf, "PROMPT_PATH", prompt)
    out = vf.render_user_prompt("the lesson", "the transcript", "benign")
    assert "T=the transcript" in out
    assert "L=the lesson" in out
    assert "D=benign" in out
