"""verify_forward.py verdict parser + run-context loader."""
from __future__ import annotations

from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent

from defender.learning import verify_forward as vf  # type: ignore[import-not-found]


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


def test_expected_disposition_direction_aware():
    """The forward-check target is direction-aware (#317). An adversarial lesson is
    authored off a `benign` source and must PRESERVE that benign call, so the target is
    the recorded disposition. A benign (FP) lesson is authored off a `malicious` source
    it exists to CORRECT toward benign, so the target is `benign` — never the recorded
    `malicious` (which would mark every de-escalation lesson BAD and hold the FP path)."""
    # Real data flow: the author gate (`_has_confident_ground_truth`) holds any
    # `inconclusive`-source finding before the forward-check runs, so production only
    # ever calls this with a `benign`/`malicious` recorded disposition.
    assert vf.expected_disposition("adversarial", "benign") == "benign"
    assert vf.expected_disposition("benign", "malicious") == "benign"
    # The `inconclusive` rows below are defensive domain-completeness checks (the
    # function is total over the disposition enum), NOT a reachable production path —
    # they pin that a future change keeps the pure function well-defined, nothing more.
    assert vf.expected_disposition("adversarial", "inconclusive") == "inconclusive"
    assert vf.expected_disposition("benign", "inconclusive") == "benign"


# ---------------------------------------------------------------------------
# Cited covering policy loading (#338, benign forward-check)
# ---------------------------------------------------------------------------


def test_cited_case_ids_parses_menu(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "run-B").mkdir(parents=True)
    (runs / "run-B" / "past_tickets.txt").write_text(
        "- case-OLD1: benign — nightly scan\n- case-OLD2: benign — maintenance\n\n"
    )
    monkeypatch.setattr(vf, "RUNS_DIR", runs)
    assert vf._cited_case_ids("run-B") == ["case-OLD1", "case-OLD2"]


def test_cited_case_ids_empty_when_no_menu(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "run-B").mkdir(parents=True)
    monkeypatch.setattr(vf, "RUNS_DIR", runs)
    assert vf._cited_case_ids("run-B") == []


def test_load_cited_policy_renders_grounded_resolutions(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "run-B").mkdir(parents=True)
    (runs / "run-B" / "past_tickets.txt").write_text("- case-OLD1: benign — scan\n")
    monkeypatch.setattr(vf, "RUNS_DIR", runs)
    monkeypatch.setattr(
        vf, "_fetch_closed_resolution",
        lambda cid: "benign — scan [grounded: identity-confirmed (l-002)]",
    )
    out = vf.load_cited_policy("run-B")
    assert "case-OLD1" in out
    assert "grounded: identity-confirmed (l-002)" in out


def test_load_cited_policy_neutral_when_unreachable(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "run-B").mkdir(parents=True)
    (runs / "run-B" / "past_tickets.txt").write_text("- case-OLD1: benign — scan\n")
    monkeypatch.setattr(vf, "RUNS_DIR", runs)
    monkeypatch.setattr(vf, "_fetch_closed_resolution", lambda cid: None)  # store down
    assert vf.load_cited_policy("run-B") == vf._NO_CITED_POLICY


def test_load_cited_policy_neutral_when_no_menu(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "run-B").mkdir(parents=True)
    monkeypatch.setattr(vf, "RUNS_DIR", runs)
    assert vf.load_cited_policy("run-B") == vf._NO_CITED_POLICY


def test_render_user_prompt_substitutes_cited_policy(monkeypatch, tmp_path):
    prompt = tmp_path / "vf.md"
    prompt.write_text("D={disposition} P={cited_policy}")
    monkeypatch.setattr(vf, "PROMPT_PATH", prompt)
    out = vf.render_user_prompt("L", "T", "benign", "the policy block")
    assert "P=the policy block" in out
    # default keeps the prompt valid for the adversarial path (no cited policy)
    out2 = vf.render_user_prompt("L", "T", "benign")
    assert vf._NO_CITED_POLICY in out2
