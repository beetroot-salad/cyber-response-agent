"""verify_forward.py verdict parser + run-context loader."""
from __future__ import annotations

from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent

from defender.learning.author.verify_forward import forward as vf  # type: ignore[import-not-found]
from defender.learning.author.verify_forward import shared as vfs  # type: ignore[import-not-found]

_PREFIX = "verify_forward"


def test_parse_verdict_good():
    assert vfs.parse_verdict("reasoning here\n\nVERDICT: GOOD\n", error_prefix=_PREFIX) == "GOOD"


def test_parse_verdict_bad():
    assert vfs.parse_verdict("blah\nVERDICT: BAD", error_prefix=_PREFIX) == "BAD"


def test_parse_verdict_takes_last_when_multiple():
    text = "VERDICT: GOOD\nmore reasoning\nVERDICT: BAD\n"
    assert vfs.parse_verdict(text, error_prefix=_PREFIX) == "BAD"


def test_parse_verdict_missing_raises():
    with pytest.raises(SystemExit, match="no VERDICT line"):
        vfs.parse_verdict("just reasoning, no verdict", error_prefix=_PREFIX)


def test_parse_verdict_unrecognized_raises():
    with pytest.raises(SystemExit, match="unrecognized"):
        vfs.parse_verdict("VERDICT: MAYBE", error_prefix=_PREFIX)


def test_load_run_context(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    rid = "run-T"
    (runs / rid).mkdir(parents=True)
    (runs / rid / "investigation.md").write_text("transcript body\n")
    import yaml
    (runs / rid / "source_refs.yaml").write_text(
        yaml.safe_dump({"normalized_disposition": "benign"})
    )
    transcript, disp = vf.load_run_context(rid, runs_dir=runs)
    assert "transcript body" in transcript
    assert disp == "benign"


def test_load_run_context_missing_disposition(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "rid").mkdir(parents=True)
    (runs / "rid" / "investigation.md").write_text("x")
    import yaml
    (runs / "rid" / "source_refs.yaml").write_text(yaml.safe_dump({}))
    with pytest.raises(SystemExit, match="missing normalized_disposition"):
        vf.load_run_context("rid", runs_dir=runs)


def test_render_prompt_substitutes(tmp_path):
    prompt = tmp_path / "vf.md"
    prompt.write_text("T={transcript} L={lesson} D={disposition}")
    out = vfs.render_prompt(
        prompt, transcript="the transcript", lesson="the lesson", disposition="benign"
    )
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
    assert vf._cited_case_ids("run-B", runs_dir=runs) == ["case-OLD1", "case-OLD2"]


def test_cited_case_ids_empty_when_no_menu(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "run-B").mkdir(parents=True)
    assert vf._cited_case_ids("run-B", runs_dir=runs) == []


def test_load_cited_policy_renders_grounded_resolutions(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "run-B").mkdir(parents=True)
    (runs / "run-B" / "past_tickets.txt").write_text("- case-OLD1: benign — scan\n")
    out = vf.load_cited_policy(
        "run-B", runs_dir=runs,
        fetch_fn=lambda cid: "benign — scan [grounded: identity-confirmed (l-002)]",
    )
    assert "case-OLD1" in out
    assert "grounded: identity-confirmed (l-002)" in out


def test_load_cited_policy_neutral_when_unreachable(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "run-B").mkdir(parents=True)
    (runs / "run-B" / "past_tickets.txt").write_text("- case-OLD1: benign — scan\n")
    # store down: fetch returns None for every cited case
    out = vf.load_cited_policy("run-B", runs_dir=runs, fetch_fn=lambda cid: None)
    assert out == vf._NO_CITED_POLICY


def test_load_cited_policy_neutral_when_no_menu(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "run-B").mkdir(parents=True)
    assert vf.load_cited_policy("run-B", runs_dir=runs) == vf._NO_CITED_POLICY


def test_render_prompt_substitutes_cited_policy(tmp_path):
    prompt = tmp_path / "vf.md"
    prompt.write_text("D={disposition} P={cited_policy}")
    out = vfs.render_prompt(
        prompt, lesson="L", transcript="T", disposition="benign",
        cited_policy="the policy block",
    )
    assert "P=the policy block" in out
    # the adversarial call site passes the neutral placeholder explicitly
    out2 = vfs.render_prompt(
        prompt, lesson="L", transcript="T", disposition="benign",
        cited_policy=vf._NO_CITED_POLICY,
    )
    assert vf._NO_CITED_POLICY in out2
