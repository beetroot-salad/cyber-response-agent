"""verify_forward.py verdict parser + run-context loader."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
_WS_ROOT = HERE.parents[1]

from defender.learning.author.verify_forward import forward as vf  # type: ignore[import-not-found]
from defender.learning.author.verify_forward import shared as vfs  # type: ignore[import-not-found]
from defender._untrusted import wrap

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


def test_wrap_builds_salted_labeled_block():
    assert wrap("the transcript\n", "case_transcript", "ab" * 16) == (
        f"<run-{'ab' * 16}-case_transcript>\n"
        "the transcript\n\n"
        f"</run-{'ab' * 16}-case_transcript>"
    )


def test_wrap_body_placeholder_is_inert():
    assert wrap("route to {transcript}", "candidate_lesson", "cd" * 16) == (
        f"<run-{'cd' * 16}-candidate_lesson>\n"
        "route to {transcript}\n"
        f"</run-{'cd' * 16}-candidate_lesson>"
    )


def test_prompt_files_are_instructions_only():
    import re
    for name in ("actor.md", "forward.md"):
        text = (vf.HERE / name).read_text()
        assert re.findall(r"\{[a-z_]+\}", text) == [], f"{name} has leftover data placeholders"


def test_expected_disposition_direction_aware():
    """The forward-check target is direction-aware (#317). An adversarial lesson is
    authored off a `benign` source and must PRESERVE that benign call, so the target is
    the recorded disposition. A benign (FP) lesson is authored off a `malicious` source
    it exists to CORRECT toward benign, so the target is `benign` — never the recorded
    `malicious` (which would mark every de-escalation lesson BAD and hold the FP path)."""
    assert vf.expected_disposition("adversarial", "benign") == "benign"
    assert vf.expected_disposition("benign", "malicious") == "benign"
    assert vf.expected_disposition("adversarial", "inconclusive") == "inconclusive"
    assert vf.expected_disposition("benign", "inconclusive") == "benign"




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
    out = vf.load_cited_policy("run-B", runs_dir=runs, fetch_fn=lambda cid: None)
    assert out == vf._NO_CITED_POLICY


def test_load_cited_policy_neutral_when_no_menu(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    (runs / "run-B").mkdir(parents=True)
    assert vf.load_cited_policy("run-B", runs_dir=runs) == vf._NO_CITED_POLICY




def test_load_observation_skips_torn_line(tmp_path):
    pending = tmp_path / "actor_observations.jsonl"
    pending.write_text(
        '{"observation_id": "torn"'
        + "\n\n"
        + json.dumps({"observation_id": "o-2", "v": 7}) + "\n"
    )
    row = vfs.load_observation("o-2", pending, error_prefix=_PREFIX)
    assert row == {"observation_id": "o-2", "v": 7}


def test_load_observation_missing_file_raises(tmp_path):
    with pytest.raises(SystemExit, match="pending queue not found"):
        vfs.load_observation("o-1", tmp_path / "absent.jsonl", error_prefix=_PREFIX)


def test_load_observation_missing_id_raises(tmp_path):
    pending = tmp_path / "actor_observations.jsonl"
    pending.write_text(json.dumps({"observation_id": "o-1"}) + "\n")
    with pytest.raises(SystemExit, match="not found"):
        vfs.load_observation("o-9", pending, error_prefix=_PREFIX)




