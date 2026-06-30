"""verify_forward.py verdict parser + run-context loader."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


HERE = Path(__file__).resolve().parent
# Workspace root (parent of ``defender/``) so a freshly-spawned subprocess can
# ``import defender.*``; in a worktree this is the worktree root (#425).
_WS_ROOT = HERE.parents[1]

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


# ---------------------------------------------------------------------------
# load_observation — reads the pending queue tolerantly (#446)
# ---------------------------------------------------------------------------


def test_load_observation_skips_torn_line(tmp_path):
    # A torn line (interrupted append) before the target row must be
    # skipped, not raised — load_observation reads via the shared tolerant
    # reader, so a half-written record never crashes the forward-check (#446).
    pending = tmp_path / "actor_observations.jsonl"
    pending.write_text(
        '{"observation_id": "torn"'  # torn: no closing brace
        + "\n\n"  # + a blank line
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


# ---------------------------------------------------------------------------
# #425 — the forward-check verifiers resolve the run bundle off the shared
# state root (DEFENDER_LEARNING_STATE_DIR), not the worktree they run in.
# The verifiers freeze their paths from DEFAULT_PATHS at import, so each case
# is driven in a fresh subprocess with the env var pinned (the curator agent
# pins it via curator_agent_env; here we set it directly).
# ---------------------------------------------------------------------------


def _run_with_state(snippet: str, state_dir: Path, cwd: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["DEFENDER_LEARNING_STATE_DIR"] = str(state_dir)
    env["PYTHONPATH"] = str(_WS_ROOT)
    return subprocess.run(
        [sys.executable, "-c", snippet],
        env=env, cwd=str(cwd), capture_output=True, text=True,
    )


def test_curator_agent_env_pins_state_root():
    from defender.learning.core.config import curator_agent_env

    env = curator_agent_env(Path("/shared/state"))
    assert env["DEFENDER_LEARNING_STATE_DIR"] == "/shared/state"
    assert "ANTHROPIC_API_KEY" not in env


def test_forward_resolves_bundle_off_state_root(tmp_path: Path):
    """forward.RUNS_DIR + load_run_context follow DEFENDER_LEARNING_STATE_DIR, so the
    bundle is found from a worktree cwd that has no runs/ of its own (#425)."""
    state = tmp_path / "state"
    run = state / "runs" / "run-X"
    run.mkdir(parents=True)
    (run / "investigation.md").write_text("TRANSCRIPT-BODY\n")
    (run / "source_refs.yaml").write_text(yaml.safe_dump({"normalized_disposition": "benign"}))
    worktree = tmp_path / "worktree"  # fresh checkout: no runs/
    worktree.mkdir()

    snippet = (
        "from defender.learning.author.verify_forward import forward as vf;"
        "t, d = vf.load_run_context('run-X');"
        "print('RUNS_DIR', vf.RUNS_DIR);"
        "print('OK' if ('TRANSCRIPT-BODY' in t and d == 'benign') else 'MISS')"
    )
    proc = _run_with_state(snippet, state, worktree)
    assert proc.returncode == 0, proc.stderr
    assert str(state / "runs") in proc.stdout
    assert "OK" in proc.stdout


def test_actor_resolves_story_and_pending_off_state_root(tmp_path: Path):
    """actor.load_story + actor.PENDING_FILE follow the state root (#425)."""
    state = tmp_path / "state"
    run = state / "runs" / "run-Y"
    run.mkdir(parents=True)
    (run / "actor_story.md").write_text("ACTOR-STORY-BODY\n")
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    snippet = (
        "from defender.learning.author.verify_forward import actor as a;"
        "print('PENDING', a.PENDING_FILE);"
        "print(a.load_story('defender/learning/runs/run-Y/'))"
    )
    proc = _run_with_state(snippet, state, worktree)
    assert proc.returncode == 0, proc.stderr
    assert str(state / "_pending" / "actor_observations.jsonl") in proc.stdout
    assert "ACTOR-STORY-BODY" in proc.stdout


def test_env_case_entities_off_state_root(tmp_path: Path):
    """env.case_entities_arg(row, DEFAULT_PATHS.runs_dir) reads the source-case
    prologue off the state root, the path main() uses (#425)."""
    state = tmp_path / "state"
    run = state / "runs" / "run-Z"
    run.mkdir(parents=True)
    (run / "investigation.md").write_text(
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|process|process:nc|nc[1]|\n"
        "```\n"
    )
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    snippet = (
        "from defender.learning.author.verify_forward import env as e;"
        "row = {'source_run_dir': 'defender/learning/runs/run-Z/'};"
        "print('ENTITIES', e.case_entities_arg(row, e.DEFAULT_PATHS.runs_dir))"
    )
    proc = _run_with_state(snippet, state, worktree)
    assert proc.returncode == 0, proc.stderr
    assert "ENTITIES process:nc" in proc.stdout
