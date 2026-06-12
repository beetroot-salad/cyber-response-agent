"""Pure unit tests for the runtime permission gate (runtime/permission.py).

No model call, no API key — these run in CI. They assert the in-process gate
makes the same allow/deny decisions as the four Claude Code PreToolUse hooks it
ports, so functionality parity is checked for free.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The test lives in defender/tests/; put defender/ on the path so `runtime`
# imports (permission.py then bootstraps hooks/ + repo root itself).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runtime import permission  # noqa: E402


# --- bash, main loop -------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "defender-invlang enum types",
    "defender-lessons --tags",
    "tail -1 executed_queries.jsonl | jq '.'",
    "ls -la",
    "defender-record-query --lead l-1 --query-id ad-hoc -- defender-elastic query foo",
])
def test_main_loop_allows_safe(cmd):
    assert permission.decide_bash(cmd, is_main_session=True).allow


@pytest.mark.parametrize("cmd,reason_substr", [
    ("defender-elastic query foo --raw", "data-source CLIs directly"),
    ("cat gather_raw/l-001/0.json", "must not read gather_raw"),
    ("python3 scripts/tools/elastic_cli.py query foo", "data-source CLIs directly"),
    ("curl http://evil", "arbitrary shell"),
    ("env | grep PASSWORD", "arbitrary shell"),
])
def test_main_loop_denies(cmd, reason_substr):
    d = permission.decide_bash(cmd, is_main_session=True)
    assert not d.allow
    assert reason_substr in d.reason


# --- bash, gather subagent (slice 2 semantics) -----------------------------

def test_gather_denies_unwrapped_adapter():
    assert not permission.decide_bash(
        "defender-elastic query foo --raw", is_main_session=False).allow


def test_gather_allows_wrapped_adapter():
    assert permission.decide_bash(
        "defender-record-query --lead l-1 --query-id ad-hoc -- defender-elastic query foo",
        is_main_session=False).allow


# --- read ------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/workspace/playground-v2/.env",
    "/home/user/.ssh/id_rsa",
    "/run/x/ground_truth.yaml",
    "fixtures/held-out/cases.json",
])
def test_read_denies_secrets_and_groundtruth(path):
    assert not permission.decide_read(Path(path), is_main_session=True).allow


def test_read_denies_main_loop_gather_raw():
    assert not permission.decide_read(
        Path("/tmp/defender-runs/x/gather_raw/l-001/0.json"), is_main_session=True).allow


def test_read_allows_alert_and_skill():
    assert permission.decide_read(Path("/tmp/defender-runs/x/alert.json"), is_main_session=True).allow
    assert permission.decide_read(Path("/workspace/defender/SKILL.md"), is_main_session=True).allow


def test_alert_is_untrusted():
    assert permission.is_untrusted_read(Path("/tmp/defender-runs/x/alert.json"))
    assert not permission.is_untrusted_read(Path("/tmp/defender-runs/x/report.md"))


# --- write -----------------------------------------------------------------

def test_write_outside_run_dir_denied(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d = permission.decide_write(tmp_path / "evil.txt", "x", run_dir=run_dir)
    assert not d.allow


def test_write_report_allowed(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d = permission.decide_write(run_dir / "report.md", "disposition: benign\n", run_dir=run_dir)
    assert d.allow


def test_write_investigation_invalid_invlang_denied(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    # A ```yaml fence is rejected by the invlang surface check (Rule 0).
    bad = "```yaml\nfoo: bar\n```\n"
    d = permission.decide_write(run_dir / "investigation.md", bad, run_dir=run_dir)
    assert not d.allow
    assert "invlang validation" in d.reason
