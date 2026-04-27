"""Unit tests for the `invoke_subagent` wrapper's outer-layer behavior:

    - argv includes `--plugin-dir` (so inner plugin hooks fire) and
      `--session-id` (so inner hooks resolve run_dir via the fast path).
    - Session → run mapping is written before subprocess invocation.
    - Post-invocation artifacts (subagent_outputs/, subagent_audit.jsonl)
      are persisted under the run dir.
    - Env-gated subagents still receive their adapter SKILL.md appended.

Subprocess is mocked — these do not invoke the real `claude` CLI.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers import _subagent  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def run_dir_env(tmp_path, monkeypatch):
    """Create a minimal runs-dir / run-dir pair and export the env vars the
    orchestrator normally sets, so `_subagent` picks them up."""
    runs_dir = tmp_path / "runs"
    run_dir = runs_dir / "run-abc"
    run_dir.mkdir(parents=True)
    monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(runs_dir))
    monkeypatch.setenv("SOC_AGENT_RUN_DIR", str(run_dir))
    monkeypatch.setenv("SOC_AGENT_SIGNATURE_ID", "wazuh-rule-5710")
    return run_dir


def _fake_run_factory(stdout: str = "ok\n", returncode: int = 0, stderr: str = ""):
    """Build a subprocess.run replacement that captures argv and input."""
    captured = {}

    def _fake(argv, input=None, capture_output=False, text=False, timeout=None, env=None):
        captured["argv"] = list(argv)
        captured["input"] = input
        captured["env"] = env
        return subprocess.CompletedProcess(
            args=argv, returncode=returncode, stdout=stdout, stderr=stderr,
        )

    return _fake, captured


# ---------------------------------------------------------------------------
# argv shape
# ---------------------------------------------------------------------------


def test_argv_includes_plugin_dir_and_session_id(run_dir_env):
    fake, captured = _fake_run_factory(stdout="done\n")
    with patch.object(_subagent.subprocess, "run", fake):
        _subagent.invoke_subagent("archetype-match", "hello")

    argv = captured["argv"]
    assert argv[0:2] == ["claude", "-p"]
    assert "--plugin-dir" in argv
    assert argv[argv.index("--plugin-dir") + 1] == str(_subagent.SOC_AGENT_ROOT)
    assert "--session-id" in argv
    session_id = argv[argv.index("--session-id") + 1]
    # UUID4 shape
    assert len(session_id) == 36 and session_id.count("-") == 4


def test_allowed_tools_passed_from_frontmatter(run_dir_env):
    fake, captured = _fake_run_factory()
    with patch.object(_subagent.subprocess, "run", fake):
        # archetype-scan's frontmatter declares tools — verify they flow through
        _subagent.invoke_subagent("archetype-match", "hi")
    argv = captured["argv"]
    assert "--allowed-tools" in argv
    tools = argv[argv.index("--allowed-tools") + 1]
    assert tools  # non-empty comma-separated list


# ---------------------------------------------------------------------------
# Session mapping
# ---------------------------------------------------------------------------


def test_session_mapping_written_before_invocation(run_dir_env):
    """The session→run mapping must exist in `.sessions/{uuid}.json` before
    the subagent runs, so inner hooks hit the fast path."""
    runs_dir = Path(os.environ["SOC_AGENT_RUNS_DIR"])
    mappings_before_call = []

    def _fake(argv, **kw):
        sessions_dir = runs_dir / ".sessions"
        mappings_before_call.extend(sessions_dir.glob("*.json"))
        return subprocess.CompletedProcess(argv, 0, "x\n", "")

    with patch.object(_subagent.subprocess, "run", _fake):
        _subagent.invoke_subagent("archetype-match", "hi")

    assert len(mappings_before_call) == 1, (
        "expected one session mapping written before subprocess.run"
    )
    mapping = json.loads(mappings_before_call[0].read_text())
    assert mapping["run_dir"] == str(run_dir_env)
    assert mapping["signature_id"] == "wazuh-rule-5710"


def test_no_session_mapping_when_run_dir_unset(tmp_path, monkeypatch):
    """Without SOC_AGENT_RUN_DIR (e.g. unit-test callers of `_subagent`),
    the wrapper must still work — just skip mapping + artifacts."""
    monkeypatch.delenv("SOC_AGENT_RUN_DIR", raising=False)
    monkeypatch.delenv("SOC_AGENT_SIGNATURE_ID", raising=False)
    fake, captured = _fake_run_factory()
    with patch.object(_subagent.subprocess, "run", fake):
        out = _subagent.invoke_subagent("archetype-match", "hi")
    assert out  # did not crash
    # argv still includes --session-id (harmless) but no mapping files anywhere.


# ---------------------------------------------------------------------------
# Post-invocation artifacts
# ---------------------------------------------------------------------------


def test_subagent_output_and_audit_written(run_dir_env):
    fake, _ = _fake_run_factory(stdout="hello world\n")
    with patch.object(_subagent.subprocess, "run", fake):
        _subagent.invoke_subagent("archetype-match", "prompt body")

    outputs = list((run_dir_env / "subagent_outputs").glob("*-archetype-match-*.txt"))
    assert len(outputs) == 1
    body = outputs[0].read_text()
    assert "=== PROMPT ===" in body
    assert "prompt body" in body
    assert "hello world" in body

    audit_path = run_dir_env / "subagent_audit.jsonl"
    assert audit_path.exists()
    lines = [json.loads(line) for line in audit_path.read_text().splitlines() if line]
    assert len(lines) == 1
    entry = lines[0]
    assert entry["agent"] == "archetype-match"
    assert entry["returncode"] == 0
    assert entry["prompt_chars"] >= len("prompt body")
    assert entry["stdout_chars"] == len("hello world\n")
    assert entry["session_id"]  # non-empty UUID string


def test_audit_records_nonzero_returncode_before_raising(run_dir_env):
    """Audit artifact should still land when the subagent exits non-zero."""
    fake, _ = _fake_run_factory(stdout="", stderr="boom", returncode=1)
    with patch.object(_subagent.subprocess, "run", fake):
        with pytest.raises(_subagent.OrchestrationError):
            _subagent.invoke_subagent("archetype-match", "p")

    audit_path = run_dir_env / "subagent_audit.jsonl"
    assert audit_path.exists()
    entry = json.loads(audit_path.read_text().splitlines()[0])
    assert entry["returncode"] == 1


# ---------------------------------------------------------------------------
# Env-context injection still works
# ---------------------------------------------------------------------------


def test_env_gated_subagent_gets_adapter_skill(run_dir_env, monkeypatch):
    """For env-gated subagents, the adapter SKILL.md must be appended to
    the stdin prompt (not replaced on disk)."""
    monkeypatch.setenv("SOC_AGENT_SIEM_ADAPTER", "wazuh")
    fake, captured = _fake_run_factory()
    with patch.object(_subagent.subprocess, "run", fake):
        _subagent.invoke_subagent("gather", "my prompt")
    assert "Environment adapter" in captured["input"]
    assert "my prompt" in captured["input"]
