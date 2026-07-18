"""Tests for defender/hooks/tag_tool_results.py.

PostToolUse hook: wraps MCP output and annotates adapter / alert.json
reads with a salted untrusted-data marker. Always exits 0; emits JSON on
stdout only when it tags something.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "tag_tool_results.py"


def _load():
    spec = importlib.util.spec_from_file_location("tag_tool_results", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _run(mod, payload: dict, capsys) -> dict | None:
    rc = mod.main(stdin=io.StringIO(json.dumps(payload)))
    assert rc == 0
    out = capsys.readouterr().out.strip()
    return json.loads(out) if out else None


def _write_meta(run_dir: Path, salt: str) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "meta.json").write_text(json.dumps({"run_id": run_dir.name, "salt": salt}))


def test_mcp_output_is_wrapped(monkeypatch, tmp_path, capsys):
    mod = _load()
    _write_meta(tmp_path, "deadbeef")
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    out = _run(mod, {"tool_name": "mcp__wazuh__query", "tool_response": {"hits": 3}}, capsys)
    wrapped = out["hookSpecificOutput"]["updatedMCPToolOutput"]
    assert "<run-deadbeef-siem-data>" in wrapped
    assert "</run-deadbeef-siem-data>" in wrapped


def test_adapter_cli_bash_is_annotated(monkeypatch, tmp_path, capsys):
    mod = _load()
    _write_meta(tmp_path, "cafe1234")
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    out = _run(mod, {
        "tool_name": "Bash",
        "tool_input": {"command": "python3 defender/scripts/adapters/wazuh_adapter.py search ..."},
    }, capsys)
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "[UNTRUSTED-cafe1234]" in ctx


def test_plain_bash_is_not_annotated(monkeypatch, tmp_path, capsys):
    mod = _load()
    _write_meta(tmp_path, "cafe1234")
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    out = _run(mod, {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}, capsys)
    assert out is None


def test_alert_json_read_is_annotated(monkeypatch, tmp_path, capsys):
    mod = _load()
    _write_meta(tmp_path, "abc12345")
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    out = _run(mod, {
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/defender-runs/r1/alert.json"},
    }, capsys)
    assert "[UNTRUSTED-abc12345]" in out["hookSpecificOutput"]["additionalContext"]


def test_gather_subagent_dispatch_is_annotated(monkeypatch, tmp_path, capsys):
    # The gather Task return is the primary untrusted channel into the main
    # loop; its dispatch points at the gather skill.
    mod = _load()
    _write_meta(tmp_path, "5a17ed00")
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    out = _run(mod, {
        "tool_name": "Task",
        "tool_input": {"prompt": "Read defender/skills/gather/SKILL.md and follow it.\n..."},
    }, capsys)
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "[UNTRUSTED-5a17ed00]" in ctx
    assert "gather-subagent" in ctx


def test_non_gather_task_is_not_annotated(monkeypatch, tmp_path, capsys):
    mod = _load()
    _write_meta(tmp_path, "5a17ed00")
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    out = _run(mod, {
        "tool_name": "Task",
        "tool_input": {"prompt": "Summarize the report draft."},
    }, capsys)
    assert out is None


def test_other_read_is_not_annotated(monkeypatch, tmp_path, capsys):
    mod = _load()
    _write_meta(tmp_path, "abc12345")
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    out = _run(mod, {
        "tool_name": "Read",
        "tool_input": {"file_path": "/workspace/defender/SKILL.md"},
    }, capsys)
    assert out is None


def test_fallback_salt_when_no_run_dir(monkeypatch, capsys):
    mod = _load()
    monkeypatch.delenv("DEFENDER_RUN_DIR", raising=False)
    out = _run(mod, {"tool_name": "mcp__x__y", "tool_response": {"a": 1}}, capsys)
    # Still wraps, with a generated (non-empty) salt.
    wrapped = out["hookSpecificOutput"]["updatedMCPToolOutput"]
    assert "<run-" in wrapped
    assert "-siem-data>" in wrapped
