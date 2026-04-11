"""Tests for audit hooks: tool call logger, investigation summary, and tool result tagging.

Tests the audit_tool_calls.py (PostToolUse), investigation_summary.py (Stop),
and tag_tool_results.py (PostToolUse) hooks.
"""

import json
import subprocess
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.audit_tool_calls import (
    MAX_FIELD_LEN,
    TRACE_TOOLS,
    sanitize_tool_input,
    truncate,
)
from hooks.scripts.frontmatter import parse_yaml_frontmatter
from hooks.scripts.investigation_summary import find_latest_run


# --- truncate ---


class TestTruncate:
    def test_short_string_unchanged(self):
        assert truncate("hello") == "hello"

    def test_exact_limit_unchanged(self):
        s = "x" * MAX_FIELD_LEN
        assert truncate(s) == s

    def test_over_limit_truncated(self):
        s = "x" * (MAX_FIELD_LEN + 500)
        result = truncate(s)
        assert result.startswith("x" * MAX_FIELD_LEN)
        assert "truncated" in result
        assert str(len(s)) in result

    def test_custom_limit(self):
        result = truncate("abcdefgh", max_len=4)
        assert result.startswith("abcd")
        assert "truncated" in result


# --- sanitize_tool_input ---


class TestSanitizeToolInput:
    def test_short_values_unchanged(self):
        inp = {"command": "ls -la", "description": "list files"}
        assert sanitize_tool_input(inp) == inp

    def test_large_string_truncated(self):
        inp = {"content": "x" * 5000, "file_path": "/tmp/test.py"}
        result = sanitize_tool_input(inp)
        assert result["file_path"] == "/tmp/test.py"
        assert len(result["content"]) < 5000
        assert "truncated" in result["content"]

    def test_large_nested_object_truncated(self):
        inp = {"data": {"nested": "x" * 5000}}
        result = sanitize_tool_input(inp)
        assert isinstance(result["data"], str)
        assert "truncated" in result["data"]

    def test_small_nested_object_preserved(self):
        inp = {"options": {"flag": True, "count": 5}}
        result = sanitize_tool_input(inp)
        assert result["options"] == {"flag": True, "count": 5}

    def test_empty_input(self):
        assert sanitize_tool_input({}) == {}


# --- audit_tool_calls main ---


class TestAuditToolCallsMain:
    def test_writes_jsonl_entry(self, tmp_path):
        hook_input = {
            "session_id": "sess-123",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la", "description": "list files"},
            "tool_use_id": "toolu_abc",
        }

        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            with patch("sys.stdin", StringIO(json.dumps(hook_input))):
                with pytest.raises(SystemExit) as exc_info:
                    from hooks.scripts.audit_tool_calls import main
                    main()
                assert exc_info.value.code == 0

        audit_file = tmp_path / "tool_audit.jsonl"
        assert audit_file.exists()
        entry = json.loads(audit_file.read_text().strip().split("\n")[-1])
        assert entry["session_id"] == "sess-123"
        assert entry["tool_name"] == "Bash"
        assert entry["tool_input"]["command"] == "ls -la"
        assert entry["tool_use_id"] == "toolu_abc"
        assert "timestamp" in entry
        assert "agent_id" not in entry

    def test_includes_subagent_fields(self, tmp_path):
        hook_input = {
            "session_id": "sess-456",
            "tool_name": "Bash",
            "tool_input": {"command": "whoami"},
            "tool_use_id": "toolu_def",
            "agent_id": "agent-789",
            "agent_type": "Explore",
        }

        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            with patch("sys.stdin", StringIO(json.dumps(hook_input))):
                with pytest.raises(SystemExit):
                    from hooks.scripts.audit_tool_calls import main
                    main()

        entry = json.loads(
            (tmp_path / "tool_audit.jsonl").read_text().strip().split("\n")[-1]
        )
        assert entry["agent_id"] == "agent-789"
        assert entry["agent_type"] == "Explore"

    def test_read_tool_goes_to_trace(self, tmp_path):
        hook_input = {
            "session_id": "sess-789",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/test.py"},
            "tool_use_id": "toolu_ghi",
        }

        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            with patch("sys.stdin", StringIO(json.dumps(hook_input))):
                with pytest.raises(SystemExit):
                    from hooks.scripts.audit_tool_calls import main
                    main()

        assert not (tmp_path / "tool_audit.jsonl").exists()
        trace_file = tmp_path / "tool_trace.jsonl"
        assert trace_file.exists()
        entry = json.loads(trace_file.read_text().strip())
        assert entry["tool_name"] == "Read"

    def test_glob_and_grep_go_to_trace(self, tmp_path):
        for tool in ["Glob", "Grep"]:
            hook_input = {
                "session_id": "sess-trace",
                "tool_name": tool,
                "tool_input": {"pattern": "*.py"},
                "tool_use_id": f"toolu_{tool.lower()}",
            }
            with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
                with patch("sys.stdin", StringIO(json.dumps(hook_input))):
                    with pytest.raises(SystemExit):
                        from hooks.scripts.audit_tool_calls import main
                        main()

        lines = (tmp_path / "tool_trace.jsonl").read_text().strip().split("\n")
        assert len(lines) == 2
        assert not (tmp_path / "tool_audit.jsonl").exists()

    def test_trace_tools_constant(self):
        assert TRACE_TOOLS == {"Read", "Glob", "Grep"}

    def test_invalid_stdin_exits_zero(self, tmp_path):
        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            with patch("sys.stdin", StringIO("not json")):
                with pytest.raises(SystemExit) as exc_info:
                    from hooks.scripts.audit_tool_calls import main
                    main()
                assert exc_info.value.code == 0

    def test_appends_multiple_entries(self, tmp_path):
        for i in range(3):
            hook_input = {
                "session_id": f"sess-{i}",
                "tool_name": "Bash",
                "tool_input": {"command": f"echo {i}"},
                "tool_use_id": f"toolu_{i}",
            }
            with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
                with patch("sys.stdin", StringIO(json.dumps(hook_input))):
                    with pytest.raises(SystemExit):
                        from hooks.scripts.audit_tool_calls import main
                        main()

        lines = (tmp_path / "tool_audit.jsonl").read_text().strip().split("\n")
        assert len(lines) == 3
        for i, line in enumerate(lines):
            entry = json.loads(line)
            assert entry["session_id"] == f"sess-{i}"


# --- investigation_summary (renamed from audit_logger) ---


class TestInvestigationSummaryParseFrontmatter:
    """parse_yaml_frontmatter is shared with validate_report but tested
    here to ensure the renamed module still works."""

    def test_basic_parse(self):
        text = """---
ticket_id: SEC-001
status: resolved
leads_pursued: 3
---
# Body"""
        fields = parse_yaml_frontmatter(text)
        assert fields["ticket_id"] == "SEC-001"
        assert fields["leads_pursued"] == 3

    def test_empty_returns_empty(self):
        assert parse_yaml_frontmatter("") == {}


class TestFindLatestRun:
    def test_no_runs_dir(self, tmp_path):
        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path / "nope")}):
            assert find_latest_run() is None

    def test_empty_runs_dir(self, tmp_path):
        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            assert find_latest_run() is None

    def test_finds_latest_by_mtime(self, tmp_path):
        import time

        # Create two run dirs with reports, ensuring different mtimes
        run_old = tmp_path / "run-old"
        run_old.mkdir()
        (run_old / "report.md").write_text("---\nstatus: resolved\n---\n")

        time.sleep(0.05)

        run_new = tmp_path / "run-new"
        run_new.mkdir()
        (run_new / "report.md").write_text("---\nstatus: escalated\n---\n")

        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            result = find_latest_run()
            assert result == run_new

    def test_ignores_dirs_without_report(self, tmp_path):
        no_report = tmp_path / "run-no-report"
        no_report.mkdir()

        has_report = tmp_path / "run-has-report"
        has_report.mkdir()
        (has_report / "report.md").write_text("---\nstatus: resolved\n---\n")

        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            result = find_latest_run()
            assert result == has_report


class TestInvestigationSummaryMain:
    def test_writes_summary_entry(self, tmp_path):
        run_dir = tmp_path / "run-001"
        run_dir.mkdir()
        (run_dir / "report.md").write_text(
            """---
ticket_id: SEC-042
signature_id: wazuh-rule-5710
status: resolved
disposition: benign
confidence: high
matched_archetype: monitoring-probe
matched_ticket_id: SEC-2024-001
leads_pursued: 4
---
# Report body
"""
        )
        (run_dir / "state.json").write_text(json.dumps({"run_id": "run-001"}))

        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            with patch("sys.stdin", StringIO("")):
                with pytest.raises(SystemExit) as exc_info:
                    from hooks.scripts.investigation_summary import main
                    main()
                assert exc_info.value.code == 0

        audit_file = tmp_path / "audit.jsonl"
        assert audit_file.exists()
        entry = json.loads(audit_file.read_text().strip())
        assert entry["run_id"] == "run-001"
        assert entry["ticket_id"] == "SEC-042"
        assert entry["status"] == "resolved"
        assert entry["leads_pursued"] == 4
        assert entry["matched_archetype"] == "monitoring-probe"
        assert entry["matched_ticket_id"] == "SEC-2024-001"


# --- tag_tool_results ---

TAG_SCRIPT = SOC_AGENT_ROOT / "hooks" / "scripts" / "tag_tool_results.py"


class TestTagToolResults:
    """Tests for tag_tool_results.py hook.

    The script outputs structured JSON to stdout with hook-specific output.
    For MCP tools: updatedMCPToolOutput with salted delimiters.
    For Bash/Read: additionalContext with untrusted data annotation.
    Read-vs-non-alert filtering is handled by ``if`` in plugin.json.
    """

    def _run_hook(self, stdin: str = "{}") -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(TAG_SCRIPT)],
            input=stdin,
            capture_output=True, text=True,
        )

    def test_always_outputs_annotation(self):
        result = self._run_hook()
        assert result.returncode == 0
        assert "UNTRUSTED" in result.stdout or "untrusted" in result.stdout.lower()

    def test_never_blocks_on_invalid_input(self):
        result = self._run_hook(stdin="not valid json")
        assert result.returncode == 0

    def test_outputs_json_with_hook_specific_output(self):
        hook_data = json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo hi"}})
        result = self._run_hook(stdin=hook_data)
        output = json.loads(result.stdout)
        assert "hookSpecificOutput" in output
        assert output["hookSpecificOutput"]["hookEventName"] == "PostToolUse"

    def test_mcp_tool_uses_updated_mcp_output(self):
        hook_data = json.dumps({
            "tool_name": "mcp__wazuh__query",
            "tool_input": {},
            "tool_response": {"data": "siem results"},
        })
        result = self._run_hook(stdin=hook_data)
        output = json.loads(result.stdout)
        assert "updatedMCPToolOutput" in output["hookSpecificOutput"]
        mcp_output = output["hookSpecificOutput"]["updatedMCPToolOutput"]
        assert "siem-data>" in mcp_output
        assert "siem results" in mcp_output

    def test_bash_tool_uses_additional_context(self):
        hook_data = json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo hi"}})
        result = self._run_hook(stdin=hook_data)
        output = json.loads(result.stdout)
        assert "additionalContext" in output["hookSpecificOutput"]
        assert "UNTRUSTED" in output["hookSpecificOutput"]["additionalContext"]
