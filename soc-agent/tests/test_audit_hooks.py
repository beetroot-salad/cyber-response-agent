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
from hooks.scripts.investigation_summary import extract_transcript_stats


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


class TestExtractTranscriptStats:
    EMPTY = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "models": [],
        "total_cost_usd": None,
    }

    def test_result_record_is_authoritative(self, tmp_path):
        """stream-json transcripts end with a `type: result` record that
        carries authoritative totals — it must win over per-message sums
        even when assistant records are also present."""
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text("\n".join([
            # Per-msg records with clearly wrong (low) numbers that must be ignored
            json.dumps({"type": "assistant", "message": {
                "id": "msg_1", "model": "claude-sonnet-4-6",
                "usage": {"input_tokens": 1, "output_tokens": 1,
                          "cache_creation_input_tokens": 1, "cache_read_input_tokens": 1},
            }}),
            json.dumps({"type": "assistant", "message": {
                "id": "msg_2", "model": "claude-sonnet-4-6",
                "usage": {"input_tokens": 1, "output_tokens": 1,
                          "cache_creation_input_tokens": 1, "cache_read_input_tokens": 1},
            }}),
            # Authoritative result record
            json.dumps({"type": "result", "usage": {
                "input_tokens": 18, "output_tokens": 11632,
                "cache_creation_input_tokens": 55762, "cache_read_input_tokens": 639513,
            }, "total_cost_usd": 0.7127}),
        ]) + "\n")

        stats = extract_transcript_stats(str(transcript))
        assert stats["input_tokens"] == 18
        assert stats["output_tokens"] == 11632
        assert stats["cache_creation_input_tokens"] == 55762
        assert stats["cache_read_input_tokens"] == 639513
        assert stats["total_cost_usd"] == 0.7127
        assert stats["models"] == ["claude-sonnet-4-6"]

    def test_dedupe_by_message_id_when_no_result_record(self, tmp_path):
        """Persisted transcripts have no `result` record and emit each
        assistant message once per content block — all copies carry the
        same final usage snapshot. Summing naively double-counts; dedupe
        by message.id first."""
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text("\n".join([
            # msg_1 emitted 3 times (text + tool_use + final) — same numbers each copy
            json.dumps({"type": "assistant", "message": {
                "id": "msg_1", "model": "claude-opus-4-6",
                "usage": {"input_tokens": 100, "output_tokens": 50,
                          "cache_creation_input_tokens": 20, "cache_read_input_tokens": 10},
            }}),
            json.dumps({"type": "assistant", "message": {
                "id": "msg_1", "model": "claude-opus-4-6",
                "usage": {"input_tokens": 100, "output_tokens": 50,
                          "cache_creation_input_tokens": 20, "cache_read_input_tokens": 10},
            }}),
            json.dumps({"type": "assistant", "message": {
                "id": "msg_1", "model": "claude-opus-4-6",
                "usage": {"input_tokens": 100, "output_tokens": 50,
                          "cache_creation_input_tokens": 20, "cache_read_input_tokens": 10},
            }}),
            # msg_2 emitted once
            json.dumps({"type": "assistant", "message": {
                "id": "msg_2", "model": "claude-opus-4-6",
                "usage": {"input_tokens": 200, "output_tokens": 80,
                          "cache_creation_input_tokens": 0, "cache_read_input_tokens": 30},
            }}),
        ]) + "\n")

        stats = extract_transcript_stats(str(transcript))
        assert stats["input_tokens"] == 300  # 100 + 200, not 3×100 + 200
        assert stats["output_tokens"] == 130
        assert stats["cache_creation_input_tokens"] == 20
        assert stats["cache_read_input_tokens"] == 40
        assert stats["total_cost_usd"] is None
        assert stats["models"] == ["claude-opus-4-6"]

    def test_multiple_models_sorted(self, tmp_path):
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text("\n".join([
            json.dumps({"type": "assistant", "message": {
                "id": "m1", "model": "claude-sonnet-4-6", "usage": {},
            }}),
            json.dumps({"type": "assistant", "message": {
                "id": "m2", "model": "claude-haiku-4-5-20251001", "usage": {},
            }}),
            json.dumps({"type": "assistant", "message": {
                "id": "m3", "model": "claude-sonnet-4-6", "usage": {},
            }}),
        ]) + "\n")
        stats = extract_transcript_stats(str(transcript))
        assert stats["models"] == ["claude-haiku-4-5-20251001", "claude-sonnet-4-6"]

    def test_missing_file_returns_empty_stats(self):
        assert extract_transcript_stats("/nonexistent/path.jsonl") == self.EMPTY

    def test_ignores_non_assistant_records(self, tmp_path):
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text(
            json.dumps({"type": "human", "message": {
                "id": "x", "model": "ignored",
                "usage": {"input_tokens": 999, "output_tokens": 999,
                          "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
            }}) + "\n"
        )
        stats = extract_transcript_stats(str(transcript))
        assert stats == self.EMPTY

    def test_skips_malformed_lines(self, tmp_path):
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text(
            "not json\n"
            + json.dumps({"type": "assistant", "message": {
                "id": "m1", "model": "claude-opus-4-6",
                "usage": {"input_tokens": 5, "output_tokens": 3,
                          "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
            }}) + "\n"
        )
        stats = extract_transcript_stats(str(transcript))
        assert stats["input_tokens"] == 5
        assert stats["output_tokens"] == 3
        assert stats["models"] == ["claude-opus-4-6"]

    def test_assistant_without_id_skipped_in_sum_path(self, tmp_path):
        """Records without message.id can't be deduped safely — skip them
        in the sum path. (They shouldn't occur in real transcripts.)"""
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text(
            json.dumps({"type": "assistant", "message": {
                "model": "claude-opus-4-6",
                "usage": {"input_tokens": 999, "output_tokens": 999,
                          "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
            }}) + "\n"
        )
        stats = extract_transcript_stats(str(transcript))
        assert stats["input_tokens"] == 0
        assert stats["models"] == ["claude-opus-4-6"]  # model is still collected

    def test_result_record_without_cost(self, tmp_path):
        """Result record may appear without total_cost_usd — cost stays None."""
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text(
            json.dumps({"type": "result", "usage": {
                "input_tokens": 10, "output_tokens": 20,
                "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
            }}) + "\n"
        )
        stats = extract_transcript_stats(str(transcript))
        assert stats["output_tokens"] == 20
        assert stats["total_cost_usd"] is None


class TestInvestigationSummaryMain:
    """main() now takes a payload dict. session_id anchors run resolution."""

    def _make_run(self, tmp_path, run_name="run-001", meta=True):
        run_dir = tmp_path / run_name
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
        (run_dir / "state.json").write_text(json.dumps({"run_id": run_name}))
        if meta:
            (run_dir / "meta.json").write_text(json.dumps({
                "run_id": run_name,
                "signature_id": "wazuh-rule-5710",
                "salt": "deadbeef01234567",
                "created_at": "2026-04-14T10:00:00+00:00",
            }))
        return run_dir

    def _invoke_main(self, tmp_path, payload_dict):
        from hooks.scripts.investigation_summary import main

        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            main(payload_dict)

    def test_writes_summary_entry(self, tmp_path):
        self._make_run(tmp_path)
        self._invoke_main(tmp_path, {"session_id": "sess-writes"})

        audit_file = tmp_path / "audit.jsonl"
        assert audit_file.exists()
        entry = json.loads(audit_file.read_text().strip())
        assert entry["run_id"] == "run-001"
        assert entry["ticket_id"] == "SEC-042"
        assert entry["status"] == "resolved"
        assert entry["leads_pursued"] == 4
        assert entry["matched_archetype"] == "monitoring-probe"
        assert entry["matched_ticket_id"] == "SEC-2024-001"

    def test_includes_timestamps(self, tmp_path):
        self._make_run(tmp_path)
        self._invoke_main(tmp_path, {"session_id": "sess-ts"})

        entry = json.loads((tmp_path / "audit.jsonl").read_text().strip())
        assert entry["start_timestamp"] == "2026-04-14T10:00:00+00:00"
        assert "end_timestamp" in entry
        assert "timestamp" not in entry

    def test_no_entry_without_session_id(self, tmp_path):
        """Without a session_id in the payload, there's nothing to resolve."""
        self._make_run(tmp_path)
        self._invoke_main(tmp_path, {})
        assert not (tmp_path / "audit.jsonl").exists()

    def test_stats_from_stream_json_result_record(self, tmp_path):
        """Eval-style transcript: authoritative `type: result` record,
        total_cost_usd captured."""
        self._make_run(tmp_path)
        transcript = tmp_path / "session.jsonl"
        transcript.write_text("\n".join([
            json.dumps({"type": "assistant", "message": {
                "id": "msg_1", "model": "claude-sonnet-4-6",
                "usage": {"input_tokens": 1, "output_tokens": 1,
                          "cache_creation_input_tokens": 1, "cache_read_input_tokens": 1},
            }}),
            json.dumps({"type": "result", "usage": {
                "input_tokens": 500, "output_tokens": 11632,
                "cache_creation_input_tokens": 100, "cache_read_input_tokens": 50,
            }, "total_cost_usd": 0.4321}),
        ]) + "\n")

        self._invoke_main(
            tmp_path,
            {"session_id": "sess-stream", "transcript_path": str(transcript)},
        )

        entry = json.loads((tmp_path / "audit.jsonl").read_text().strip())
        assert entry["input_tokens"] == 500
        assert entry["output_tokens"] == 11632
        assert entry["cache_creation_input_tokens"] == 100
        assert entry["cache_read_input_tokens"] == 50
        assert entry["total_cost_usd"] == 0.4321
        assert entry["models"] == ["claude-sonnet-4-6"]

    def test_stats_from_persisted_transcript_dedupe(self, tmp_path):
        """Persisted-session transcript: no `result` record, duplicate
        message.id entries must be deduped."""
        self._make_run(tmp_path)
        transcript = tmp_path / "session.jsonl"
        def m(mid, inp, out):
            return json.dumps({"type": "assistant", "message": {
                "id": mid, "model": "claude-opus-4-6",
                "usage": {"input_tokens": inp, "output_tokens": out,
                          "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
            }})
        transcript.write_text("\n".join([
            m("msg_1", 500, 200),
            m("msg_1", 500, 200),
            m("msg_2", 100, 50),
        ]) + "\n")

        self._invoke_main(
            tmp_path,
            {"session_id": "sess-dedupe", "transcript_path": str(transcript)},
        )

        entry = json.loads((tmp_path / "audit.jsonl").read_text().strip())
        assert entry["input_tokens"] == 600
        assert entry["output_tokens"] == 250
        assert entry["total_cost_usd"] is None
        assert entry["models"] == ["claude-opus-4-6"]

    def test_env_var_transcript_path_takes_precedence(self, tmp_path):
        """SOC_AGENT_TRANSCRIPT_PATH overrides the payload's transcript_path
        so eval_run.sh can point at the tee'd full transcript under
        --no-session-persistence (where the payload path is a 1-line stub)."""
        self._make_run(tmp_path)

        stub = tmp_path / "stub.jsonl"
        stub.write_text(
            json.dumps({"type": "ai-title", "aiTitle": "x"}) + "\n"
        )
        full = tmp_path / "full.jsonl"
        full.write_text(
            json.dumps({"type": "result", "usage": {
                "input_tokens": 777, "output_tokens": 42,
                "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
            }, "total_cost_usd": 0.123}) + "\n"
            + json.dumps({"type": "assistant", "message": {
                "id": "m", "model": "claude-sonnet-4-6", "usage": {},
            }}) + "\n"
        )

        from hooks.scripts.investigation_summary import main

        with patch.dict("os.environ", {
            "SOC_AGENT_RUNS_DIR": str(tmp_path),
            "SOC_AGENT_TRANSCRIPT_PATH": str(full),
        }):
            main({"session_id": "sess-env", "transcript_path": str(stub)})

        entry = json.loads((tmp_path / "audit.jsonl").read_text().strip())
        assert entry["input_tokens"] == 777
        assert entry["output_tokens"] == 42
        assert entry["total_cost_usd"] == 0.123
        assert entry["models"] == ["claude-sonnet-4-6"]

    def test_stats_empty_without_transcript(self, tmp_path):
        self._make_run(tmp_path)
        self._invoke_main(tmp_path, {"session_id": "sess-empty"})

        entry = json.loads((tmp_path / "audit.jsonl").read_text().strip())
        assert entry["input_tokens"] == 0
        assert entry["output_tokens"] == 0
        assert entry["cache_creation_input_tokens"] == 0
        assert entry["cache_read_input_tokens"] == 0
        assert entry["models"] == []
        assert entry["total_cost_usd"] is None


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
