"""Tests for save_raw_tool_output.py — PostToolUse hook that saves
raw tool output to disk for allowlist-matched tools.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

import hooks.scripts.save_raw_tool_output as srto
from hooks.scripts.save_raw_tool_output import (
    build_command_summary,
    context_annotation,
    derive_loop_n,
    extract_body,
    load_allowlist,
    make_nonce,
    match_entry,
    save_payload,
    write_manifest_entry,
)


HOOK_PATH = SOC_AGENT_ROOT / "hooks" / "scripts" / "save_raw_tool_output.py"


# ---------------------------------------------------------------------------
# Allowlist + matching
# ---------------------------------------------------------------------------


class TestLoadAllowlist:
    def test_real_allowlist_parses(self):
        entries = load_allowlist()
        assert isinstance(entries, list)
        assert any(e.get("schema") == "wazuh_cli" for e in entries)
        assert any(e.get("schema") == "host_query" for e in entries)
        assert any(e.get("schema") == "ticket_cli" for e in entries)


class TestMatchEntry:
    def _allowlist(self):
        return load_allowlist()

    def test_matches_wazuh_cli_bash_command(self):
        entry = match_entry(
            "Bash",
            {"command": "python scripts/tools/wazuh_cli.py query --query foo"},
            self._allowlist(),
        )
        assert entry is not None
        assert entry["schema"] == "wazuh_cli"
        assert entry["ext"] == "jsonl"

    def test_matches_host_query(self):
        entry = match_entry(
            "Bash",
            {"command": "scripts/tools/host_query.py process-list --target endpoint"},
            self._allowlist(),
        )
        assert entry is not None
        assert entry["schema"] == "host_query"

    def test_matches_ticket_cli_variant(self):
        entry = match_entry(
            "Bash",
            {"command": "playground_ticket_cli.py close --ticket-id T1"},
            self._allowlist(),
        )
        assert entry is not None
        assert entry["schema"] == "ticket_cli"

    def test_does_not_match_ls(self):
        assert match_entry("Bash", {"command": "ls -la"}, self._allowlist()) is None

    def test_does_not_match_unrelated_python(self):
        assert (
            match_entry(
                "Bash",
                {"command": "python -c 'print(1)'"},
                self._allowlist(),
            )
            is None
        )

    def test_mcp_does_not_match_when_no_mcp_entries(self):
        # Real allowlist has no MCP entries currently
        assert match_entry("mcp__siem__query", {}, self._allowlist()) is None

    def test_mcp_matches_when_pattern_present(self):
        custom = [{"kind": "mcp", "pattern": "mcp__siem__*", "schema": "siem_mcp", "ext": "json"}]
        entry = match_entry("mcp__siem__query", {}, custom)
        assert entry is not None
        assert entry["schema"] == "siem_mcp"

    def test_other_tool_names_do_not_match(self):
        assert match_entry("Read", {"command": "wazuh_cli.py"}, self._allowlist()) is None
        assert match_entry("Write", {}, self._allowlist()) is None


# ---------------------------------------------------------------------------
# Loop derivation
# ---------------------------------------------------------------------------


class TestDeriveLoopN:
    def test_missing_state_returns_zero(self, tmp_path):
        assert derive_loop_n(tmp_path) == 0

    def test_corrupt_state_returns_zero(self, tmp_path):
        (tmp_path / "state.json").write_text("{not json")
        assert derive_loop_n(tmp_path) == 0

    def test_counts_gather_phases(self, tmp_path):
        state = {
            "phase": "ANALYZE",
            "history": ["CONTEXTUALIZE", "PREDICT", "GATHER", "ANALYZE", "PREDICT", "GATHER"],
        }
        (tmp_path / "state.json").write_text(json.dumps(state))
        assert derive_loop_n(tmp_path) == 2

    def test_zero_when_no_gather_yet(self, tmp_path):
        (tmp_path / "state.json").write_text(json.dumps({"history": ["CONTEXTUALIZE"]}))
        assert derive_loop_n(tmp_path) == 0

    def test_handles_non_list_history(self, tmp_path):
        (tmp_path / "state.json").write_text(json.dumps({"history": "not a list"}))
        assert derive_loop_n(tmp_path) == 0


# ---------------------------------------------------------------------------
# Body extraction
# ---------------------------------------------------------------------------


class TestExtractBody:
    def test_bash_reads_stdout(self):
        body = extract_body("Bash", {"stdout": "hello\nworld\n", "stderr": "warn"})
        assert body == "hello\nworld\n"

    def test_bash_missing_stdout_empty(self):
        assert extract_body("Bash", {"stderr": "only err"}) == ""

    def test_bash_non_dict_response_stringifies(self):
        assert extract_body("Bash", "raw text") == "raw text"

    def test_mcp_serializes_dict(self):
        body = extract_body("mcp__siem__query", {"a": 1, "b": [2, 3]})
        parsed = json.loads(body)
        assert parsed == {"a": 1, "b": [2, 3]}

    def test_mcp_serializes_list(self):
        body = extract_body("mcp__siem__query", [{"id": 1}])
        assert json.loads(body) == [{"id": 1}]


# ---------------------------------------------------------------------------
# Nonce + save
# ---------------------------------------------------------------------------


class TestMakeNonce:
    def test_length_is_four(self):
        for _ in range(20):
            assert len(make_nonce()) == 4

    def test_charset_is_base36(self):
        for _ in range(20):
            for c in make_nonce():
                assert c in "0123456789abcdefghijklmnopqrstuvwxyz"


class TestSavePayload:
    def test_writes_file_with_expected_path(self, tmp_path):
        path = save_payload(tmp_path, loop_n=1, ext="jsonl", body="hello")
        assert path.exists()
        assert path.read_text() == "hello"
        assert path.parent == tmp_path / "raw_query_outputs"
        assert path.name.startswith("1-")
        assert path.suffix == ".jsonl"

    def test_creates_directory_if_missing(self, tmp_path):
        sub = tmp_path / "fresh-run"
        sub.mkdir()
        path = save_payload(sub, loop_n=0, ext="json", body="{}")
        assert path.parent == sub / "raw_query_outputs"
        assert path.parent.exists()

    def test_collision_retry(self, tmp_path, monkeypatch):
        # Force make_nonce to return the same value 3 times then a unique one.
        sequence = iter(["aaaa", "aaaa", "aaaa", "bbbb"])
        monkeypatch.setattr(srto, "make_nonce", lambda: next(sequence))
        first = save_payload(tmp_path, 1, "txt", "first")
        second = save_payload(tmp_path, 1, "txt", "second")
        assert first.name == "1-aaaa.txt"
        assert second.name == "1-bbbb.txt"
        assert first.read_text() == "first"
        assert second.read_text() == "second"

    def test_exhausted_retries_falls_through(self, tmp_path, monkeypatch):
        monkeypatch.setattr(srto, "make_nonce", lambda: "xxxx")
        save_payload(tmp_path, 0, "txt", "first")
        # Exhaust retries; should still write a file (token_hex suffix)
        second = save_payload(tmp_path, 0, "txt", "second")
        assert second.exists()
        assert second.read_text() == "second"
        assert second != tmp_path / "raw_query_outputs" / "0-xxxx.txt"


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class TestWriteManifestEntry:
    def test_appends_jsonl_line(self, tmp_path):
        write_manifest_entry(tmp_path, {"a": 1})
        write_manifest_entry(tmp_path, {"b": 2})
        manifest = tmp_path / "raw_query_outputs" / "manifest.jsonl"
        lines = manifest.read_text().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"a": 1}
        assert json.loads(lines[1]) == {"b": 2}


class TestBuildCommandSummary:
    def test_truncates_long_bash_command(self):
        cmd = "x" * 1000
        result = build_command_summary("Bash", {"command": cmd})
        assert len(result) <= 200

    def test_uses_tool_name_for_mcp(self):
        result = build_command_summary("mcp__siem__query", {})
        assert result == "mcp__siem__query"


class TestContextAnnotation:
    def test_returns_post_tool_use_envelope(self, tmp_path):
        path = tmp_path / "raw_query_outputs" / "1-abcd.json"
        out = context_annotation(path)
        assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert str(path) in ctx
        assert "raw-saved" in ctx


# ---------------------------------------------------------------------------
# End-to-end via subprocess (real hook script)
# ---------------------------------------------------------------------------


def _make_run_dir(runs_dir: Path, session_id: str) -> Path:
    run_dir = runs_dir / "run-test"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "meta.json").write_text(json.dumps({"signature_id": "test-sig"}))
    (run_dir / "state.json").write_text(json.dumps({"history": ["GATHER"]}))
    sessions = runs_dir / ".sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    (sessions / f"{session_id}.json").write_text(
        json.dumps({"run_dir": str(run_dir), "signature_id": "test-sig"})
    )
    return run_dir


def _run_hook(payload: dict, runs_dir: Path) -> tuple[int, str, str]:
    env = {
        "SOC_AGENT_RUNS_DIR": str(runs_dir),
        "PATH": "/usr/bin:/bin",
    }
    proc = subprocess.run(
        [sys.executable, str(HOOK_PATH)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestEndToEnd:
    def test_matched_bash_writes_file_and_manifest(self, tmp_path):
        runs_dir = tmp_path / "runs"
        run_dir = _make_run_dir(runs_dir, "sess-1")
        payload = {
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_use_id": "tu-1",
            "agent_id": "ag-1",
            "agent_type": "soc-agent:gather",
            "tool_input": {"command": "wazuh_cli.py query --query 'foo'"},
            "tool_response": {"stdout": '{"events":[1,2,3]}', "stderr": ""},
        }
        rc, stdout, stderr = _run_hook(payload, runs_dir)
        assert rc == 0, stderr

        # additionalContext returned
        out = json.loads(stdout)
        assert "additionalContext" in out["hookSpecificOutput"]

        # File written
        out_dir = run_dir / "raw_query_outputs"
        files = [p for p in out_dir.iterdir() if p.suffix == ".jsonl" and p.name != "manifest.jsonl"]
        assert len(files) == 1
        assert files[0].read_text() == '{"events":[1,2,3]}'

        # Manifest written
        manifest = out_dir / "manifest.jsonl"
        lines = manifest.read_text().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["agent_id"] == "ag-1"
        assert entry["agent_type"] == "soc-agent:gather"
        assert entry["tool_use_id"] == "tu-1"
        assert entry["schema"] == "wazuh_cli"
        assert entry["loop_n"] == 1
        assert entry["bytes"] == len('{"events":[1,2,3]}')
        assert entry["path"] == str(files[0])

    def test_unmatched_bash_writes_nothing(self, tmp_path):
        runs_dir = tmp_path / "runs"
        run_dir = _make_run_dir(runs_dir, "sess-2")
        payload = {
            "session_id": "sess-2",
            "tool_name": "Bash",
            "tool_use_id": "tu-2",
            "tool_input": {"command": "ls -la"},
            "tool_response": {"stdout": "out", "stderr": ""},
        }
        rc, stdout, stderr = _run_hook(payload, runs_dir)
        assert rc == 0, stderr
        assert stdout.strip() == ""
        out_dir = run_dir / "raw_query_outputs"
        assert not out_dir.exists()

    def test_empty_stdout_skips_save(self, tmp_path):
        runs_dir = tmp_path / "runs"
        run_dir = _make_run_dir(runs_dir, "sess-3")
        payload = {
            "session_id": "sess-3",
            "tool_name": "Bash",
            "tool_input": {"command": "wazuh_cli.py"},
            "tool_response": {"stdout": "", "stderr": ""},
        }
        rc, stdout, _ = _run_hook(payload, runs_dir)
        assert rc == 0
        assert stdout.strip() == ""
        assert not (run_dir / "raw_query_outputs").exists()

    def test_no_run_dir_silently_exits(self, tmp_path):
        runs_dir = tmp_path / "runs-empty"
        runs_dir.mkdir()
        payload = {
            "session_id": "no-such-session",
            "tool_name": "Bash",
            "tool_input": {"command": "wazuh_cli.py"},
            "tool_response": {"stdout": "data", "stderr": ""},
        }
        rc, stdout, stderr = _run_hook(payload, runs_dir)
        assert rc == 0, stderr
        assert stdout.strip() == ""

    def test_two_runs_append_to_manifest(self, tmp_path):
        runs_dir = tmp_path / "runs"
        run_dir = _make_run_dir(runs_dir, "sess-4")
        for i in range(2):
            payload = {
                "session_id": "sess-4",
                "tool_name": "Bash",
                "tool_use_id": f"tu-{i}",
                "tool_input": {"command": "wazuh_cli.py"},
                "tool_response": {"stdout": f"body-{i}", "stderr": ""},
            }
            rc, _, _ = _run_hook(payload, runs_dir)
            assert rc == 0
        manifest = run_dir / "raw_query_outputs" / "manifest.jsonl"
        assert len(manifest.read_text().splitlines()) == 2
