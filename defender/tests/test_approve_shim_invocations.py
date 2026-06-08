"""Tests for defender/hooks/approve_shim_invocations.py.

The hook auto-approves Bash commands composed entirely of `defender-*` shims
and a small read-only utility set — including `bash -c '<shim>'` and read-only
pipes the static allowlist can't express — while never approving anything the
main-loop clamp (block_main_loop_raw_access.py) would deny.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "approve_shim_invocations.py"
MAIN_CWD = "/workspace/defender-v2-tree"
SUBAGENT_CWD = "/tmp/cc-worktree-abc123"


def _load(monkeypatch):
    spec = importlib.util.spec_from_file_location("approve_shim_invocations", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "REPO_ROOT", Path(MAIN_CWD))
    # Deterministic shim roster (don't depend on the real bin/ dir contents).
    monkeypatch.setattr(mod, "_all_defender_shims", lambda: {
        "defender-invlang", "defender-record-query", "defender-data-source-debug",
        "defender-elastic", "defender-cmdb", "defender-identity", "defender-host-state",
        "defender-threat-intel", "defender-change-mgmt", "defender-ticket",
    })
    return mod


class _StringIn:
    def __init__(self, s: str):
        self._s = s

    def read(self) -> str:
        return self._s


def _decide(mod, monkeypatch, capsys, command: str, cwd: str | None) -> str:
    payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    if cwd is not None:
        payload["cwd"] = cwd
    monkeypatch.setattr(sys, "stdin", _StringIn(json.dumps(payload)))
    rc = mod.main()
    assert rc == 0
    out = capsys.readouterr().out.strip()
    if not out:
        return "PASSTHROUGH"
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"]


# --- subagent context: safe shim / read-only shapes get approved ----------

@pytest.mark.parametrize("command", [
    "defender-elastic query 'x' --raw",
    "bash -c 'defender-invlang enum types'",
    "timeout 5 bash -c 'defender-elastic query foo --raw'",
    "defender-record-query --run-dir /r --lead l-1 --system elastic --query-id elastic.q -- defender-elastic query foo --raw",
    "tail -1 /r/executed_queries.jsonl | jq .",
    "cat /r/gather_raw/0/0.json | jq '.hits | length'",
])
def test_approves_safe_shapes_in_subagent(monkeypatch, capsys, command):
    mod = _load(monkeypatch)
    assert _decide(mod, monkeypatch, capsys, command, SUBAGENT_CWD) == "allow"


# --- main session: never approve what the clamp would deny ----------------

def test_main_adapter_shim_passes_through(monkeypatch, capsys):
    """Adapter shim in the main loop must reach block_main_loop_raw_access, not
    be approved here."""
    mod = _load(monkeypatch)
    assert _decide(mod, monkeypatch, capsys, "bash -c 'defender-elastic query foo'", MAIN_CWD) == "PASSTHROUGH"


def test_main_invlang_shim_approved(monkeypatch, capsys):
    mod = _load(monkeypatch)
    assert _decide(mod, monkeypatch, capsys, "defender-invlang enum types", MAIN_CWD) == "allow"


def test_main_gather_raw_read_passes_through(monkeypatch, capsys):
    """A read-only `cat` on gather_raw is safe-by-token but the main-loop clamp
    owns that decision — don't approve it here."""
    mod = _load(monkeypatch)
    assert _decide(mod, monkeypatch, capsys, "cat /r/gather_raw/0/0.json", MAIN_CWD) == "PASSTHROUGH"


# --- unsafe shapes always pass through (no approval) -----------------------

@pytest.mark.parametrize("command", [
    "env | grep V2_ELASTIC",                       # credential groping
    "printenv ELASTICSEARCH_URL",
    "defender-elastic query foo > /tmp/out",       # redirect
    "bash -c 'defender-elastic query; rm -rf /tmp/x'",  # injection via ;
    "defender-invlang enum $(whoami)",             # command substitution
    "find /workspace -name .env",
    "python3 -c 'import os'",
])
def test_unsafe_shapes_pass_through(monkeypatch, capsys, command):
    mod = _load(monkeypatch)
    assert _decide(mod, monkeypatch, capsys, command, SUBAGENT_CWD) == "PASSTHROUGH"


def test_non_bash_ignored(monkeypatch, capsys):
    mod = _load(monkeypatch)
    payload = {"tool_name": "Read", "tool_input": {"file_path": "/r/x"}, "cwd": SUBAGENT_CWD}
    monkeypatch.setattr(sys, "stdin", _StringIn(json.dumps(payload)))
    assert mod.main() == 0
    assert capsys.readouterr().out.strip() == ""


def test_malformed_stdin_ignored(monkeypatch, capsys):
    mod = _load(monkeypatch)
    monkeypatch.setattr(sys, "stdin", _StringIn("not json"))
    assert mod.main() == 0
