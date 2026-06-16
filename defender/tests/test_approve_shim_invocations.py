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
# Main vs subagent is told apart by `agent_id`, not cwd. These constants are
# sentinels for the _decide helper: SUBAGENT_CWD marks the call as a subagent
# (adds agent_id to the payload); cwd itself is ignored by the hook.
MAIN_CWD = "/workspace/defender-v2-tree"
SUBAGENT_CWD = "/tmp/cc-worktree-abc123"


def _load(monkeypatch):
    spec = importlib.util.spec_from_file_location("approve_shim_invocations", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
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
    if cwd == SUBAGENT_CWD:  # sentinel → mark as a Task subagent (agent_id present)
        payload["agent_id"] = "sub-abc123"
        payload["agent_type"] = "general-purpose"
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


# --- find: gather-only discovery, guarded ---------------------------------

@pytest.mark.parametrize("command", [
    "find /workspace/defender/skills/gather/queries/elastic -name '*.md'",
    "find /workspace/defender/skills/gather/queries/host-state -type f -name '*.md' | head",
])
def test_find_approved_for_gather(monkeypatch, capsys, command):
    """Plain read-only find is approved in the subagent (template discovery)."""
    mod = _load(monkeypatch)
    assert _decide(mod, monkeypatch, capsys, command, SUBAGENT_CWD) == "allow"


@pytest.mark.parametrize("command", [
    "find /r -delete",                          # action flag: delete
    "find / -exec rm -rf {} +",                 # action flag: exec
    "find /r -execdir cat {} ;",                # action flag: execdir
    "find /r -fprintf /tmp/x %p",               # action flag: write
    "find /workspace -name .env",               # locating a denied-read file
    "find / -name ground_truth.yaml",           # locating ground truth
    "find /r -path '*/.ssh/*'",                 # locating ssh material
])
def test_find_dangerous_or_sensitive_passes_through(monkeypatch, capsys, command):
    """find with an action flag or naming a denied-read file is NOT approved,
    even in the subagent — it falls through to the normal flow."""
    mod = _load(monkeypatch)
    assert _decide(mod, monkeypatch, capsys, command, SUBAGENT_CWD) == "PASSTHROUGH"


# --- benign stderr redirects are tolerated; real redirects are not ---------

@pytest.mark.parametrize("command", [
    "ls -la /r/gather_raw 2>/dev/null",
    "grep -rl 'sshd' /workspace/defender/skills/gather/queries/elastic/ 2>/dev/null",
    "find /workspace/defender/skills/gather/queries/cmdb -name '*.md' 2>/dev/null | head",
    "cat /r/x.json 2>&1 | jq .",
])
def test_benign_stderr_redirect_approved(monkeypatch, capsys, command):
    """2>/dev/null and 2>&1 are noise the agent appends; they don't write a file
    or exfiltrate, so they don't block an otherwise-safe read-only command."""
    mod = _load(monkeypatch)
    assert _decide(mod, monkeypatch, capsys, command, SUBAGENT_CWD) == "allow"


@pytest.mark.parametrize("command", [
    "cat /etc/passwd > /tmp/out",       # stdout file redirect — real exfil shape
    "cat x 1> /tmp/out",                # explicit stdout redirect
    "find / -delete 2>/dev/null",       # danger flag survives the stderr strip
])
def test_real_redirect_or_danger_still_passes_through(monkeypatch, capsys, command):
    mod = _load(monkeypatch)
    assert _decide(mod, monkeypatch, capsys, command, SUBAGENT_CWD) == "PASSTHROUGH"


def test_find_passes_through_in_main(monkeypatch, capsys):
    """find is gather-only; the main loop has the workspace map and never gets it."""
    mod = _load(monkeypatch)
    assert _decide(mod, monkeypatch, capsys, "find /workspace -name SKILL.md", MAIN_CWD) == "PASSTHROUGH"


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
