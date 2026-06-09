"""Tests for defender/hooks/block_unwrapped_adapter_calls.py.

The hook denies (exit 2) a data-source adapter call inside the gather subagent
unless it is wrapped in `defender-record-query`, so every query lands in the
queries table. The main loop is out of its scope (owned by
block_main_loop_raw_access.py).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "block_unwrapped_adapter_calls.py"


def _load(monkeypatch):
    spec = importlib.util.spec_from_file_location("block_unwrapped_adapter_calls", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    # Deterministic adapter roster (don't depend on the real bin/ dir contents).
    # The hook reads `adapter_shims` from its `_cmd_segments` import; patch that.
    import _cmd_segments  # type: ignore[import-not-found]
    monkeypatch.setattr(_cmd_segments, "all_defender_shims", lambda: {
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


def _run(mod, monkeypatch, command: str, *, subagent: bool) -> int:
    payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    if subagent:
        payload["agent_id"] = "sub-abc123"
        payload["agent_type"] = "general-purpose"
    monkeypatch.setattr(sys, "stdin", _StringIn(json.dumps(payload)))
    return mod.main()


WRAPPED = (
    "defender-record-query --run-dir /r --lead l-1 --system elastic "
    "--query-id elastic.q -- defender-elastic query foo --raw"
)


# --- subagent: unwrapped adapter calls are denied -------------------------

@pytest.mark.parametrize("command", [
    "defender-elastic query foo --raw",
    "bash -c 'defender-cmdb host-lookup web-1'",
    "timeout 5 bash -c 'defender-elastic query foo --raw'",
    "defender-elastic query foo | jq .",
    "defender-record-query ... ; defender-elastic query bar",   # second seg unwrapped
    "python3 /x/defender/scripts/tools/elastic_cli.py query foo",  # raw _cli.py path
])
def test_denies_unwrapped_adapter_in_subagent(monkeypatch, capsys, command):
    mod = _load(monkeypatch)
    assert _run(mod, monkeypatch, command, subagent=True) == 2
    assert "capture wrapper" in capsys.readouterr().err


# --- subagent: wrapped / non-adapter shapes are allowed -------------------

@pytest.mark.parametrize("command", [
    WRAPPED,
    f"{WRAPPED} | jq .",
    "tail -1 /r/executed_queries.jsonl | jq .",
    "cat /r/gather_raw/l-1/0.json | jq '.hits | length'",
    "defender-data-source-debug --payload /r/gather_raw/l-1/0.json --question q",
    "defender-invlang enum types",
])
def test_allows_wrapped_and_nonadapter_in_subagent(monkeypatch, capsys, command):
    mod = _load(monkeypatch)
    assert _run(mod, monkeypatch, command, subagent=True) == 0
    assert capsys.readouterr().err == ""


# --- main loop is out of scope (block_main_loop_raw_access.py owns it) -----

def test_main_loop_unwrapped_adapter_passes_through(monkeypatch, capsys):
    mod = _load(monkeypatch)
    assert _run(mod, monkeypatch, "defender-elastic query foo --raw", subagent=False) == 0
    assert capsys.readouterr().err == ""


# --- non-Bash / malformed input is ignored --------------------------------

def test_non_bash_ignored(monkeypatch):
    mod = _load(monkeypatch)
    payload = {"tool_name": "Read", "tool_input": {"file_path": "/r/x"}, "agent_id": "s1"}
    monkeypatch.setattr(sys, "stdin", _StringIn(json.dumps(payload)))
    assert mod.main() == 0


def test_malformed_stdin_ignored(monkeypatch):
    mod = _load(monkeypatch)
    monkeypatch.setattr(sys, "stdin", _StringIn("not json"))
    assert mod.main() == 0


def test_empty_command_ignored(monkeypatch):
    mod = _load(monkeypatch)
    assert _run(mod, monkeypatch, "   ", subagent=True) == 0
