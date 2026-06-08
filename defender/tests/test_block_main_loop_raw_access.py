"""Tests for defender/hooks/block_main_loop_raw_access.py.

The hook denies (exit 2) main-session Bash|Read|Grep|Glob calls that
reach into gather_raw/, while leaving gather-subagent calls (cwd != the
main REPO_ROOT) untouched.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "block_main_loop_raw_access.py"

MAIN_CWD = "/workspace/defender-v2-tree"
SUBAGENT_CWD = "/tmp/cc-worktree-abc123"


def _load(monkeypatch):
    spec = importlib.util.spec_from_file_location("block_main_loop_raw_access", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    # Pin REPO_ROOT so the cwd discriminator is deterministic regardless of
    # where the test tree actually lives.
    monkeypatch.setattr(mod, "REPO_ROOT", Path(MAIN_CWD))
    return mod


class _StringIn:
    def __init__(self, s: str):
        self._s = s

    def read(self) -> str:
        return self._s


def _run(mod, monkeypatch, payload: dict) -> int:
    monkeypatch.setattr(sys, "stdin", _StringIn(json.dumps(payload)))
    return mod.main()


# --- main-session denials ---------------------------------------------------

def test_denies_bash_cat_gather_raw_in_main(monkeypatch, capsys):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "cat /tmp/defender-runs-v2/r1/gather_raw/3/4.json"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2
    assert "gather_raw" in capsys.readouterr().err


def test_denies_bash_jq_gather_raw_in_main(monkeypatch, capsys):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "jq '.hits[]' /run/gather_raw/0/0.json"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2


def test_denies_read_gather_raw_in_main(monkeypatch):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Read",
        "tool_input": {"file_path": "/run/gather_raw/0/0.json"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2


def test_denies_grep_into_gather_raw_in_main(monkeypatch):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Grep",
        "tool_input": {"pattern": "Accepted", "path": "/run/gather_raw"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2


# --- subagent calls are never blocked --------------------------------------

def test_allows_subagent_reading_gather_raw(monkeypatch):
    """Gather subagent (cwd is a managed worktree, not REPO_ROOT) must keep
    its §3.5/§4 raw-payload access."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "python3 data_source_debug.py --payload /run/gather_raw/0/0.json"},
        "cwd": SUBAGENT_CWD,
    })
    assert rc == 0


def test_fails_open_when_cwd_missing(monkeypatch):
    """No cwd → can't confirm main session → allow (never break gather)."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Read",
        "tool_input": {"file_path": "/run/gather_raw/0/0.json"},
    })
    assert rc == 0


# --- legitimate main-session calls are untouched ---------------------------

def test_allows_main_reading_other_run_artifacts(monkeypatch):
    mod = _load(monkeypatch)
    for fp in ("/run/investigation.md", "/run/alert.json", "/run/lead_sequence.yaml"):
        rc = _run(mod, monkeypatch, {
            "tool_name": "Read",
            "tool_input": {"file_path": fp},
            "cwd": MAIN_CWD,
        })
        assert rc == 0, fp


def test_ignores_unwatched_tools(monkeypatch):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Write",
        "tool_input": {"file_path": "/run/gather_raw/x.json", "content": "x"},
        "cwd": MAIN_CWD,
    })
    assert rc == 0


def test_ignores_malformed_stdin(monkeypatch):
    mod = _load(monkeypatch)
    monkeypatch.setattr(sys, "stdin", _StringIn("not json"))
    assert mod.main() == 0


# --- adapter-CLI clamp: main loop must not query data sources directly ---

def test_denies_main_running_adapter_cli(monkeypatch, capsys):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "python3 defender/scripts/tools/elastic_cli.py query 'x' --raw"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2
    assert "must not run data-source CLIs" in capsys.readouterr().err


def test_denies_main_adapter_cli_absolute_path(monkeypatch):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "python3 /workspace/defender-v2-tree/defender/scripts/tools/identity_cli.py whoami > /run/x.json"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2


def test_allows_subagent_running_adapter_cli(monkeypatch):
    """Gather subagent (cwd != REPO_ROOT) runs the adapter CLI — never blocked."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "python3 .../scripts/tools/elastic_cli.py query 'x' --raw"},
        "cwd": SUBAGENT_CWD,
    })
    assert rc == 0


def test_allows_main_running_invlang_cli(monkeypatch):
    """The invlang enum CLI is not an adapter query CLI — stays allowed."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "python3 -m defender.skills.invlang.cli /tmp enum types"},
        "cwd": MAIN_CWD,
    })
    assert rc == 0


def test_allows_main_running_record_query(monkeypatch):
    """record_query.py is not an adapter *_cli.py; not matched (and the main
    loop never runs it anyway)."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "python3 defender/scripts/tools/record_query.py --help"},
        "cwd": MAIN_CWD,
    })
    assert rc == 0


def test_record_query_wrapped_adapter_cli_exempt_even_at_repo_root(monkeypatch):
    """Robustness net: a record_query-wrapped adapter call is gather's path
    (and is audited); never blocked, even if a subagent ran at REPO_ROOT.

    Pins the exemption literal: the clamp checks `"record_query.py" not in cmd`,
    so the rename from gather_exec.py must keep this command exempt."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": (
            "python3 defender/scripts/tools/record_query.py --run-dir /r --lead l-001 "
            "--system elastic --query-id elastic.q -- "
            "python3 defender/scripts/tools/elastic_cli.py query 'x' --raw"
        )},
        "cwd": MAIN_CWD,
    })
    assert rc == 0


# --- adapter clamp via the `defender-*` invocation shims -------------------
# The bin/ shims hide the scripts/tools/*_cli.py path behind a bare token, so
# the clamp must recognise the adapter shim names too.

def test_denies_main_running_adapter_shim(monkeypatch, capsys):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "defender-elastic query 'x' --raw"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2
    assert "must not run data-source CLIs" in capsys.readouterr().err


def test_denies_main_adapter_shim_inside_bash_c(monkeypatch):
    """The shim name is visible in the `bash -c` payload string, so the clamp
    still fires on the wrapped form."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "bash -c 'defender-host-state proc-tree web-1 --raw'"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2


def test_allows_main_running_invlang_shim(monkeypatch):
    """defender-invlang is corpus query, not an adapter — stays allowed."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "defender-invlang enum types"},
        "cwd": MAIN_CWD,
    })
    assert rc == 0


def test_allows_main_record_query_shim_wrapping_adapter_shim(monkeypatch):
    """defender-record-query is gather's audited wrapper; the wrapped
    defender-<adapter> stays exempt."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": (
            "defender-record-query --run-dir /r --lead l-001 --system elastic "
            "--query-id elastic.q -- defender-elastic query 'x' --raw"
        )},
        "cwd": MAIN_CWD,
    })
    assert rc == 0


def test_allows_subagent_running_adapter_shim(monkeypatch):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "defender-elastic query 'x' --raw"},
        "cwd": SUBAGENT_CWD,
    })
    assert rc == 0
