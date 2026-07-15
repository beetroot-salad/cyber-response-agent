"""Tests for defender/hooks/block_main_loop_raw_access.py.

The hook denies (exit 2) main-loop Bash|Read|Grep|Glob calls that reach into
gather_raw/, while leaving gather-subagent calls untouched. Main-loop vs
subagent is told apart by `agent_id` in the PreToolUse payload (present only
inside a Task subagent) — NOT cwd, since v2 runs both at the same cwd.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "block_main_loop_raw_access.py"

# v2 runs the orchestrator and gather subagents in-process at the same cwd, so
# cwd is NOT the discriminator; these constants only show that cwd is ignored.
MAIN_CWD = "/workspace/defender-v2-tree"
# A subagent payload carries `agent_id` (+ `agent_type`); spread into a payload
# to mark it as a Task subagent regardless of cwd.
SUBAGENT = {"agent_id": "sub-abc123", "agent_type": "general-purpose"}


def _load(monkeypatch):
    spec = importlib.util.spec_from_file_location("block_main_loop_raw_access", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
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


# --- subagent calls are never blocked (agent_id present) -------------------

def test_allows_subagent_reading_gather_raw(monkeypatch):
    """Gather subagent (agent_id present) keeps its §3.5/§4 raw-payload access."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "jq '.hits' /run/gather_raw/0/0.json"},
        **SUBAGENT,
    })
    assert rc == 0


def test_allows_subagent_reading_gather_raw_at_repo_root_cwd(monkeypatch):
    """The v2 regression: a gather subagent runs in-process at REPO_ROOT cwd, so
    cwd looks exactly like the main loop. agent_id must win — its legitimate
    gather_raw reads (jq/cat/Read) stay allowed, not denied as 'hook error'."""
    mod = _load(monkeypatch)
    for payload in (
        {"tool_name": "Read", "tool_input": {"file_path": "/run/gather_raw/0/0.json"}},
        {"tool_name": "Bash", "tool_input": {"command": "cat /run/gather_raw/l-003/0.json | jq ."}},
    ):
        rc = _run(mod, monkeypatch, {**payload, "cwd": MAIN_CWD, **SUBAGENT})
        assert rc == 0, payload


def test_blocks_main_loop_even_without_cwd(monkeypatch):
    """No agent_id → main loop → block, regardless of whether cwd is present."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Read",
        "tool_input": {"file_path": "/run/gather_raw/0/0.json"},
    })
    assert rc == 2


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
        "tool_input": {"command": "python3 defender/scripts/adapters/elastic_cli.py query 'x'"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2
    assert "must not run data-source CLIs" in capsys.readouterr().err


def test_denies_main_adapter_cli_absolute_path(monkeypatch):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "python3 /workspace/defender-v2-tree/defender/scripts/adapters/identity_cli.py whoami > /run/x.json"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2


def test_allows_subagent_running_adapter_cli(monkeypatch):
    """Gather subagent (agent_id present) runs the adapter CLI — never blocked."""
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "python3 .../scripts/adapters/elastic_cli.py query 'x'"},
        **SUBAGENT,
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
        "tool_input": {"command": "python3 defender/scripts/gather_tools/record_query.py --help"},
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
            "python3 defender/scripts/gather_tools/record_query.py --run-dir /r --lead l-001 "
            "--system elastic --query-id elastic.q -- "
            "python3 defender/scripts/adapters/elastic_cli.py query 'x'"
        )},
        "cwd": MAIN_CWD,
    })
    assert rc == 0


# --- adapter clamp via the `defender-*` invocation shims -------------------
# The bin/ shims hide the scripts/adapters/*_cli.py path behind a bare token, so
# the clamp must recognise the adapter shim names too.

def test_denies_main_running_adapter_shim(monkeypatch, capsys):
    # #611: the `defender-<system>` adapter shims were DELETED from defender/bin (a data source is
    # reached through the `query` tool now), so the LIVE roster carries no adapter to recognize —
    # this hook's shim-token clamp correctly fails OPEN on an empty roster, and the real main-loop
    # adapter deny moved to the permission gate (test_permission.py::test_main_loop_denies). The
    # roster-driven regex MECHANISM this test protects still holds: given a roster that DOES carry
    # an adapter shim, the clamp fires. Sourced from the shared _cmd_segments taxonomy, so the
    # mechanism is exercised the same way test_newly_onboarded_adapter_auto_gates does.
    from defender.hooks import _cmd_segments
    monkeypatch.setattr(_cmd_segments, "all_defender_shims", lambda: {
        "defender-invlang", "defender-elastic",  # a synthetic roster carrying one adapter
    })
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "defender-elastic query 'x'"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2
    assert "must not run data-source CLIs" in capsys.readouterr().err


def test_newly_onboarded_adapter_auto_gates_in_main_loop(monkeypatch, capsys):
    """A new adapter dropped in bin/ auto-gates here too — the shim roster is
    sourced from the shared _cmd_segments taxonomy, not a hardcoded list. This
    pins the PR's 'single source of truth' claim for the main-loop clamp."""
    mod = _load(monkeypatch)
    # Patch the canonical module the hook resolves (`defender.hooks._cmd_segments`).
    from defender.hooks import _cmd_segments
    monkeypatch.setattr(_cmd_segments, "all_defender_shims", lambda: {
        "defender-record-query", "defender-invlang",
        "defender-elastic", "defender-foo",  # 'foo' is the freshly onboarded adapter
    })
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "defender-foo lookup web-1"},
        "cwd": MAIN_CWD,
    })
    assert rc == 2
    assert "must not run data-source CLIs" in capsys.readouterr().err


def test_denies_main_adapter_shim_inside_bash_c(monkeypatch):
    """The shim name is visible in the `bash -c` payload string, so the clamp still fires on the
    wrapped form — mechanism unchanged. #611 deleted the real adapter shims from bin/, so the
    roster is monkeypatched to carry one (as above); the production main-loop adapter deny is the
    permission gate's."""
    from defender.hooks import _cmd_segments
    monkeypatch.setattr(_cmd_segments, "all_defender_shims", lambda: {
        "defender-invlang", "defender-host-state",
    })
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "bash -c 'defender-host-state proc-tree web-1'"},
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
            "--query-id elastic.q -- defender-elastic query 'x'"
        )},
        "cwd": MAIN_CWD,
    })
    assert rc == 0


def test_allows_subagent_running_adapter_shim(monkeypatch):
    mod = _load(monkeypatch)
    rc = _run(mod, monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "defender-elastic query 'x'"},
        **SUBAGENT,
    })
    assert rc == 0


def test_still_denies_main_loop_reading_gather_raw_directly(monkeypatch):
    """The exemption must not loosen the real clamp: a bare cat/cp/Read of a
    gather_raw payload from the main loop stays blocked."""
    mod = _load(monkeypatch)
    for cmd in (
        "cat /tmp/r/gather_raw/l-004/0.json",
        "cp /tmp/r/gather_raw/l-004/0.json /tmp/x.json",
    ):
        rc = _run(mod, monkeypatch, {
            "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": MAIN_CWD,
        })
        assert rc == 2, cmd
