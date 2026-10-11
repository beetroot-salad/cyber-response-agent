"""Circuit-breaker exit-code taxonomy + the usage-error structured signal.

The breaker counts only genuine infra failures (exit 2 / 124). A usage error —
the agent passing a bad flag / unknown subcommand — must NOT count: exit 64 is
reserved for it, keeping the agent's CLI typos out of the connectivity bucket.
This replaces the old, fragile stderr-phrase heuristic (#301). No adapter has a
CLI any more (#1107 deleted the last one), so nothing mints 64 itself.
"""
from __future__ import annotations

import pytest

from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters import ticket_adapter
from defender.runtime import circuit_breaker as cb


def test_usage_exit_code_is_reserved():
    assert transport.USAGE_EXIT_CODE == 64


@pytest.mark.parametrize(("exit_code", "counts"), [
    (0, False),
    (1, False),
    (2, True),
    (64, False),
    (124, True),
])
def test_is_infra_failure_keys_on_exit_code_only(exit_code, counts):
    assert cb.is_infra_failure(exit_code) is counts


def test_argparse_heuristic_is_gone():
    assert not hasattr(cb, "_ARGPARSE_USAGE_RE")


def test_no_adapter_has_a_cli_left_to_mistype():
    """The ticket adapter's CLI is gone (#1107): there is no argv an agent can mistype, so no
    adapter exits 64 and the parser class that minted it no longer exists."""
    for name in ("build_parser", "main", "_cli_context"):  # lint-stale-ref: ok — asserts these are gone
        assert not hasattr(ticket_adapter, name), f"ticket_adapter still has `{name}`"
    assert not hasattr(transport, "AdapterArgumentParser")
    assert not cb.is_infra_failure(transport.USAGE_EXIT_CODE)


def test_usage_error_does_not_trip_breaker(tmp_path):
    """Exit 64 is the agent's own usage error: it charges nothing. #1235: the breaker is
    the run process's memory, so "charged nothing" is read off `breaker_state`, not off
    the absence of a file. Positive control: test_two_infra_failures_trip_breaker, where
    the same read DOES show the system's failures."""
    from defender.runtime.circuit_breaker import breaker_state

    cb.record_outcome(tmp_path, "elastic", 64)
    cb.record_outcome(tmp_path, "elastic", 64)
    assert not cb.is_tripped(tmp_path, "elastic")
    state = breaker_state(tmp_path)
    assert "elastic" not in state["systems"], f"a usage error charged the breaker: {state}"
    assert state["total_failures"] == 0, state


def test_two_infra_failures_trip_breaker(tmp_path):
    from defender.runtime.circuit_breaker import breaker_state

    cb.record_outcome(tmp_path, "elastic", 2)
    cb.record_outcome(tmp_path, "elastic", 2)
    assert cb.is_tripped(tmp_path, "elastic")
    state = breaker_state(tmp_path)
    assert state["systems"]["elastic"]["failures"] == 2, state
    assert "tripped_at" in state["systems"]["elastic"], state
    assert state["total_failures"] == 2, state


def test_open_breaker_starts_the_run_with_a_blank_breaker(tmp_path):
    """`open_breaker` is the run's start (#1235, called beside `open_budget`): whatever this
    process held for the folder, the run begins with no system down.

    Positive control: before the open, the system WAS tripped, so the healthy read after it
    is a reset rather than a breaker that never counted."""
    from defender.runtime.circuit_breaker import breaker_state, open_breaker

    cb.record_outcome(tmp_path, "elastic", 2)
    cb.record_outcome(tmp_path, "elastic", 2)
    assert cb.is_tripped(tmp_path, "elastic"), "the control never tripped"

    open_breaker(tmp_path)
    assert not cb.is_tripped(tmp_path, "elastic"), "a new run inherited a tripped system"
    assert breaker_state(tmp_path) == {"systems": {}, "total_failures": 0}


def test_a_breaker_file_in_the_run_folder_is_not_the_breaker(tmp_path):
    """#1235 D3: the breaker lives in the run's process, and no file in the run folder moves
    it. Two real infra failures trip `elastic` and write nothing; a `circuit_breaker.json`
    planted over that run claiming a blank breaker leaves `elastic` down; one claiming a
    healthy `cmdb` tripped does not put `cmdb` down; and unreadable bytes at that name are
    no longer "tripped" (the unreadable-state branch retired with the file).

    Positive control on the same folder: `elastic`, tripped by the host's own record, IS
    down, with the down message the host has always given."""
    from defender.runtime.circuit_breaker import breaker_state

    run_dir = tmp_path / "runs" / "run-1235"
    run_dir.mkdir(parents=True)
    cb.record_outcome(run_dir, "elastic", 2)
    cb.record_outcome(run_dir, "elastic", 2)
    on_disk = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")
                     if not p.is_dir())
    assert on_disk == [], f"the breaker wrote files: {on_disk}"

    planted = run_dir / "circuit_breaker.json"
    planted.write_text('{"systems": {}, "total_failures": 0}', encoding="utf-8")
    assert cb.is_tripped(run_dir, "elastic"), "a planted blank breaker revived a down system"
    assert "is DOWN for this run" in cb.down_message(run_dir, "elastic")

    planted.write_text('{"systems": {"cmdb": {"failures": 5, "tripped_at": '
                       '"2026-01-01T00:00:00+00:00"}}, "total_failures": 5}', encoding="utf-8")
    assert not cb.is_tripped(run_dir, "cmdb"), "a planted file put a healthy system down"

    planted.write_bytes(b"\xff\xfe not json")
    assert not cb.is_tripped(run_dir, "cmdb"), \
        "unreadable bytes at the old state name still read as tripped"
    assert cb.is_tripped(run_dir, "elastic"), "the host's own trip was lost"
    state = breaker_state(run_dir)
    assert state["systems"]["elastic"]["failures"] == 2, state
    assert "cmdb" not in state["systems"], state
