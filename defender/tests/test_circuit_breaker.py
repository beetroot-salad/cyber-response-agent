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


def _state(run_dir):
    """A run's state (#1235 round 2): the breaker lives on the run's one `RunState`."""
    from defender.runtime.run_state import RunState

    return RunState(run_dir, "run-cb")


def test_usage_error_does_not_trip_breaker(tmp_path):
    """Exit 64 is the agent's own usage error: it charges nothing. #1235: the breaker is
    the run's state, so "charged nothing" is read off its `breaker_snapshot`, not off the
    absence of a file. Positive control: test_two_infra_failures_trip_breaker, where the
    same read DOES show the system's failures."""
    state = _state(tmp_path)
    cb.record_outcome(state, "elastic", 64)
    cb.record_outcome(state, "elastic", 64)
    assert not cb.is_tripped(state, "elastic")
    snapshot = state.breaker_snapshot()
    assert "elastic" not in snapshot["systems"], f"a usage error charged the breaker: {snapshot}"
    assert snapshot["total_failures"] == 0, snapshot


def test_two_infra_failures_trip_breaker(tmp_path):
    state = _state(tmp_path)
    cb.record_outcome(state, "elastic", 2)
    cb.record_outcome(state, "elastic", 2)
    assert cb.is_tripped(state, "elastic")
    snapshot = state.breaker_snapshot()
    assert snapshot["systems"]["elastic"]["failures"] == 2, snapshot
    assert "tripped_at" in snapshot["systems"]["elastic"], snapshot
    assert snapshot["total_failures"] == 2, snapshot


def test_a_new_runs_state_starts_with_a_blank_breaker(tmp_path):
    """A run's breaker starts blank (#1235: `RunState(...)` is the run's start): whatever an
    earlier run over the same folder tripped, the new run begins with no system down.

    Positive control: the earlier run's state WAS tripped, so the healthy read of the new one
    is a fresh start rather than a breaker that never counted."""
    earlier = _state(tmp_path)
    cb.record_outcome(earlier, "elastic", 2)
    cb.record_outcome(earlier, "elastic", 2)
    assert cb.is_tripped(earlier, "elastic"), "the control never tripped"

    fresh = _state(tmp_path)
    assert not cb.is_tripped(fresh, "elastic"), "a new run inherited a tripped system"
    assert fresh.breaker_snapshot() == {"systems": {}, "total_failures": 0}
    assert cb.is_tripped(earlier, "elastic"), "starting a new run's state reset the earlier one"


def test_a_breaker_file_in_the_run_folder_is_not_the_breaker(tmp_path):
    """#1235 D3: the breaker lives in the run's state, and no file in the run folder moves
    it. Two real infra failures trip `elastic` and write nothing; a `circuit_breaker.json`
    planted over that run claiming a blank breaker leaves `elastic` down; one claiming a
    healthy `cmdb` tripped does not put `cmdb` down; and unreadable bytes at that name are
    no longer "tripped" (the unreadable-state branch retired with the file).

    Positive control on the same folder: `elastic`, tripped by the host's own record, IS
    down, with the down message the host has always given."""
    run_dir = tmp_path / "runs" / "run-1235"
    run_dir.mkdir(parents=True)
    state = _state(run_dir)
    cb.record_outcome(state, "elastic", 2)
    cb.record_outcome(state, "elastic", 2)
    on_disk = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")
                     if not p.is_dir())
    assert on_disk == [], f"the breaker wrote files: {on_disk}"

    planted = run_dir / "circuit_breaker.json"
    planted.write_text('{"systems": {}, "total_failures": 0}', encoding="utf-8")
    assert cb.is_tripped(state, "elastic"), "a planted blank breaker revived a down system"
    assert "is DOWN for this run" in cb.down_message(state, "elastic")

    planted.write_text('{"systems": {"cmdb": {"failures": 5, "tripped_at": '
                       '"2026-01-01T00:00:00+00:00"}}, "total_failures": 5}', encoding="utf-8")
    assert not cb.is_tripped(state, "cmdb"), "a planted file put a healthy system down"

    planted.write_bytes(b"\xff\xfe not json")
    assert not cb.is_tripped(state, "cmdb"), \
        "unreadable bytes at the old state name still read as tripped"
    assert cb.is_tripped(state, "elastic"), "the host's own trip was lost"
    snapshot = state.breaker_snapshot()
    assert snapshot["systems"]["elastic"]["failures"] == 2, snapshot
    assert "cmdb" not in snapshot["systems"], snapshot


def test_a_breaker_tripped_by_config_faults_names_configuration(tmp_path):
    """#1246: a missing or broken config (`ConfigFault`) exits 2 like a transport failure and
    charges the same breaker — intended — so the messages it produces cannot blame
    connectivity alone; the breaker sees exit codes, not which fault raised them. The causes
    are one phrase both messages read, and MAIN's opening correlation sentence for a tripped
    system claims no cause at all."""
    from defender.runtime.lead_zero import (
        ENDING_TRIPPED_BREAKER,
        CorrelationOutcome,
        render_correlation_section,
    )
    from defender.scripts.adapters.faults import ConfigFault

    state = _state(tmp_path)
    for _ in range(cb.PER_SYSTEM_FAIL_LIMIT):
        cb.record_outcome(state, "elastic", ConfigFault.exit_code)
    assert cb.is_tripped(state, "elastic"), "config faults no longer charge the breaker"
    down = cb.down_message(state, "elastic")
    assert "configuration" in cb.INFRA_CAUSES, cb.INFRA_CAUSES
    assert cb.INFRA_CAUSES in down, f"the down message restates the causes: {down!r}"

    for i in range(cb.RUN_FAIL_KILL_LIMIT - cb.PER_SYSTEM_FAIL_LIMIT - 1):
        cb.record_outcome(state, f"system-{i}", ConfigFault.exit_code)
    with pytest.raises(cb.RunAborted) as aborted:
        cb.record_outcome(state, "system-last", ConfigFault.exit_code)
    assert cb.INFRA_CAUSES in str(aborted.value), \
        f"the run-kill message restates the causes: {aborted.value}"

    opening = render_correlation_section(
        CorrelationOutcome(ending=ENDING_TRIPPED_BREAKER, system="elastic"), grant_home="-")
    assert "elastic" in opening, opening
    assert "unreachable" not in opening, \
        f"MAIN's opening message blames connectivity for a tripped breaker: {opening!r}"
