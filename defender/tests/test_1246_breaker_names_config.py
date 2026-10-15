"""#1246 — a breaker tripped by a missing config must not tell MAIN the cause was connectivity.

A `ConfigFault` (the tenant's settings do not configure the system) exits 2, the same code as a
`TransportFault`, so it charges the same per-system breaker. That sharing is intended; the
breaker's text naming only "connectivity/auth" is not — it points the model and the operator
away from the settings. The breaker sees exit codes alone, so its text must name every cause
that exit code carries.
"""
from __future__ import annotations

import pytest

from defender.runtime import circuit_breaker as cb
from defender.runtime.run_state import RunState
from defender.scripts.adapters.faults import ConfigFault


def test_a_breaker_tripped_by_config_faults_names_configuration(tmp_path):
    state = RunState(tmp_path, "run-1246")
    for _ in range(cb.PER_SYSTEM_FAIL_LIMIT):
        cb.record_outcome(state, "elastic", ConfigFault.exit_code)
    assert cb.is_tripped(state, "elastic"), "config faults no longer charge the breaker"
    msg = cb.down_message(state, "elastic")
    assert "configuration" in msg, f"the down message never names a config cause: {msg!r}"


def test_a_run_killed_by_config_faults_names_configuration(tmp_path):
    state = RunState(tmp_path, "run-1246")
    for i in range(cb.RUN_FAIL_KILL_LIMIT - 1):
        cb.record_outcome(state, f"system-{i}", ConfigFault.exit_code)
    with pytest.raises(cb.RunAborted) as aborted:
        cb.record_outcome(state, "system-last", ConfigFault.exit_code)
    msg = str(aborted.value)
    assert "configuration" in msg, f"the run-kill message never names a config cause: {msg!r}"
