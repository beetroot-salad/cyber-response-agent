"""Tests for defender/hooks/budget_enforcer.py.

Warning-only budget LIBRARY: counts tool calls / subagent spawns on the run's
own ``RunState`` (#1235 round 2: no ``budget.json``, no table keyed by the folder),
and returns warning strings at 75% / 100%.
Emitting them is the caller's job (`runtime/driver.py`'s `after_tool_execute`).

The `claude -p` PostToolUse entrypoint these tests used to drive — stdin
JSON in, exit code out — was deleted with that retired runtime, so they
drive the two functions the driver actually calls.
"""

from __future__ import annotations

from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    check_budgets,
)


def _state(run_dir):
    from defender.runtime.run_state import RunState

    return RunState.start(run_dir, run_dir.name)


def _bump(state, tool_name: str) -> dict:
    from defender.hooks.budget_enforcer import count_call

    return count_call(state, tool_name)


def test_counts_tool_calls_and_spawns(tmp_path):
    state = _state(tmp_path)
    _bump(state, "bash")
    _bump(state, "gather")
    _bump(state, "read_file")
    budget = state.budget_snapshot()
    assert budget["tool_calls"] == 3
    assert budget["subagent_spawns"] == 1


def test_only_gather_counts_as_a_spawn(tmp_path):
    """"Task"/"Agent" were the retired claude -p dispatch names. No tool by
    either name is registered now, so neither is a spawn — `gather` is."""
    state = _state(tmp_path)
    for name in ("Task", "Agent", "bash", "read_file"):
        _bump(state, name)
    budget = state.budget_snapshot()
    assert budget["tool_calls"] == 4
    assert budget["subagent_spawns"] == 0


def test_warns_when_over_cap(tmp_path):
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 2}
    run = _state(tmp_path)
    _bump(run, "bash")
    state = _bump(run, "bash")
    warnings = check_budgets(state, limits)
    assert any("Budget exceeded: tool_calls at 2/2" in w for w in warnings)


def test_warns_at_the_75_percent_threshold(tmp_path):
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 4}
    run = _state(tmp_path)
    for _ in range(3):
        state = _bump(run, "bash")
    warnings = check_budgets(state, limits)
    assert any("Budget warning: tool_calls at 3/4 (75%)" in w for w in warnings)


def test_no_warning_below_threshold(tmp_path):
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 100}
    state = _bump(_state(tmp_path), "bash")
    assert check_budgets(state, limits) == []


def test_check_budgets_survives_a_budget_missing_started_at(tmp_path):
    """The wall-clock arm swallows a malformed/absent timestamp rather than
    raising into the caller — the tool-call arms still report."""
    warnings = check_budgets({"tool_calls": 9}, {**DEFAULT_LIMITS, "max_tool_calls": 9})
    assert any("tool_calls at 9/9" in w for w in warnings)


