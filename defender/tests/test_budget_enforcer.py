"""Tests for defender/hooks/budget_enforcer.py.

Warning-only budget LIBRARY: counts tool calls / subagent spawns per run
into ``{run_dir}/budget.json`` and returns warning strings at 75% / 100%.
Emitting them is the caller's job (`runtime/driver.py`'s `after_tool_execute`).

The `claude -p` PostToolUse entrypoint these tests used to drive — stdin
JSON in, exit code out — was deleted with that retired runtime, so they
drive the two functions the driver actually calls.
"""

from __future__ import annotations

import json

from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    check_budgets,
    update_budget_locked,
)


def _bump(run_dir, tool_name: str) -> dict:
    return update_budget_locked(run_dir, run_dir.name, tool_name)


def test_counts_tool_calls_and_spawns(tmp_path):
    _bump(tmp_path, "bash")
    _bump(tmp_path, "gather")
    _bump(tmp_path, "read_file")
    budget = json.loads((tmp_path / "budget.json").read_text())
    assert budget["tool_calls"] == 3
    assert budget["subagent_spawns"] == 1


def test_only_gather_counts_as_a_spawn(tmp_path):
    """"Task"/"Agent" were the retired claude -p dispatch names. No tool by
    either name is registered now, so neither is a spawn — `gather` is."""
    for name in ("Task", "Agent", "bash", "read_file"):
        _bump(tmp_path, name)
    budget = json.loads((tmp_path / "budget.json").read_text())
    assert budget["tool_calls"] == 4
    assert budget["subagent_spawns"] == 0


def test_warns_when_over_cap(tmp_path):
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 2}
    _bump(tmp_path, "bash")
    state = _bump(tmp_path, "bash")  # hits cap (2/2)
    warnings = check_budgets(state, limits)
    assert any("Budget exceeded: tool_calls at 2/2" in w for w in warnings)


def test_warns_at_the_75_percent_threshold(tmp_path):
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 4}
    for _ in range(3):
        state = _bump(tmp_path, "bash")
    warnings = check_budgets(state, limits)
    assert any("Budget warning: tool_calls at 3/4 (75%)" in w for w in warnings)


def test_no_warning_below_threshold(tmp_path):
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 100}
    state = _bump(tmp_path, "bash")
    assert check_budgets(state, limits) == []


def test_check_budgets_survives_a_budget_missing_started_at(tmp_path):
    """The wall-clock arm swallows a malformed/absent timestamp rather than
    raising into the caller — the tool-call arms still report."""
    warnings = check_budgets({"tool_calls": 9}, {**DEFAULT_LIMITS, "max_tool_calls": 9})
    assert any("tool_calls at 9/9" in w for w in warnings)


def test_increments_are_serialized(tmp_path):
    # Sequential invocations all land — the flock path round-trips cleanly
    # (a smoke check that the read-modify-write doesn't clobber).
    for _ in range(5):
        _bump(tmp_path, "bash")
    budget = json.loads((tmp_path / "budget.json").read_text())
    assert budget["tool_calls"] == 5
