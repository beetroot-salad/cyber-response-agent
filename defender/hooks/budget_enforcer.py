
from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from defender._clock import parse_iso_utc
from defender.runtime.agent_role import AgentRole

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.runtime.run_state import RunState

DEFAULT_LIMITS = {
    "max_tool_calls": 200,
    "wall_clock_timeout": 1200,
    "max_subagent_spawns": 40,
    "grace_seconds": 120,
}
WARNING_THRESHOLD = 0.75

TAIL_ALLOWANCE = 10

#: Tools never refused for budget (re-exported by `close_tool.py`). Closing must always be
#: possible, since the gate's own forced turns are what push a run into budget pressure.
BUDGET_EXEMPT_TOOLS = frozenset({"close_investigation"})

BUDGET_REFUSAL_MESSAGE = (
    "Budget stop: the {tool} tool is now PERMANENTLY withdrawn for the rest of this "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    "run (the {limb} cap is reached and will not reset). Appending to investigation.md — "
    "append_block — repairing a flagged row — fix_row — and closing the investigation are "
    "still available. "
    "Do not retry this tool; close the investigation now and record your report from "
    "the evidence you already have."
)
# `fix_row` is named because while a row is flagged both `append_block` and the close are
# refused, so offering only those would send the model to a refused close.


class BudgetKill(Exception):
    pass


# The run's budget and its oracle clock live on the run's `RunState` (#1235), which the
# functions below take first and change under its lock. Only the run's own process reads or
# writes them, so no file holds them: nothing the box writes into the run folder can move a
# count or stop the clock.


def _valid_count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


def _count(state: RunState, tool_name: str) -> None:
    """One call on the run's counters; `gather` is also a spawn. Call under `state.lock`."""
    state.budget["tool_calls"] += 1
    if tool_name == "gather":
        state.budget["subagent_spawns"] += 1


def count_call(state: RunState, tool_name: str) -> dict:
    """Count one call with no cap check (the unenforced posture). Returns the budget after."""
    with state.lock:
        _count(state, tool_name)
        return dict(state.budget)


def account_call(state: RunState, tool_name: str, *, limits: dict, tier: str) -> dict:
    """Count one executed call against the pool, re-checking the cap at commit time. Returns
    the budget after.

    The read, the cap check and the increment are one step under the state's lock, so no
    interleaving with another thread can lose an increment; a call at the cap changes
    nothing."""
    limit = limits["max_tool_calls"] + (TAIL_ALLOWANCE if tier == "tail" else 0)
    with state.lock:
        if state.budget["tool_calls"] < limit:
            _count(state, tool_name)
        return dict(state.budget)


def _wall_origin(state: dict) -> datetime | None:
    """The run's wall-clock origin as an aware UTC datetime. A naive one (from a preserved
    offset-less stamp) would make `_elapsed`'s subtraction raise `TypeError`."""
    for key in ("created_at", "started_at"):
        parsed = parse_iso_utc(state.get(key))
        if parsed is not None:
            return parsed
    return None


#: The key `_budget_state_for_enforcement` sets on the in-memory enforcement state to hand
#: `_elapsed` the host's oracle-held seconds. It is never read from a state that names no host
#: value: `_elapsed` honours only a `_HostHeld`, which no JSON document can produce.
ENFORCEMENT_HELD_KEY = "_host_oracle_held"


class _HostHeld(float):
    """Oracle-held seconds the host measured (`oracle_held`). A distinct type so a same-named
    key in a budget state, a plain number, subtracts nothing."""


# S15 (#1224): the seconds a branched world's oracle held the turn, which every investigator
# time limit excludes, are the run's own host state (`RunState.oracle_credited`, and the open
# turn's start). Nothing persists them, so no credit outlives its run (#1239).


def oracle_turn_opened(state: RunState) -> None:
    """Pause the investigator's clock: an oracle turn holds the world from now until
    `oracle_turn_closed`. One turn at a time per world (`WorldRegistry._turn`), so an open
    mark is the turn's own; opening again restarts it."""
    with state.lock:
        state.oracle_opened = time.monotonic()


def oracle_turn_closed(state: RunState) -> None:
    """Resume the investigator's clock, crediting the closed turn's interval to the run, once.

    @owns oracle_credited"""
    with state.lock:
        opened, state.oracle_opened = state.oracle_opened, None
        if opened is not None:
            state.oracle_credited += max(0.0, time.monotonic() - opened)


def oracle_held(state: RunState) -> float:
    """The oracle time the investigator's clock excludes: the credited total plus the turn
    open now, if any. Zero for a run no oracle served."""
    with state.lock:
        held = state.oracle_credited
        if state.oracle_opened is not None:
            held += max(0.0, time.monotonic() - state.oracle_opened)
    return _HostHeld(held)


def _elapsed(state: dict) -> float | None:
    deltas: list[float] = []
    origin = _wall_origin(state)
    if origin is not None:
        deltas.append((datetime.now(UTC) - origin).total_seconds())
    mono = state.get("started_monotonic")
    if isinstance(mono, (int, float)) and not isinstance(mono, bool):
        deltas.append(time.monotonic() - mono)
    if not deltas:
        return None
    held = state.get(ENFORCEMENT_HELD_KEY)
    return max(deltas) - (float(held) if isinstance(held, _HostHeld) else 0.0)


def tail_exhausted(state: dict, limits: dict) -> bool:
    count = _valid_count(state.get("tool_calls"))
    if count is not None and count >= limits["max_tool_calls"] + TAIL_ALLOWANCE:
        return True
    elapsed = _elapsed(state)
    return elapsed is not None and elapsed > limits["wall_clock_timeout"] + limits["grace_seconds"]


#: Main's bookkeeping verbs: metered but never refused at the cap, so a capped run can still
#: record what it found. `fix_row` is included because while a row is flagged both the append
#: and the close are refused. Still stoppable at `tail_exhausted`. Stale names are inert.
_MAIN_TAIL_TOOLS = ("read_file", "append_block", "fix_row", "write_file", "edit_file")


def tier(tool_name: str, role: AgentRole) -> str:
    if role is AgentRole.MAIN and tool_name in _MAIN_TAIL_TOOLS:
        return "tail"
    return "core"


def should_refuse(state: dict, tool_name: str, call_tier: str, limits: dict) -> bool:
    if tool_name in BUDGET_EXEMPT_TOOLS:
        return False
    if call_tier == "tail":
        return False
    count = _valid_count(state.get("tool_calls", 0))
    if count is None or count >= limits["max_tool_calls"]:
        return True
    if tool_name == "gather":
        spawns = _valid_count(state.get("subagent_spawns", 0))
        if spawns is None or spawns >= limits["max_subagent_spawns"]:
            return True
    elapsed = _elapsed(state)
    return elapsed is not None and elapsed >= limits["wall_clock_timeout"]


def refusal_message(state: dict, tool_name: str, limits: dict) -> str:
    return BUDGET_REFUSAL_MESSAGE.format(tool=tool_name, limb=_tripped_limb(state, tool_name, limits))


def _tripped_limb(state: dict, tool_name: str, limits: dict) -> str:
    count = _valid_count(state.get("tool_calls", 0))
    elapsed = _elapsed(state)
    if elapsed is not None and elapsed >= limits["wall_clock_timeout"]:
        return "wall-clock"
    if tool_name == "gather":
        spawns = _valid_count(state.get("subagent_spawns", 0))
        if spawns is None or spawns >= limits["max_subagent_spawns"]:
            return "subagent-spawn"
    if count is None or count >= limits["max_tool_calls"]:
        return "tool-call"
    return "budget"



def _ratio_warning(label: str, current: float, cap: float, unit: str = "") -> str | None:
    cur_s = f"{int(current)}{unit}"
    cap_s = f"{int(cap)}{unit}"
    if cap <= 0:
        return (
            f"Budget exceeded: {label} at {cur_s}/{cap_s}. "
            "Investigation should conclude with current evidence."
        )
    ratio = current / cap
    if ratio >= 1.0:
        return (
            f"Budget exceeded: {label} at {cur_s}/{cap_s}. "
            "Investigation should conclude with current evidence."
        )
    if ratio >= WARNING_THRESHOLD:
        return (
            f"Budget warning: {label} at {cur_s}/{cap_s} "
            f"({int(ratio * 100)}%). Consider wrapping up."
        )
    return None


def _counter_warning(label: str, value: object, cap: float) -> list[str]:
    count = _valid_count(value)
    if count is None:
        return [
            f"Budget exceeded: {label} failed validation (got {value!r}) — failing "
            "closed. Investigation should conclude with current evidence."
        ]
    w = _ratio_warning(label, count, cap)
    return [w] if w else []


def check_budgets(budget: dict, limits: dict) -> list[str]:
    warnings: list[str] = []
    elapsed = _elapsed(budget)
    if elapsed is None:
        warnings.append(
            "Budget exceeded: wall_clock origin is unreadable — failing closed. "
            "Investigation should conclude with current evidence."
        )
    else:
        w = _ratio_warning("wall_clock", elapsed, limits["wall_clock_timeout"], "s")
        if w:
            warnings.append(w)
    warnings += _counter_warning("tool_calls", budget.get("tool_calls"), limits["max_tool_calls"])
    warnings += _counter_warning(
        "subagent_spawns", budget.get("subagent_spawns"), limits["max_subagent_spawns"]
    )
    return warnings
