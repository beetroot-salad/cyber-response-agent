
from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from defender._clock import parse_iso_utc

from defender._agent_role import AgentRole

if TYPE_CHECKING:  # pragma: no cover — typing only
    from contextlib import AbstractContextManager
    from typing import Any, Protocol

    class _Ticks(Protocol):
        def ticks(self) -> float: ...

    class RunState(Protocol):
        """The slice of the run's live state (`investigation.run_state.RunState`, which sits above
        `hooks`) this module reads and writes: the budget, the oracle clock hold and the lock."""

        oracle_credited: float
        oracle_opened: float | None

        @property
        def lock(self) -> AbstractContextManager[Any]: ...
        @property
        def budget(self) -> dict: ...
        @property
        def clock(self) -> _Ticks: ...
        def oracle_held_at(self, tick: float) -> float: ...
        def budget_snapshot(self) -> dict: ...
        def elapsed(self) -> float: ...

DEFAULT_LIMITS = {
    "max_tool_calls": 200,
    "wall_clock_timeout": 1200,
    "max_subagent_spawns": 40,
    "grace_seconds": 120,
    # The ONE harness deadline around the whole correlation lead, in seconds (#1222 A7). Half
    # the run clock: the lead's eight requests and their backend calls (each bounded by its
    # transport, 40 s) finish well inside it, and it stays far under the ceiling
    # (`lead_zero.DEADLINE_CEILING_S`, the clock less the 120 s a `bash` call cannot be cut
    # in). Chosen from the bounds, not measured timings: no real correlation timings exist yet.
    "correlation_deadline": 600,
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


def _tally(state: RunState, tool_name: str) -> None:
    """One call on the run's counters; `gather` is also a spawn. Call under `state.lock`."""
    state.budget["tool_calls"] += 1
    if tool_name == "gather":
        state.budget["subagent_spawns"] += 1


def count_call(state: RunState, tool_name: str) -> dict:
    """Count one call with no cap check (the unenforced posture). Returns the run's budget as
    the enforcing checks read it after the call (`enforcement_state`)."""
    with state.lock:
        _tally(state, tool_name)
        return enforcement_state(state)


def account_call(state: RunState, tool_name: str, *, limits: dict, tier: str) -> dict:
    """Count one executed call against the pool, re-checking the cap at commit time. Returns
    the run's budget as the enforcing checks read it after the call (`enforcement_state`).

    The read, the cap check and the increment are one step under the state's lock, so no
    interleaving with another thread can lose an increment; a call at the cap changes
    nothing."""
    limit = limits["max_tool_calls"] + (TAIL_ALLOWANCE if tier == "tail" else 0)
    with state.lock:
        if state.budget["tool_calls"] < limit:
            _tally(state, tool_name)
        return enforcement_state(state)


# S15 (#1224): the seconds a branched world's oracle held the turn, which every investigator
# time limit excludes, are the run's own host state (`RunState.oracle_credited`, and the open
# turn's start). Nothing persists them, so no credit outlives its run (#1239). They are measured
# on the run clock's own ticks (#1255): an oracle turn pauses the run clock, so it moves neither
# the budget's elapsed time nor any time the model is shown.


def oracle_turn_opened(state: RunState) -> None:
    """Pause the run clock: an oracle turn holds the world from now until
    `oracle_turn_closed`. One turn at a time per world (`WorldRegistry._turn`), so an open
    mark is the turn's own; opening again restarts it."""
    with state.lock:
        state.oracle_opened = state.clock.ticks()


def oracle_turn_closed(state: RunState) -> None:
    """Resume the run clock, crediting the closed turn's interval to the run, once.

    @owns oracle_credited"""
    with state.lock:
        opened, state.oracle_opened = state.oracle_opened, None
        if opened is not None:
            state.oracle_credited += max(0.0, state.clock.ticks() - opened)


def oracle_held(state: RunState) -> float:
    """The oracle time the run clock excludes: the credited total plus the turn open now, if
    any. Zero for a run no oracle served."""
    with state.lock:
        return state.oracle_held_at(state.clock.ticks())


#: The key `enforcement_state` carries the run's live elapsed reader under.
_ELAPSED = "elapsed_now"


def enforcement_state(state: RunState) -> dict:
    """The run's budget as every enforcing check reads it: the counters (`budget_snapshot`)
    and the run's live elapsed reader (`RunState.elapsed`, on the run clock, less the seconds
    oracle turns held the world) — read when a check runs, not when the view is built.

    The one builder of that view: the budget hooks (`driver._budget`) and lead-0's gate both
    read it, so on the same state they answer "is the tail spent?" from one clock."""
    return {**state.budget_snapshot(), _ELAPSED: state.elapsed,
            # Informational: the seconds the reader above already excludes.
            "oracle_held": oracle_held(state)}


def _wall_origin(state: dict) -> datetime | None:
    """A bare budget's origin as an aware UTC datetime. A naive one (from a preserved
    offset-less stamp) would make `_elapsed`'s subtraction raise `TypeError`."""
    for key in ("created_at", "started_at"):
        parsed = parse_iso_utc(state.get(key))
        if parsed is not None:
            return parsed
    return None


def _elapsed(state: dict) -> float | None:
    """The run's elapsed seconds. A view `enforcement_state` built reads the run clock alone
    (#1255 "Time"), through the live reader it carries. A bare budget carries no run clock: it
    reads the wall clock since its origin stamp, as anything outside a run does (rev 5 C4).
    `None` when it names neither — every enforcing check then fails closed."""
    reader = state.get(_ELAPSED)
    if callable(reader):
        value = reader()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)
    origin = _wall_origin(state)
    if origin is None:
        return None
    return (datetime.now(UTC) - origin).total_seconds()


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
