
from __future__ import annotations

import logging
import math
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from defender._clock import parse_iso_utc
from defender.run_repository import RunPaths
from defender.hooks._run_dir import read_json_locked, update_json_locked
from defender.runtime.agent_role import AgentRole

_logger = logging.getLogger(__name__)

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



def make_budget_state(run_id: str) -> dict:
    now = datetime.now(UTC).isoformat()
    return {
        "run_id": run_id,
        "tool_calls": 0,
        "subagent_spawns": 0,
        "created_at": now,
        "started_at": now,
    }


#: The run's budget state, per run folder (`os.path.abspath`), in this process's memory (#1235).
#: Only the run's own process reads or writes it, so no file holds it: nothing the box writes
#: into the run folder can move a count. It stays until the next `open_budget` for the folder,
#: so the run's own process can read it back after the loop ends.
_BUDGETS: dict[str, dict] = {}
#: One lock for every read-modify-write of `_BUDGETS`: the cap check and the increment are one
#: step, so no interleaving of this process's threads loses an increment or overshoots the cap.
_BUDGET_LOCK = threading.Lock()


def _budget_key(run_dir: Path) -> str:
    return os.path.abspath(run_dir)


def open_budget(run_dir: Path, run_id: str) -> dict:
    """Start this run's budget: fresh counters and a wall-clock origin of now, replacing any
    earlier budget this process held for the folder."""
    forget_open_turn(run_dir)
    state = make_budget_state(run_id)
    with _BUDGET_LOCK:
        _BUDGETS[_budget_key(run_dir)] = state
        return dict(state)


def read_budget(run_dir: Path) -> dict:
    """The run's budget state, `{}` when this process opened none for the folder.

    `{}` rather than `make_budget_state(...)`: callers treat absent counters as unspent, and a
    fresh `created_at` would restart the wall clock on every read."""
    with _BUDGET_LOCK:
        return dict(_BUDGETS.get(_budget_key(run_dir), {}))



def _valid_count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


def _held_state(run_dir: Path, run_id: str) -> dict:
    """The folder's live state, started if this process holds none. Call under `_BUDGET_LOCK`."""
    return _BUDGETS.setdefault(_budget_key(run_dir), make_budget_state(run_id))


def update_budget_locked(
    run_dir: Path, run_id: str, tool_name: str, *, limits: dict = DEFAULT_LIMITS
) -> dict:
    """Count one call with no cap check (the unenforced posture)."""
    with _BUDGET_LOCK:
        state = _held_state(run_dir, run_id)
        state["tool_calls"] = (_valid_count(state.get("tool_calls")) or 0) + 1
        if tool_name == "gather":
            state["subagent_spawns"] = (_valid_count(state.get("subagent_spawns")) or 0) + 1
        return dict(state)


def account_call(
    run_dir: Path, run_id: str, tool_name: str, *,
    limits: dict, tier: str, exit_code: int = 0,
) -> dict:
    """Count one executed call against the pool, re-checking the cap at commit time.

    The read, the cap check and the increment are one step under `_BUDGET_LOCK`, so no
    interleaving with another thread can lose an increment; a call at the cap changes nothing.
    (Oracle-held time is not in this state: it is in the run's `oracle-held` sidecar and this
    process's open-turn memory.)"""
    limit = limits["max_tool_calls"] + (TAIL_ALLOWANCE if tier == "tail" else 0)
    with _BUDGET_LOCK:
        state = _held_state(run_dir, run_id)
        current = _valid_count(state.get("tool_calls")) or 0
        if current < limit:
            state["tool_calls"] = current + 1
            if tool_name == "gather":
                state["subagent_spawns"] = (_valid_count(state.get("subagent_spawns")) or 0) + 1
        return dict(state)


def _wall_origin(state: dict) -> datetime | None:
    """The run's wall-clock origin as an aware UTC datetime. A naive one (from a preserved
    offset-less stamp) would make `_elapsed`'s subtraction raise `TypeError`."""
    for key in ("created_at", "started_at"):
        parsed = parse_iso_utc(state.get(key))
        if parsed is not None:
            return parsed
    return None


#: S15 (#1224): the seconds a branched world's oracle held the turn, which every investigator
#: time limit excludes. HOST state, never in the run dir: the box can write the run dir, so a
#: total or an open-turn mark read from there would let it stop the investigator's clock, and a
#: link it planted there would fault every oracle turn. The credited total lives in the run's
#: host-only sidecar beside the run dir (`RunPaths.oracle_held`), where it survives a resume;
#: the turn open now lives in this process's memory — the registry holding it and the
#: enforcer reading it are one process, and a process that dies holds no turn.
ORACLE_HELD_KEY = "oracle_held_seconds"

#: The key `_budget_state_for_enforcement` sets on the in-memory enforcement state to hand
#: `_elapsed` the host's oracle-held seconds. It is never read from a state that names no host
#: value: `_elapsed` honours only a `_HostHeld`, which no JSON document can produce.
ENFORCEMENT_HELD_KEY = "_host_oracle_held"


class _HostHeld(float):
    """Oracle-held seconds the host measured (`oracle_held`). A distinct type so a same-named
    key in a budget state, a plain number, subtracts nothing."""


#: The oracle turn open now per run dir: its `time.monotonic()` start. One turn at a time per
#: world (`WorldRegistry._turn`), and one world per run dir.
_OPEN_TURNS: dict[str, float] = {}
_OPEN_LOCK = threading.Lock()


def _turn_key(run_dir: Path) -> str:
    return os.path.abspath(run_dir)


def _oracle_held_path(run_dir: Path) -> Path:
    run_dir = Path(run_dir)
    return RunPaths(run_dir).oracle_held()


def _seconds(value: object) -> float:
    """A credited total as a usable number of seconds: anything else reads as none credited."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if math.isfinite(number) and number >= 0:
            return number
    return 0.0


def _credited(run_dir: Path) -> float:
    """The oracle-held seconds credited so far, from the host-only sidecar. Absent, linked,
    unreadable or garbage reads as none: the clock then runs, it never pauses."""
    try:
        return _seconds(read_json_locked(_oracle_held_path(run_dir)).get(ORACLE_HELD_KEY))
    except (OSError, ValueError):
        return 0.0


def _has_clock(run_dir: Path) -> bool:
    """Whether this process holds a budget for the run (an enforcer whose clock an oracle turn
    pauses)."""
    with _BUDGET_LOCK:
        return _budget_key(Path(run_dir)) in _BUDGETS


def oracle_turn_opened(run_dir: Path) -> None:
    """Pause the investigator's clock: an oracle turn holds the world from now until
    `oracle_turn_closed`. A run with no budget record (no enforcer) has no clock to pause.
    Writes nothing: the open turn is this process's memory, so nothing the box writes can
    fault it."""
    if not _has_clock(run_dir):
        return
    with _OPEN_LOCK:
        _OPEN_TURNS[_turn_key(run_dir)] = time.monotonic()


def oracle_turn_closed(run_dir: Path) -> None:
    """Resume the investigator's clock, crediting the closed turn's interval to the run's
    host-only total, once. Never raises for the record: a turn whose credit cannot be written
    still closes, and its time then counts toward the investigator's clock.

    @owns oracle_held_seconds"""
    with _OPEN_LOCK:
        opened = _OPEN_TURNS.pop(_turn_key(run_dir), None)
    if opened is None:
        return
    interval = max(0.0, time.monotonic() - opened)

    def _mutate(state: dict) -> None:
        state[ORACLE_HELD_KEY] = _seconds(state.get(ORACLE_HELD_KEY)) + interval

    try:
        update_json_locked(_oracle_held_path(run_dir), _mutate, default=dict)
    except OSError as e:
        _logger.warning(f"the oracle turn's {interval:.1f}s could not be credited to the "
                        f"investigator's clock ({e!r}); it counts as investigator time")


def forget_open_turn(run_dir: Path) -> None:
    """Drop a turn left open in this process for `run_dir` (a run that ended mid-turn): a run
    that starts again in this process starts with its clock running."""
    with _OPEN_LOCK:
        _OPEN_TURNS.pop(_turn_key(run_dir), None)


def oracle_held(run_dir: Path) -> float:
    """The oracle time the investigator's clock excludes for `run_dir`: the host-only credited
    total plus the turn this process holds open now, if any. Zero for a run no oracle served."""
    held = _credited(run_dir)
    with _OPEN_LOCK:
        opened = _OPEN_TURNS.get(_turn_key(run_dir))
    if opened is not None:
        held += max(0.0, time.monotonic() - opened)
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
