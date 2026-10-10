
from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from defender._clock import parse_iso_utc
from defender._io import write_atomic
from defender.run_repository import RunPaths
from defender.hooks._run_dir import read_json_locked, update_json_locked
from defender.runtime.agent_role import AgentRole

_logger = logging.getLogger(__name__)

DEFAULT_LIMITS = {
    "max_tool_calls": 200,
    "wall_clock_timeout": 1200,
    "max_subagent_spawns": 40,
    "grace_seconds": 120,
    "accounting_failure_max_consecutive": 5,
    "accounting_failure_max_elapsed": 300,
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


def open_budget(run_dir: Path, run_id: str) -> dict:
    def _mutate(state: dict) -> None:
        now = datetime.now(UTC).isoformat()
        state.setdefault("run_id", run_id)
        state.setdefault("tool_calls", 0)
        state.setdefault("subagent_spawns", 0)
        state.setdefault("created_at", now)
        state.setdefault("started_at", now)

    forget_open_turn(run_dir)
    return update_json_locked(RunPaths(run_dir).budget, _mutate, default=dict)


def read_budget(run_dir: Path) -> dict:
    """The budget state, `{}` when there is none or `budget.json` is not a JSON object (the
    boxed adapter can write the run root, so a planted non-dict must not crash readers).

    `{}` rather than `make_budget_state(...)`: callers treat absent counters as unspent, and a
    fresh `created_at` would restart the wall clock on every read."""
    return read_json_locked(RunPaths(run_dir).budget)



def _valid_count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


def update_budget_locked(
    run_dir: Path, run_id: str, tool_name: str, *, limits: dict = DEFAULT_LIMITS
) -> dict:
    def _mutate(state: dict) -> None:
        state["tool_calls"] = (_valid_count(state.get("tool_calls")) or 0) + 1
        if tool_name == "gather":
            state["subagent_spawns"] = (_valid_count(state.get("subagent_spawns")) or 0) + 1

    return update_json_locked(
        RunPaths(run_dir).budget, _mutate, default=lambda: make_budget_state(run_id)
    )


#: Serializes this process's threads over the failure path's sidecar writes
#: (`_record_accounting_failure`, `_record_alias_refusal`), as before.
#: `budget.json` itself needs no process lock: every write to it is one `update_json_locked`
#: under its file lock, which also orders this process's threads (each opens its own fd).
_ACCOUNT_LOCK = threading.Lock()


def account_call(
    run_dir: Path, run_id: str, tool_name: str, *,
    limits: dict, tier: str, exit_code: int = 0,
) -> dict:
    """Count one executed call against the pool, re-checking the cap at commit time.

    A call at the cap writes nothing. Below it, the read, the cap check and the increment are
    one locked read-modify-write of
    `budget.json` (`update_json_locked`), the same lock the oracle-turn marks are written
    under, so no interleaving with another writer can lose an increment or resurrect a mark
    that writer removed."""
    limit = limits["max_tool_calls"] + (TAIL_ALLOWANCE if tier == "tail" else 0)
    # At the cap nothing changes, so nothing is written: a capped call cannot fail an
    # accounting write (and climb the kill circuit) over a count it never makes. The count only
    # grows, so a read showing the cap stays true; below it the locked write re-checks.
    seen = read_budget(run_dir)
    if (_valid_count(seen.get("tool_calls")) or 0) >= limit:
        with _ACCOUNT_LOCK:
            _reset_accounting_failure(run_dir)
        return seen or make_budget_state(run_id)
    built: dict = {}

    def _mutate(state: dict) -> None:
        if not state:
            state.update(make_budget_state(run_id))
        current = _valid_count(state.get("tool_calls")) or 0
        if current < limit:
            state["tool_calls"] = current + 1
            if tool_name == "gather":
                state["subagent_spawns"] = (_valid_count(state.get("subagent_spawns")) or 0) + 1
        built.update(state)

    with _ACCOUNT_LOCK:
        try:
            state = update_json_locked(
                RunPaths(run_dir).budget, _mutate, default=lambda: make_budget_state(run_id))
        except OSError as e:
            # An alias refusal never counts toward the kill circuit, or the box would hold a
            # DoS lever. Ordinary write failures (squatted directory, full disk) still escalate.
            if getattr(e, "write_guarded_alias", False):
                _record_alias_refusal(run_dir, RunPaths(run_dir).budget)
                return read_budget(run_dir) or built or make_budget_state(run_id)
            _record_accounting_failure(run_dir, limits)
            return read_budget(run_dir) or built or make_budget_state(run_id)
    _reset_accounting_failure(run_dir)
    return state



def _accounting_failure_path(run_dir: Path) -> Path:
    run_dir = Path(run_dir)
    return RunPaths(run_dir).accounting_failures(run_dir.parent)


def accounting_failure_state(run_dir: Path) -> dict:
    """The two accounting-failure counters, normalised: a corrupt value reads as "no failures
    yet". Callers do arithmetic on them inside an `except OSError` arm that cannot handle the
    `ValueError`/`TypeError` a bad value would raise."""
    state = read_json_locked(_accounting_failure_path(run_dir))
    stamp = state.get("first_failure_at")
    return {
        "consecutive_failures": _valid_count(state.get("consecutive_failures")) or 0,
        "first_failure_at": (
            stamp if isinstance(stamp, (int, float)) and not isinstance(stamp, bool) else None
        ),
    }


def _record_accounting_failure(run_dir: Path, limits: dict) -> None:
    state = accounting_failure_state(run_dir)
    state["consecutive_failures"] += 1
    if state["first_failure_at"] is None:
        state["first_failure_at"] = time.monotonic()
    _write_accounting_failure(run_dir, state)
    if state["consecutive_failures"] >= limits["accounting_failure_max_consecutive"]:
        raise BudgetKill(
            f"budget accounting write failed {state['consecutive_failures']}x "
            "consecutively — the run dir is unwritable; enforcement has left the run"
        )
    if time.monotonic() - state["first_failure_at"] >= limits["accounting_failure_max_elapsed"]:
        raise BudgetKill(
            "budget accounting has been failing intermittently past the elapsed "
            "threshold — the run dir is degraded; enforcement cannot be trusted"
        )


def _reset_accounting_failure(run_dir: Path) -> None:
    state = accounting_failure_state(run_dir)
    if state["consecutive_failures"] == 0:
        return
    state["consecutive_failures"] = 0
    _write_accounting_failure(run_dir, state)


def _write_accounting_failure(run_dir: Path, state: dict) -> None:
    write_atomic(_accounting_failure_path(run_dir), json.dumps(state))  # lint-unguarded-tree-write: ok — outside every box mount


def _record_alias_refusal(run_dir: Path, path: Path) -> None:
    """Record an alias refusal in the accounting-failure sidecar, outside every box mount: an
    in-tree record could itself be aliased by the attack it exists to observe."""
    p = _accounting_failure_path(run_dir)
    state = read_json_locked(p)
    refusals = list(state.get("alias_refusals", []))
    refusals.append({"path": str(path), "ts": datetime.now(UTC).isoformat()})
    state["alias_refusals"] = refusals
    write_atomic(p, json.dumps(state))  # lint-unguarded-tree-write: ok — outside every box mount



def _wall_origin(state: dict) -> datetime | None:
    """The run's wall-clock origin as an aware UTC datetime. A naive one (from a preserved
    offset-less stamp) would make `_elapsed`'s subtraction raise `TypeError`."""
    for key in ("created_at", "started_at"):
        parsed = parse_iso_utc(state.get(key))
        if parsed is not None:
            return parsed
    return None


#: S15 (#1224): the seconds a branched world's oracle held the turn, which every investigator
#: time limit excludes. HOST state, never in `budget.json`: the box can write the run dir, so a
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
    key in `budget.json`, which decodes to a plain number, subtracts nothing."""


#: The oracle turn open now per run dir: its `time.monotonic()` start. One turn at a time per
#: world (`WorldRegistry._turn`), and one world per run dir.
_OPEN_TURNS: dict[str, float] = {}
_OPEN_LOCK = threading.Lock()


def _turn_key(run_dir: Path) -> str:
    return os.path.abspath(run_dir)


def _oracle_held_path(run_dir: Path) -> Path:
    run_dir = Path(run_dir)
    return RunPaths(run_dir).oracle_held(run_dir.parent)


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
    """Whether the run has a budget record (an enforcer whose clock an oracle turn pauses).
    `lexists`, so a link the box planted at `budget.json` still counts as a run with a clock."""
    return os.path.lexists(RunPaths(Path(run_dir)).budget)


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
