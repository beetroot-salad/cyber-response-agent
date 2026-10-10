
from __future__ import annotations

import json
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from defender._clock import parse_iso_utc
from defender._io import read_text_utf8, write_atomic
from defender.run_repository import RunPaths
from defender.hooks._run_dir import read_json_locked, update_json_locked
from defender.runtime.agent_role import AgentRole

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


_ACCOUNT_LOCK = threading.Lock()


def _write_budget_atomic(run_dir: Path, state: dict) -> None:
    write_atomic(RunPaths(run_dir).budget, json.dumps(state, indent=2))  # lint-unguarded-tree-write: ok — delegates to write_guarded


def account_call(
    run_dir: Path, run_id: str, tool_name: str, *,
    limits: dict, tier: str, exit_code: int = 0,
) -> dict:
    limit = limits["max_tool_calls"] + (TAIL_ALLOWANCE if tier == "tail" else 0)
    with _ACCOUNT_LOCK:
        state = read_budget(run_dir) or make_budget_state(run_id)
        current = _valid_count(state.get("tool_calls")) or 0
        if current >= limit:
            _reset_accounting_failure(run_dir)
            return state
        state["tool_calls"] = current + 1
        if tool_name == "gather":
            state["subagent_spawns"] = (_valid_count(state.get("subagent_spawns")) or 0) + 1
        try:
            _write_budget_atomic(run_dir, state)
        except OSError as e:
            # An alias refusal never counts toward the kill circuit, or the box would hold a
            # DoS lever. Ordinary write failures (squatted directory, full disk) still escalate.
            if getattr(e, "write_guarded_alias", False):
                _record_alias_refusal(run_dir, RunPaths(run_dir).budget)
                return read_budget(run_dir) or state
            _record_accounting_failure(run_dir, limits)
            return read_budget(run_dir) or state
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
#: time limit excludes, and the mark of the turn now open (absent when none is):
#: `{"at": <wall-clock start>, "pid": <writer>, "started": <writer's start time or null>}`.
ORACLE_HELD_KEY = "oracle_held_seconds"
ORACLE_OPEN_KEY = "oracle_open_since"


def _number(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _process_stat(pid: int) -> tuple[str, str] | None:
    """`pid`'s `(state, start time in clock ticks since boot)` from Linux `/proc`, or None where
    it cannot be read. The start time tells a reused pid from the process that held it."""
    try:
        stat = read_text_utf8(Path(f"/proc/{pid}/stat"), limit=4096)
    except (OSError, ValueError):  # unreadable, or a process name that is not UTF-8
        return None
    fields = stat.rpartition(")")[2].split()
    return (fields[0], fields[19]) if len(fields) > 19 else None


def _this_process() -> dict:
    pid = os.getpid()
    stat = _process_stat(pid)
    return {"pid": pid, "started": stat[1] if stat else None}


def _writer_alive(mark: dict) -> bool:
    """Whether the process that wrote `mark` still runs: same pid, same start time where the
    platform tells it, and not a zombie. A mark naming no writer is never trusted."""
    pid = mark.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if pid != os.getpid():
        try:
            os.kill(pid, 0)
        except PermissionError:
            pass  # it exists, owned by someone else
        except OSError:
            return False
    started = mark.get("started")
    stat = _process_stat(pid)
    if stat is None:
        return started is None
    state, now_started = stat
    return state not in ("Z", "X") and (started is None or started == now_started)


def _open_mark(state: dict) -> float | None:
    """The start of the oracle turn open now, if a live process holds it. A turn whose process
    died mid-turn (a killed sibling) left its mark behind; it holds nothing, so a resume into
    the same run dir finds its clock running."""
    mark = state.get(ORACLE_OPEN_KEY)
    if not isinstance(mark, dict) or not _writer_alive(mark):
        return None
    return _number(mark.get("at"))


def oracle_turn_opened(run_dir: Path) -> None:
    """Pause the investigator's clock: an oracle turn holds the world from now, for as long as
    this process lives to close it. A run with no budget record (no enforcer) has no clock to
    pause."""
    path = RunPaths(run_dir).budget
    if not path.is_file():
        return
    writer = _this_process()

    def _mutate(state: dict) -> None:
        state[ORACLE_OPEN_KEY] = {"at": time.time(), **writer}

    update_json_locked(path, _mutate, default=dict)


def oracle_turn_closed(run_dir: Path) -> None:
    """Resume the investigator's clock, crediting the closed turn's interval to the excluded
    total, once.

    @owns oracle_held_seconds"""
    path = RunPaths(run_dir).budget
    if not path.is_file():
        return

    def _mutate(state: dict) -> None:
        opened = _open_mark(state)
        state.pop(ORACLE_OPEN_KEY, None)
        held = _number(state.get(ORACLE_HELD_KEY)) or 0.0
        if opened is not None:
            held += max(0.0, time.time() - opened)
        state[ORACLE_HELD_KEY] = held

    update_json_locked(path, _mutate, default=dict)


def _oracle_held(state: dict) -> float:
    """The excluded oracle time: the credited total plus the turn a live process holds open
    now, if any."""
    held = _number(state.get(ORACLE_HELD_KEY)) or 0.0
    opened = _open_mark(state)
    if opened is not None:
        held += max(0.0, time.time() - opened)
    return held


def _elapsed(state: dict) -> float | None:
    deltas: list[float] = []
    origin = _wall_origin(state)
    if origin is not None:
        deltas.append((datetime.now(UTC) - origin).total_seconds())
    mono = state.get("started_monotonic")
    if isinstance(mono, (int, float)) and not isinstance(mono, bool):
        deltas.append(time.monotonic() - mono)
    return max(deltas) - _oracle_held(state) if deltas else None


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
