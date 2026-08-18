
from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from defender._clock import parse_iso_utc
from defender._io import write_atomic
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

#: The close tool's budget exemption — an explicit roster rather than a side effect of which
#: tier a tool lands in. `close_tool.py` re-exports this name so
#: `defender.runtime.close_tool.BUDGET_EXEMPT_TOOLS` resolves to the SAME object. Closing must
#: always be possible even under budget pressure, since the gate's own forced turns are what
#: push a run into that pressure.
BUDGET_EXEMPT_TOOLS = frozenset({"close_investigation"})

BUDGET_REFUSAL_MESSAGE = (
    "Budget stop: the {tool} tool is now PERMANENTLY withdrawn for the rest of this "
    "run (the {limb} cap is reached and will not reset). Appending to investigation.md — "
    "append_block — repairing a flagged row — fix_row — and closing the investigation are "
    "still available. "
    "Do not retry this tool; close the investigation now and record your report from "
    "the evidence you already have."
)
# `fix_row` is named because the survivor set would otherwise be WRONG whenever a repair
# window is open: both `append_block` and the close are refused while a row is flagged, so a
# message offering only those two sends the model to a close it will be refused.


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

    return update_json_locked(run_dir / "budget.json", _mutate, default=dict)


def read_budget(run_dir: Path) -> dict:
    """The budget state, `{}` when there is none — including when `budget.json` holds valid
    JSON that is not a state at all.

    The narrowing for that last case lives at `read_json_locked`, not here. Without it `[]`,
    `3`, `"x"` and `null` come back as the state itself, and `_budget_state_for_enforcement`'s
    `{**state, …}` raises `TypeError: 'list' object is not a mapping` out of
    `lead_zero._budget_gate` — a path NOT gated on `DEFENDER_BUDGET_ENFORCE`, before MAIN's
    first prompt is built.

    `{}` rather than `make_budget_state(...)`: this reader has no run id, and every caller
    already treats a missing state as "no budget recorded yet" (`account_call` coalesces with
    `or make_budget_state`, `tail_exhausted` and `should_refuse` read absent counters as
    unspent). Inventing a fresh `created_at` here would restart the wall clock on every read.

    The named writer is the boxed adapter subprocess: it bind-mounts the run root rw while the
    defender tree is readonly, and it handles attacker-influenced payloads. This is the DoS
    lever `docs/runtime-sandbox-design.md` §7 D3 exists to deny."""
    return read_json_locked(run_dir / "budget.json")



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
        run_dir / "budget.json", _mutate, default=lambda: make_budget_state(run_id)
    )


_ACCOUNT_LOCK = threading.Lock()


def _write_budget_atomic(run_dir: Path, state: dict) -> None:
    write_atomic(run_dir / "budget.json", json.dumps(state, indent=2))  # lint-unguarded-tree-write: ok — delegates to write_guarded


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
            # §7 D3: a write refused because an alias was planted counts toward nothing and can
            # never end a run — otherwise the box holds a DoS lever. An ORDINARY write failure
            # (a squatted directory, a full disk) still escalates.
            if getattr(e, "write_guarded_alias", False):
                _record_alias_refusal(run_dir, run_dir / "budget.json")
                return read_budget(run_dir) or state
            _record_accounting_failure(run_dir, limits)
            return read_budget(run_dir) or state
    _reset_accounting_failure(run_dir)
    return state



def _accounting_failure_path(run_dir: Path) -> Path:
    run_dir = Path(run_dir)
    return run_dir.parent / f"{run_dir.name}.accounting_failures.json"


def accounting_failure_state(run_dir: Path) -> dict:
    """The two accounting-failure counters, NORMALISED — a corrupt sidecar reads as "no
    failures yet", never as a value the callers then arithmetic on.

    `read_json_locked` narrows the DOCUMENT to a dict; it says nothing about the values inside
    it, and both readers of this state do arithmetic: `int(state.get(...))` raises `ValueError`
    on a string count, and `_record_accounting_failure`'s `time.monotonic() - first_failure_at`
    raises `TypeError` on a non-number stamp — from inside `account_call`'s `except OSError`
    arm, which has no handler for either."""
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
    write_atomic(_accounting_failure_path(run_dir), json.dumps(state))  # lint-unguarded-tree-write: ok — outside every box mount (X6)


def _record_alias_refusal(run_dir: Path, path: Path) -> None:
    """§7 D7: the alias-refusal record lives in the accounting-failure sidecar — a SIBLING of
    the run dir, outside every box mount — not as a new artifact inside the shared tree. An
    in-tree sink would be a sixteenth writer the box could itself plant an alias at, making the
    record suppressible by the exact attack it exists to observe."""
    p = _accounting_failure_path(run_dir)
    state = read_json_locked(p)
    refusals = list(state.get("alias_refusals", []))
    refusals.append({"path": str(path), "ts": datetime.now(UTC).isoformat()})
    state["alias_refusals"] = refusals
    write_atomic(p, json.dumps(state))  # lint-unguarded-tree-write: ok — outside every box mount (X6/D7)



def _wall_origin(state: dict) -> datetime | None:
    """The run's wall-clock origin as an AWARE UTC datetime, never a naive one.

    A bare `datetime.fromisoformat` parses an offset-less stamp — which `open_budget`'s
    `setdefault` PRESERVES rather than replaces — into a naive datetime, and `_elapsed`'s
    `datetime.now(UTC) - origin` then raises `TypeError: can't subtract offset-naive and
    offset-aware datetimes`, which no `except ValueError` catches.

    `_clock.parse_iso_utc` reads a naive stamp AS UTC and accepts the trailing `Z` that
    hand-written seeds carry."""
    for key in ("created_at", "started_at"):
        parsed = parse_iso_utc(state.get(key))
        if parsed is not None:
            return parsed
    return None


def _elapsed(state: dict) -> float | None:
    deltas: list[float] = []
    origin = _wall_origin(state)
    if origin is not None:
        deltas.append((datetime.now(UTC) - origin).total_seconds())
    mono = state.get("started_monotonic")
    if isinstance(mono, (int, float)) and not isinstance(mono, bool):
        deltas.append(time.monotonic() - mono)
    return max(deltas) if deltas else None


def tail_exhausted(state: dict, limits: dict) -> bool:
    count = _valid_count(state.get("tool_calls"))
    if count is not None and count >= limits["max_tool_calls"] + TAIL_ALLOWANCE:
        return True
    elapsed = _elapsed(state)
    return elapsed is not None and elapsed > limits["wall_clock_timeout"] + limits["grace_seconds"]


#: Main's own bookkeeping verbs: reading and recording cost budget but are never REFUSED for
#: it, or a run that hits the cap could no longer write down what it already found.
#: `append_block` is main's only writer, so omitting it would leave the transcript
#: budget-refusable mid-investigation. `write_file`/`edit_file` stay listed because the tier is
#: keyed on a name, not a grant, and a stale name here is inert. `fix_row` is here for the same
#: reason as `append_block`: while a row is flagged BOTH the append and the close are refused,
#: so a repair verb at `core` tier would be permanently withdrawn at the cap and leave the run
#: with nothing that can reopen either.
#: METERED, not exempt — a model looping on repairs is still stoppable at `tail_exhausted`.
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
