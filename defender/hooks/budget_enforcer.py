
from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

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

BUDGET_REFUSAL_MESSAGE = (
    "Budget stop: the {tool} tool is now PERMANENTLY withdrawn for the rest of this "
    "run (the {limb} cap is reached and will not reset). Writing your report — "
    "write_file / edit_file to report.md and investigation.md — is still available. "
    "Do not retry this tool; write your report now from the evidence you already have."
)


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
    write_atomic(run_dir / "budget.json", json.dumps(state, indent=2))


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
        except OSError:
            _record_accounting_failure(run_dir, limits)
            return read_budget(run_dir) or state
    _reset_accounting_failure(run_dir)
    return state



def _accounting_failure_path(run_dir: Path) -> Path:
    run_dir = Path(run_dir)
    return run_dir.parent / f"{run_dir.name}.accounting_failures.json"


def accounting_failure_state(run_dir: Path) -> dict:
    state = read_json_locked(_accounting_failure_path(run_dir))
    return {
        "consecutive_failures": int(state.get("consecutive_failures", 0) or 0),
        "first_failure_at": state.get("first_failure_at"),
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
    write_atomic(_accounting_failure_path(run_dir), json.dumps(state))



def _wall_origin(state: dict) -> datetime | None:
    for key in ("created_at", "started_at"):
        raw = state.get(key)
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw)
            except ValueError:
                continue
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


def tier(tool_name: str, role: AgentRole) -> str:
    if role is AgentRole.MAIN and tool_name in ("read_file", "write_file", "edit_file"):
        return "tail"
    return "core"


def should_refuse(state: dict, tool_name: str, call_tier: str, limits: dict) -> bool:
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
