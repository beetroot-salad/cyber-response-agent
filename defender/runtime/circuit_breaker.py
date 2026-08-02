
from __future__ import annotations

import json
from pathlib import Path

from defender._clock import now_iso
from defender.hooks._run_dir import update_json_locked

PER_SYSTEM_FAIL_LIMIT = 2
RUN_FAIL_KILL_LIMIT = 5

INFRA_EXIT_CODES = frozenset({2, 124})


def is_infra_failure(exit_code: int) -> bool:
    return exit_code in INFRA_EXIT_CODES


def error_class_for_exit(exit_code: int) -> str | None:
    if exit_code == 0:
        return None
    return "infra" if exit_code in INFRA_EXIT_CODES else "agent-fixable"


class RunAborted(Exception):

    def __init__(self, total_failures: int, systems: list[str]):
        self.total_failures = total_failures
        self.systems = sorted(set(systems))
        super().__init__(
            f"run aborted by circuit breaker: {total_failures} connectivity/auth "
            f"failures across systems {self.systems} — the environment appears "
            f"unreachable. Escalate with the visibility gap named."
        )


def _path(run_dir: Path) -> Path:
    return Path(run_dir) / "circuit_breaker.json"


def _blank() -> dict:
    return {"systems": {}, "total_failures": 0}


def _load(run_dir: Path) -> dict:
    """§7 D3's second rider: an unreadable state must NOT read as a healthy, freshly
    initialised breaker (`is_tripped`/`down_message` below both fail closed on `_unreadable`).
    Absence is the ordinary "no breaker file yet" case and stays healthy; existing-but-unreadable
    (a directory squatting the name, a corrupted file) is a distinct, observable state."""
    p = _path(run_dir)
    if not p.exists():
        return _blank()
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return {**_blank(), "_unreadable": True}
    try:
        return json.loads(text or "{}") or _blank()
    except json.JSONDecodeError:
        return {**_blank(), "_unreadable": True}


def record_outcome(run_dir: Path, system: str, exit_code: int) -> dict:
    if not system or not is_infra_failure(exit_code):
        return {}

    def _mutate(state: dict) -> None:
        state.setdefault("systems", {})
        sysrec = state["systems"].setdefault(system, {"failures": 0})
        sysrec["failures"] += 1
        state["total_failures"] = state.get("total_failures", 0) + 1
        if sysrec["failures"] >= PER_SYSTEM_FAIL_LIMIT and "tripped_at" not in sysrec:
            sysrec["tripped_at"] = now_iso()

    try:
        state = update_json_locked(_path(run_dir), _mutate, default=_blank)
    except OSError:
        # A robustness fix regardless of §7 D3's exemption (rider #1): today this propagates
        # uncaught PAST `_drive_agent`'s four-type catch and crashes the process harder than
        # `BudgetKill` would. A refused write here is contained at the writer, same as every
        # other alias refusal — it does not get to also be the reason the run crashes.
        return {}

    if state.get("total_failures", 0) >= RUN_FAIL_KILL_LIMIT:
        raise RunAborted(state["total_failures"], list(state["systems"]))
    return state


def is_tripped(run_dir: Path, system: str) -> bool:
    if not system:
        return False
    state = _load(run_dir)
    if state.get("_unreadable"):
        return True
    rec = state.get("systems", {}).get(system)
    return bool(rec) and rec.get("failures", 0) >= PER_SYSTEM_FAIL_LIMIT


def down_message(run_dir: Path, system: str) -> str:
    state = _load(run_dir)
    if state.get("_unreadable"):
        return (
            f"[circuit-breaker] System '{system}''s breaker state at {_path(run_dir)} is "
            f"UNREADABLE — failing closed: treating {system} as DOWN for this run rather than "
            f"reporting a corrupted or missing state file as a healthy, untripped breaker. Do "
            f"NOT re-dispatch {system}; escalate (inconclusive) if this blocks disposition."
        )
    rec = state.get("systems", {}).get(system, {})
    n = rec.get("failures", PER_SYSTEM_FAIL_LIMIT)
    return (
        f"[circuit-breaker] System '{system}' is DOWN for this run: {n} "
        f"connectivity/auth failures or timeouts (adapter exit 2 / 124) tripped the "
        f"breaker, so this dispatch did not run and {system}'s reference skill was "
        f"not loaded. This "
        f"is a visibility gap, not a query result. Do NOT re-dispatch {system}; "
        f"name the missing evidence in your analysis and escalate (inconclusive) "
        f"if it blocks disposition."
    )
