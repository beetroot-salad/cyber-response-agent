
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
    p = _path(run_dir)
    if not p.is_file():
        return _blank()
    try:
        return json.loads(p.read_text(encoding="utf-8") or "{}") or _blank()
    except (json.JSONDecodeError, OSError):
        return _blank()


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

    state = update_json_locked(_path(run_dir), _mutate, default=_blank)

    if state.get("total_failures", 0) >= RUN_FAIL_KILL_LIMIT:
        raise RunAborted(state["total_failures"], list(state["systems"]))
    return state


def is_tripped(run_dir: Path, system: str) -> bool:
    if not system:
        return False
    rec = _load(run_dir).get("systems", {}).get(system)
    return bool(rec) and rec.get("failures", 0) >= PER_SYSTEM_FAIL_LIMIT


def down_message(run_dir: Path, system: str) -> str:
    rec = _load(run_dir).get("systems", {}).get(system, {})
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
