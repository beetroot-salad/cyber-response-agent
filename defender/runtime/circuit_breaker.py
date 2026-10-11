
from __future__ import annotations

import copy
import os
import threading
from pathlib import Path

from defender._clock import now_iso

PER_SYSTEM_FAIL_LIMIT = 2
RUN_FAIL_KILL_LIMIT = 5

INFRA_EXIT_CODES = frozenset({2, 124})

#: The exit code of a call the grant check refused (sysexits' `EX_NOPERM`). Neither infra (a
#: withheld verb is policy, so it charges no breaker) nor agent-fixable (retrying cannot fix a
#: policy bug or injection attempt). Its own class lets readers of the `∅.denied` sentinel row
#: tell it apart without parsing text.
DENIED_EXIT_CODE = 77

#: The values `error_class_for_exit` writes into every queries-table row. Readers branch on
#: them (the repeat guard counts `agent-fixable`, the breaker `infra`; `denied` counts toward
#: neither), so they import these rather than spelling the strings.
INFRA_ERROR_CLASS = "infra"
AGENT_FIXABLE_ERROR_CLASS = "agent-fixable"
DENIED_ERROR_CLASS = "denied"


def is_infra_failure(exit_code: int) -> bool:
    return exit_code in INFRA_EXIT_CODES


def error_class_for_exit(exit_code: int) -> str | None:
    if exit_code == 0:
        return None
    if exit_code == DENIED_EXIT_CODE:
        return DENIED_ERROR_CLASS
    return INFRA_ERROR_CLASS if exit_code in INFRA_EXIT_CODES else AGENT_FIXABLE_ERROR_CLASS


class RunAborted(Exception):

    def __init__(self, total_failures: int, systems: list[str]):
        self.total_failures = total_failures
        self.systems = sorted(set(systems))
        super().__init__(
            f"run aborted by circuit breaker: {total_failures} connectivity/auth "
            f"failures across systems {self.systems} — the environment appears "
            f"unreachable. Escalate with the visibility gap named."
        )


#: The run's breaker state, per run folder (`os.path.abspath`), in this process's memory
#: (#1235). Only the run's own process charges or reads it, so no file holds it: nothing the box
#: writes into the run folder can trip or untrip a system. It stays until the next
#: `open_breaker` for the folder.
_BREAKERS: dict[str, dict] = {}
_BREAKER_LOCK = threading.Lock()


def _blank() -> dict:
    return {"systems": {}, "total_failures": 0}


def _key(run_dir: Path) -> str:
    return os.path.abspath(run_dir)


def open_breaker(run_dir: Path) -> None:
    """Start this run's breaker with no failures, replacing any earlier state for the folder."""
    with _BREAKER_LOCK:
        _BREAKERS[_key(run_dir)] = _blank()


def breaker_state(run_dir: Path) -> dict:
    """A copy of the run's breaker state: `{"systems": {name: {"failures": n, "tripped_at"?:
    iso}}, "total_failures": n}`, blank when nothing was recorded."""
    with _BREAKER_LOCK:
        return copy.deepcopy(_BREAKERS.get(_key(run_dir), _blank()))


def record_outcome(run_dir: Path, system: str, exit_code: int) -> dict:
    if not system or not is_infra_failure(exit_code):
        return {}
    with _BREAKER_LOCK:
        state = _BREAKERS.setdefault(_key(run_dir), _blank())
        sysrec = state["systems"].setdefault(system, {"failures": 0})
        sysrec["failures"] += 1
        state["total_failures"] += 1
        if sysrec["failures"] >= PER_SYSTEM_FAIL_LIMIT and "tripped_at" not in sysrec:
            sysrec["tripped_at"] = now_iso()
        snapshot = copy.deepcopy(state)
    if snapshot["total_failures"] >= RUN_FAIL_KILL_LIMIT:
        raise RunAborted(snapshot["total_failures"], list(snapshot["systems"]))
    return snapshot


def is_tripped(run_dir: Path, system: str) -> bool:
    if not system:
        return False
    rec = breaker_state(run_dir)["systems"].get(system)
    return bool(rec) and rec["failures"] >= PER_SYSTEM_FAIL_LIMIT


def down_message(run_dir: Path, system: str) -> str:
    rec = breaker_state(run_dir)["systems"].get(system, {})
    n = rec.get("failures", PER_SYSTEM_FAIL_LIMIT)
    return (
        f"[circuit-breaker] System '{system}' is DOWN for this run: {n} "
        f"connectivity/auth failures or timeouts (adapter exit 2 / 124) tripped the "
        f"breaker, so this dispatch did not run and {system}'s reference skill was "
        f"not loaded. This "
        f"is a visibility gap, not a query result. Do NOT re-dispatch {system}; "
        f"name the missing evidence in your analysis and in a `:T conclude` "
        f"`ceiling_test` row (the entry price `inconclusive` owes), then escalate "
        f"(inconclusive) if it blocks disposition."
    )
