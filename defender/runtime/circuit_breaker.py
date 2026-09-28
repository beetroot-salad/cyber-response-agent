
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from defender._clock import now_iso
from defender._io import TEXT_READ_ERRORS
from defender._run_paths import RunPaths
from defender.hooks._run_dir import update_json_locked

_logger = logging.getLogger(__name__)

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


def _path(run_dir: Path) -> Path:
    return RunPaths(run_dir).circuit_breaker


def _blank() -> dict:
    return {"systems": {}, "total_failures": 0}


def _load(run_dir: Path) -> dict:
    """Load breaker state. Absent is healthy; existing but unreadable (a squatting directory,
    corrupted file, symlink) is marked `_unreadable`, which the readers treat as tripped.

    `lexists`, not `exists`, so a planted dangling symlink doesn't read as "no file yet"; a
    live symlink is refused too, since following it reads whatever it was aimed at."""
    p = _path(run_dir)
    if not os.path.lexists(p):
        return _blank()
    if p.is_symlink():
        return {**_blank(), "_unreadable": True}
    # `TEXT_READ_ERRORS` includes `UnicodeDecodeError`: the box can write non-UTF-8 bytes
    # here, and the callers have no `try`.
    try:
        text = p.read_text(encoding="utf-8")
    except TEXT_READ_ERRORS:
        return {**_blank(), "_unreadable": True}
    try:
        doc = json.loads(text or "{}")
    except json.JSONDecodeError:
        return {**_blank(), "_unreadable": True}
    # Valid JSON of the wrong shape is corrupted too; readers would raise on it.
    if not isinstance(doc, dict):
        return {**_blank(), "_unreadable": True}
    # Nested levels too. Marked unreadable rather than coerced: coercing `{"systems": 5}` to
    # `{}` would fail open ("no system is down").
    if not _shape_ok(doc):
        return {**_blank(), "_unreadable": True}
    return doc or _blank()


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _shape_ok(doc: dict) -> bool:
    """Whether every nested level has the shape `is_tripped`/`down_message` dereference. An
    absent counter defaults to `0`, as the readers do."""
    if not _is_count(doc.get("total_failures", 0)):
        return False
    systems = doc.get("systems", {})
    if not isinstance(systems, dict):
        return False
    return all(
        isinstance(rec, dict) and _is_count(rec.get("failures", 0))
        for rec in systems.values()
    )


def record_outcome(run_dir: Path, system: str, exit_code: int) -> dict:
    if not system or not is_infra_failure(exit_code):
        return {}

    def _mutate(state: dict) -> None:
        # Unlike `_load`, the writer coerces: it must leave a countable document, so a bad
        # level restarts from zero.
        if not isinstance(state.get("systems"), dict):
            state["systems"] = {}
        sysrec = state["systems"].get(system)
        if not isinstance(sysrec, dict) or not _is_count(sysrec.get("failures")):
            sysrec = {"failures": 0}
            state["systems"][system] = sysrec
        sysrec["failures"] += 1
        prior = state.get("total_failures", 0)
        state["total_failures"] = (prior if _is_count(prior) else 0) + 1
        if sysrec["failures"] >= PER_SYSTEM_FAIL_LIMIT and "tripped_at" not in sysrec:
            sysrec["tripped_at"] = now_iso()

    try:
        state = update_json_locked(_path(run_dir), _mutate, default=_blank)
    except (OSError, TypeError, AttributeError, ValueError) as e:
        # Contained here: uncaught, it would escape the driver's catch and crash the process.
        # Safe, since `_load` reads an unparseable document as down. Logged, because failures
        # stop being counted for the rest of the run.
        _logger.warning(f"outcome for {system!r} not recorded "
                        f"({type(e).__name__}: {e}); this run's failure count no longer advances")
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
            f"NOT re-dispatch {system}; escalate (inconclusive, naming this gap in a `:T conclude` "
            f"`ceiling_test` row) if this blocks disposition."
        )
    rec = state.get("systems", {}).get(system, {})
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
