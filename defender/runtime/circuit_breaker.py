
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from defender._clock import now_iso
from defender._io import TEXT_READ_ERRORS
from defender.hooks._run_dir import update_json_locked

PER_SYSTEM_FAIL_LIMIT = 2
RUN_FAIL_KILL_LIMIT = 5

INFRA_EXIT_CODES = frozenset({2, 124})

#: The two values `error_class_for_exit` writes into every queries-table row. Named because
#: readers BRANCH on them: the companion repeat guard's counted domain is the `agent-fixable`
#: half of the above-guard rows, and the `infra` half is this module's own. A reader that
#: spelled the value itself would be one rename away from silently counting nothing.
INFRA_ERROR_CLASS = "infra"
AGENT_FIXABLE_ERROR_CLASS = "agent-fixable"


def is_infra_failure(exit_code: int) -> bool:
    return exit_code in INFRA_EXIT_CODES


def error_class_for_exit(exit_code: int) -> str | None:
    if exit_code == 0:
        return None
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
    return Path(run_dir) / "circuit_breaker.json"


def _blank() -> dict:
    return {"systems": {}, "total_failures": 0}


def _load(run_dir: Path) -> dict:
    """§7 D3's second rider: an unreadable state must NOT read as a healthy, freshly
    initialised breaker (`is_tripped`/`down_message` both fail closed on `_unreadable`).
    Absence stays healthy; existing-but-unreadable (a directory squatting the name, a
    corrupted file, a symlink aliasing state this run does not own) is a distinct state.

    Existence is `lexists`, not `exists`: `exists()` DEREFERENCES, so a planted DANGLING
    symlink would read as "no file yet" and fail open. A live symlink is refused for the
    mirror reason — following it reads whatever the planter aimed it at."""
    p = _path(run_dir)
    if not os.path.lexists(p):
        return _blank()
    if p.is_symlink():
        return {**_blank(), "_unreadable": True}
    # `TEXT_READ_ERRORS`, not a bare `OSError`: a text read can also fail UNDECODABLE
    # (`UnicodeDecodeError`, a `ValueError`), and a run root the box bind-mounts rw is where
    # non-UTF-8 bytes land for free. That decode error escapes `is_tripped`/`down_message` —
    # outside every `try` at both call sites.
    try:
        text = p.read_text(encoding="utf-8")
    except TEXT_READ_ERRORS:
        return {**_blank(), "_unreadable": True}
    try:
        doc = json.loads(text or "{}")
    except json.JSONDecodeError:
        return {**_blank(), "_unreadable": True}
    # `3`, `"x"` and `[…]` are all valid JSON and none of them is a breaker state; returned as
    # the state itself, every reader's `.get(...)` raises. "Corrupted" has to include "parsed
    # fine, wrong shape" — the shape a box writing into its own run dir produces for free.
    if not isinstance(doc, dict):
        return {**_blank(), "_unreadable": True}
    # ...and so is a dict whose `systems` is `5`, whose per-system record is `7`, or whose
    # `failures`/`total_failures` is `"x"`: every reader below the top level dereferences bare,
    # from call sites outside every `try`. UNREADABLE, not coerced — coercing `{"systems": 5}`
    # to `{}` would answer "no system is down", the fail-OPEN this function refuses.
    # (`lead_zero._breaker_failures` coerces because its answer is a COUNT, not a gate.)
    if not _shape_ok(doc):
        return {**_blank(), "_unreadable": True}
    return doc or _blank()


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _shape_ok(doc: dict) -> bool:
    """Every level below the top, in the shape `is_tripped`/`down_message` dereference it. An
    ABSENT counter is spelled as the `0` those readers already default it to, so the
    membership and type tests are one expression rather than two that could disagree."""
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
        # The writer coerces where `_load` refuses. It cannot fail closed — it has to leave a
        # countable document behind — so a level it cannot read as a counter it starts over
        # from, which is what `default=_blank` already does for the document as a whole.
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
        # §7 D3 rider #1: a refused write is contained at the writer — uncaught it propagates
        # PAST `_drive_agent`'s four-type catch and crashes the process. Shape faults join
        # `OSError` for when a level neither `_mutate`'s coercions nor `_shape_ok` anticipated
        # turns up; failing the write closed is safe, since `_load` reads an unparseable
        # document as `_unreadable`, i.e. DOWN.
        #
        # NEVER SILENTLY, though: a refused write means infra failures stop being counted for
        # the rest of the run — no trip, no `RUN_FAIL_KILL_LIMIT`.
        print(f"[circuit-breaker] outcome for {system!r} not recorded "
              f"({type(e).__name__}: {e}); this run's failure count no longer advances",
              file=sys.stderr)
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
