
from __future__ import annotations

from typing import TYPE_CHECKING

from defender._clock import now_iso

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.runtime.run_state import RunState

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

#: What a breaker charge can mean, after its count in both messages that name a cause (the
#: down message and the run kill). It sees exit codes alone, and exit 2 is both a
#: `TransportFault` and a `ConfigFault` (#1246).
INFRA_CAUSES = (
    "infra failures (exit 2: unreachable, refused credentials, or missing/broken settings; "
    "exit 124: timed out)")


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
            f"run aborted by circuit breaker: {total_failures} {INFRA_CAUSES} across "
            f"systems {self.systems} — "
            f"the environment appears unreachable or unconfigured. Escalate with the "
            f"visibility gap named."
        )


# The run's breaker lives on the run's `RunState` (#1235): only the run's own process charges or
# reads it, so no file holds it, and nothing the box writes into the run folder can trip or
# untrip a system. Read it with `state.breaker_failures(system)`, or `state.breaker_snapshot()`
# for the whole of it.


def record_outcome(
    state: RunState, system: str, exit_code: int, *, counts_toward_run: bool = True,
) -> dict:
    """Charge an infra failure (exit 2 / 124) to `system`, tripping it at
    `PER_SYSTEM_FAIL_LIMIT`. Returns the breaker after, a copy; `{}` when nothing was charged.
    `RunAborted` once the run's failures reach `RUN_FAIL_KILL_LIMIT`."""
    if not system or not is_infra_failure(exit_code):
        return {}
    with state.lock:
        sysrec = state.breaker["systems"].setdefault(system, {"failures": 0})
        sysrec["failures"] += 1
        if counts_toward_run:
            state.breaker["total_failures"] += 1
        if sysrec["failures"] >= PER_SYSTEM_FAIL_LIMIT and "tripped_at" not in sysrec:
            sysrec["tripped_at"] = now_iso()
        # Inside the charge's lock (it is reentrant), so the copy is the breaker this charge left.
        snapshot = state.breaker_snapshot()
    if snapshot["total_failures"] >= RUN_FAIL_KILL_LIMIT:
        raise RunAborted(snapshot["total_failures"], list(snapshot["systems"]))
    return snapshot


def is_tripped(state: RunState, system: str) -> bool:
    if not system:
        return False
    return state.breaker_failures(system) >= PER_SYSTEM_FAIL_LIMIT


def down_message(state: RunState, system: str) -> str:
    # A system never charged has no count to name; the trip boundary stands in for it.
    n = state.breaker_failures(system) or PER_SYSTEM_FAIL_LIMIT
    return (
        f"[circuit-breaker] System '{system}' is DOWN for this run: {n} {INFRA_CAUSES} "
        f"tripped the "
        f"breaker, so this dispatch did not run and {system}'s reference skill was "
        f"not loaded. This "
        f"is a visibility gap, not a query result. Do NOT re-dispatch {system}; "
        f"name the missing evidence in your analysis and in a `:T conclude` "
        f"`ceiling_test` row (the entry price `inconclusive` owes), then escalate "
        f"(inconclusive) if it blocks disposition."
    )
