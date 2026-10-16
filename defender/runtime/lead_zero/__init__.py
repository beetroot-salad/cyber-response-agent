"""The harness-dispatched correlation lead (`l-00c`), run to its end before MAIN's opening message.

The lead reads this run's alert itself (its stored goal is the harness contract plus a pointer to
the alert file, never alert bytes), is bound by ONE harness deadline, and ends in exactly one way
MAIN is told of: its framed summary, or one fixed sentence naming why there is none (A2, A4, A7).
The ending is decided here, once, from what the lead did, never from text a model or provider
wrote.

  * `_spec`    — the reserved id, the ending vocabulary, the correlation grant.
  * `_agreement` — the run-start check that the configured template and the table agree.
  * `_capture` — the lead's run-folder bookkeeping (declaring row, spawn spend, queries rows).
  * `_items`   — the lead's contract and its one dispatch.
"""
from __future__ import annotations

import asyncio
import logging
import math
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender._io import read_text_utf8
from defender.run_repository import RunPaths
from defender.hooks.budget_enforcer import BudgetKill, count_call
from defender.hooks.record_lead import ALREADY_CLAIMED, CLAIMED, claim_lead
from defender.runtime import circuit_breaker, run_end, system_status
from defender.runtime.run_state import RunState
from defender.runtime.verb_grant import GrantError, VerbGrant
from ._spec import (
    CORRELATION_HEADING,
    CORRELATION_REQUEST_LIMIT,
    ENDING_CLAIM_COLLIDED,
    ENDING_CLAIM_FAILED,
    ENDING_DISPATCH_RAISED,
    ENDING_DOWN_AT_START,
    ENDING_DOWN_MID_LEAD,
    ENDING_EMPTY_OUTPUT,
    ENDING_EVERY_CALL_FAILED,
    ENDING_REQUEST_LIMIT,
    ENDING_TIMED_OUT,
    ENDING_TRIPPED_BREAKER,
    ENDING_WITHHELD,
    HARNESS_PROVENANCE,
    L3,
    PROVENANCE_KEY,
    RESERVED_LEAD_IDS,
    correlation_grant,
    correlation_system,
)
from ._agreement import (
    CorrelationDispatch,
    CorrelationDispatchError,
    resolve_correlation_dispatch,
)
from ._capture import _declare_l_finding
from ._items import LeadEnd, correlation_contract, run_correlation_lead

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.hooks.inject_system_skill_description import SystemIndex

_logger = logging.getLogger(__name__)

#: The cap-table key of the ONE harness deadline around the whole correlation lead (A7). A key of
#: the run's `limits`, so an operator's shortened clock is a cap-table edit like any other.
DEADLINE_KEY = "correlation_deadline"
#: Its fixed ceiling, in seconds: the default run clock (1200 s) less 120 s, the longest step the
#: deadline cannot cut (a `bash` call), less MAIN's minimum time (which has no number: zero).
#: Fixed against the default clock, checked once; never recomputed from a run's own settings.
DEADLINE_CEILING_S = 1200 - 120


class CorrelationDeadlineError(ValueError):
    """The run's correlation deadline is missing or unusable: a setup fault that stops the run
    before the lead starts. Never replaced by a fallback — a zero is not 'unbounded'."""


def correlation_deadline(limits: dict) -> float:
    """@owns correlation_deadline — the correlation deadline in seconds from the run's cap
    table, or `CorrelationDeadlineError` naming the setting. The one reader: called once at run
    start, and the value it returns is passed on to the dispatch, so the value that was checked
    is the value used."""
    if DEADLINE_KEY not in limits:
        raise CorrelationDeadlineError(
            f"the cap table has no {DEADLINE_KEY!r}: the correlation lead is bound by one "
            "deadline and is not run without it")
    value = limits[DEADLINE_KEY]
    try:
        usable = (not isinstance(value, bool) and isinstance(value, (int, float))
                  and math.isfinite(value))
    except OverflowError:  # an integer too large for a float is not a usable number of seconds
        usable = False
    if not usable:
        raise CorrelationDeadlineError(
            f"{DEADLINE_KEY} must be a finite number of seconds, got {value!r}")
    if value <= 0:
        raise CorrelationDeadlineError(
            f"{DEADLINE_KEY} must be a positive number of seconds, got {value!r}")
    if value > DEADLINE_CEILING_S:
        raise CorrelationDeadlineError(
            f"{DEADLINE_KEY} {value!r} is above its ceiling of {DEADLINE_CEILING_S} s (the "
            "default run clock less the longest step the deadline cannot cut)")
    return float(value)


@dataclass(frozen=True)
class CorrelationOutcome:
    """How the correlation lead ended: exactly one of `summary` (the lead's framed result) and
    `ending` (a member of A2's closed list, named to MAIN as one fixed sentence)."""

    summary: str | None = None
    ending: str | None = None
    #: The system the lead was dispatched on (names the one marked down, for `tripped_breaker`).
    system: str | None = None
    #: Why that system is down (#1256), for the two endings that name a cause the breaker does
    #: not count: `down_at_start` and `down_mid_lead`.
    down: system_status.StartCause | None = None


#: One fixed sentence per ending, each saying in its own words why there is no summary. No error
#: text, host path or alert byte ever enters one (A2): they are constants, not renderings.
_SENTENCES = {
    ENDING_DISPATCH_RAISED: (
        "The correlation lead could not be run: dispatching it raised an error, so no "
        "correlation summary exists for this alert and none is coming."),
    ENDING_CLAIM_COLLIDED: (
        f"The correlation lead did not run: the lead id {L3} was already claimed in this run "
        "folder, so its claim collided and nothing was dispatched. No correlation summary "
        "exists for this alert."),
    ENDING_CLAIM_FAILED: (
        "The correlation lead did not start: the harness could not write the lead's own "
        "records or open its session. No correlation summary exists for this alert and none "
        "is coming."),
    ENDING_REQUEST_LIMIT: (
        "The correlation lead was stopped at its own request limit before it could report. "
        "No correlation summary exists for this alert."),
    ENDING_EMPTY_OUTPUT: (
        "The correlation lead finished but wrote nothing, so there is no correlation summary "
        "for this alert."),
    ENDING_EVERY_CALL_FAILED: (
        "Every query the correlation lead issued failed, so it measured nothing and there is "
        "no correlation summary for this alert."),
    ENDING_TIMED_OUT: (
        "The correlation lead timed out: it was still running when the harness's correlation "
        "deadline passed, so it was cut off and anything it produced late was discarded. "
        "No correlation summary exists for this alert."),
}


def _sentence(outcome: CorrelationOutcome, grant_home: str) -> str:
    if outcome.ending == ENDING_WITHHELD:
        return (
            f"No correlation was run on this alert and none is coming: the verb-disposition "
            f"table ({grant_home}) grants the correlation lead no query verb (withheld, or "
            "never decided for it).")
    if outcome.ending == ENDING_TRIPPED_BREAKER:
        return (
            f"The correlation lead's queries were refused: the circuit breaker marked "
            f"{outcome.system} as down for this run. There is no correlation summary, and "
            f"{outcome.system} is unavailable for the rest of the run.")
    if outcome.ending == ENDING_DOWN_AT_START:
        return _down_at_start_sentence(outcome)
    if outcome.ending == ENDING_DOWN_MID_LEAD:
        return (
            f"The correlation lead's queries were refused: one of its calls showed that "
            f"{outcome.system} is not configured for this run (its settings lack something its "
            f"adapter needs), so {outcome.system} is down for the rest of the run. There is no "
            "correlation summary for this alert.")
    return _SENTENCES[str(outcome.ending)]


def _down_at_start_sentence(outcome: CorrelationOutcome) -> str:
    """The `down_at_start` sentence: it names the cause (#1256 O-6), never the check's fault
    text — the reason reaches MAIN in its workspace view (O-3), and these sentences stay
    constants over the system name (A2)."""
    if isinstance(outcome.down, system_status.AdapterBroken):
        cause = (f"{outcome.system}'s adapter is broken (it could not be loaded, or its settings "
                 "check failed unexpectedly)")
    else:
        cause = (f"{outcome.system} is not configured for this run (its settings, checked "
                 "when the run started, do not make it usable)")
    return (
        f"No correlation was run on this alert and none is coming: {cause}, so "
        f"{outcome.system} is down for the whole run and the correlation lead was not started.")


def render_correlation_section(outcome: CorrelationOutcome, *, grant_home: str) -> str:
    """The ONE correlation section of MAIN's opening message: a host heading naming the reserved
    id, the lead's framed summary or its ending's sentence (never both), nothing else."""
    reserved = (
        f"The lead id {L3} is reserved by the harness: it was dispatched, or its absence "
        "decided, before your first turn. Do not attach new work to it.")
    body = outcome.summary if outcome.summary is not None else _sentence(outcome, grant_home)
    return f"{CORRELATION_HEADING}\n{reserved}\n\n{body}"


def _classify_end(end: LeadEnd, run_state: RunState, system: str) -> str | None:
    """The ending of a lead that ran to its own end, or `None` for a usable summary. Decided
    from what the lead did (the harness's stops, the lead's call results), in a fixed order:
    a refused call names the breaker before any count of failures."""
    from defender.runtime import session_store  # lazy: the store needs the agent framework, and the operator tools that read this package's census run without it

    if end.fault_terminator == session_store.TRUNCATED_BY_STORE:
        raise session_store.StoreError("the correlation lead's session could not be recorded")
    if end.breaker_refused is not None:
        return ENDING_TRIPPED_BREAKER
    if isinstance(system_status.down_cause(run_state, system), system_status.NotConfigured):
        # A call's `ConfigFault` escaped the start check: the system went down as not configured
        # mid-lead, uncharged (#1256 O-5b) — never "tripped breaker" nor "every call failed".
        return ENDING_DOWN_MID_LEAD
    summary = (end.summary or "").strip()
    if end.fault_terminator == session_store.TRUNCATED_BY_REQUEST_LIMIT or (
            end.ceiling is not None and not summary):
        return ENDING_REQUEST_LIMIT
    if end.fault_terminator is not None:
        return ENDING_DISPATCH_RAISED
    rows = run_state.lead_rows(L3)
    if rows and all(r.get("exit_code") != 0 for r in rows):
        return ENDING_EVERY_CALL_FAILED
    if not summary:
        return ENDING_EMPTY_OUTPUT
    return None


async def run_correlation(  # noqa: C901, PLR0911, PLR0913 — one early exit per way the lead fails to start; the dispatch seams
    *, run: Any, run_state: RunState, defender_dir: Path, verbs: Any, limits: dict,
    make_model: Any, logger: Any, box: Any, store: Any,
    catalog: SystemIndex | None, dispatch: CorrelationDispatch, tenant: Any, deadline: float,
) -> CorrelationOutcome:
    """Run `l-00c` to its end inside `deadline` seconds and say how it ended.

    Every way it fails to run or yields nothing is a returned ending, never a raise (A2); a
    run-level kill (`BudgetKill`, `RunAborted`), an interrupt, a store fault after the lead
    began, and a run folder that refuses its produced summary propagate and stop the run."""
    from defender.runtime import session_store  # lazy, as in `_classify_end`

    system = dispatch.system
    if system is None:
        return CorrelationOutcome(ending=ENDING_WITHHELD)
    # The run's one question (#1256 DP4). A system down from run start ends the lead here,
    # before its claim and its gather count, as the withheld ending does (O-6): it never refuses
    # the run. A trip keeps its own ending, after the claim (below).
    down = system_status.down_cause(run_state, system)
    if down is not None and not isinstance(down, system_status.Tripped):
        return CorrelationOutcome(ending=ENDING_DOWN_AT_START, system=system, down=down)
    run_dir = run_state.run_dir
    pointer = RunPaths(run_dir).alert.relative_to(run_dir).as_posix()
    goal, what_to_summarize = correlation_contract(pointer, dispatch.template_id)
    claimed = claim_lead({
        "run_dir": str(run_dir), "lead_id": L3, "goal": goal,
        "what_to_summarize": what_to_summarize, PROVENANCE_KEY: HARNESS_PROVENANCE,
    }, run=run)
    if claimed == ALREADY_CLAIMED:
        return CorrelationOutcome(ending=ENDING_CLAIM_COLLIDED, system=system)
    if claimed != CLAIMED or not _declare_l_finding(run, L3, "correlation lead", system):
        return CorrelationOutcome(ending=ENDING_CLAIM_FAILED, system=system)
    # Account the spawn explicitly: `subagent_spawns` counts the "gather" tool name, which a
    # harness dispatch never emits. It spends the run's one budget; nothing is reserved for it.
    count_call(run_state, "gather")
    if down is not None:
        return CorrelationOutcome(ending=ENDING_TRIPPED_BREAKER, system=system)

    from ..agent_role import GATHER_AGENT_ID_PREFIX

    session_id: str | None = None
    if store is not None:
        try:
            session_id = store.new_session(agent_id=f"{GATHER_AGENT_ID_PREFIX}{L3}")
        except (sqlite3.Error, session_store.StoreError, OSError) as e:
            _logger.warning(f"correlation lead's session could not be opened ({e!r})")
            return CorrelationOutcome(ending=ENDING_CLAIM_FAILED, system=system)

    ends: list[LeadEnd] = []
    try:
        async with asyncio.timeout(deadline) as frame:
            wrapped = await run_correlation_lead(
                run=run, run_state=run_state, defender_dir=defender_dir, goal=goal,
                what_to_summarize=what_to_summarize, verbs=verbs, limits=limits,
                make_model=make_model, logger=logger, box=box, store=store,
                catalog=catalog,
                dispatch=dispatch, tenant=tenant, session_id=session_id,
                on_stamp=lambda _reason: None, on_end=ends.append)
    except TimeoutError:
        if not frame.expired():
            return CorrelationOutcome(ending=ENDING_DISPATCH_RAISED, system=system)
        _stamp_timed_out(store, session_id)
        return CorrelationOutcome(ending=ENDING_TIMED_OUT, system=system)
    except (BudgetKill, circuit_breaker.RunAborted, run_end.CallRecordWriteFailed, session_store.StoreError, sqlite3.Error,
            asyncio.CancelledError, KeyboardInterrupt, GeneratorExit, SystemExit):
        raise
    except Exception as e:  # noqa: BLE001 — the lead's own dispatch must never break the run
        _logger.warning(f"correlation lead dispatch failed ({type(e).__name__}); naming it")
        return CorrelationOutcome(ending=ENDING_DISPATCH_RAISED, system=system)
    if not ends:
        return CorrelationOutcome(ending=ENDING_DISPATCH_RAISED, system=system)
    ending = _classify_end(ends[-1], run_state, system)
    if ending is not None:
        return CorrelationOutcome(ending=ending, system=system)
    # A run folder that refuses a produced summary stops the run: it is not the lead's ending.
    path = RunPaths(run_dir).gather_summary(L3)
    if read_text_utf8(path) != wrapped:
        raise OSError("the correlation lead's summary could not be persisted in the run folder")
    return CorrelationOutcome(summary=wrapped, system=system)


def _stamp_timed_out(store: Any, session_id: str | None) -> None:
    """Stamp the lead's session with its ending, best-effort (the store may be the reason)."""
    if store is None or session_id is None:
        return
    try:
        store.set_truncated_by(session_id, run_end.TRUNCATED_BY_TIMED_OUT)
    except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
        _logger.warning(f"correlation lead truncated_by write skipped: {e!r}")


__all__ = [
    "CORRELATION_HEADING",
    "CORRELATION_REQUEST_LIMIT",
    "CorrelationDeadlineError",
    "CorrelationDispatch",
    "CorrelationDispatchError",
    "CorrelationOutcome",
    "DEADLINE_CEILING_S",
    "DEADLINE_KEY",
    "GrantError",
    "L3",
    "RESERVED_LEAD_IDS",
    "VerbGrant",
    "correlation_deadline",
    "correlation_grant",
    "correlation_system",
    "render_correlation_section",
    "resolve_correlation_dispatch",
    "run_correlation",
]
