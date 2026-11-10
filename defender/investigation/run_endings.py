"""The one order in which a run's endings are chosen (#1465).

A run can end on several failures at once: concurrent leads deliver theirs inside an exception
group. Every site that ends a run or stamps a lead on one asks `ending_in` here and never orders
the endings itself, so a new ending is one row of `ENDINGS`, not an edit at each site.

The vocabulary (`TRUNCATED_BY_*`) and the exit codes stay in `records/run_end`. They cannot own
the order: it names exception classes from `box`, `providers`, `systems` and `hooks`, which sit
above `records`.

The table's order is the precedence: the first row that holds wins. A row holds for an exception
that is, or (inside a group, however deep) carries, its failure, unless the group also carries
something with a meaning of its own for the run: an interrupt or cancellation, or one of the
row's `overridden_by`. Such a group is not decided by this row, so it propagates as itself and the
next row is asked. Each site names the rows it takes part in; it never reorders them. Those lists (the `*_ENDINGS`
and `*_PROPAGATES` tuples below) are the one place a new ending is not automatic: the sites that
take every row but one derive theirs by exclusion, the others opt in, so a new row must be added
to an opt-in list on purpose.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from defender import box as box_mod
from defender import providers
from defender._exception_groups import carried, carried_unless_overridden
from defender.hooks.budget_enforcer import BudgetKill
from defender.records import run_end
from defender.systems.circuit_breaker import RunAborted
from defender.systems.verbs import ServingAbort


@dataclass(frozen=True)
class RunEnding:
    """The ending an exception carries: the failure itself (`error`), the exit class a run or
    lead is stamped with, the exit reason a run reports, and whether the ending's own words are
    all the log says (`plain`) or the site adds how it ends there. `keep_traceback` marks a
    refusal whose traceback is kept: a 400 may be our own request built wrong."""

    error: BaseException
    exit_class: str
    exit_reason: str
    plain: bool = False
    keep_traceback: bool = False


@dataclass(frozen=True)
class EndingRow:
    """One row of the table: how to find its failure in an exception, and what it ends the run
    as."""

    name: str
    find: Callable[[BaseException], RunEnding | None]


#: The failures that propagate before a box ending, beside an interrupt or a cancellation.
PROPAGATE_FIRST: tuple[type[BaseException], ...] = (BudgetKill, RunAborted, ServingAbort)


def box_ending_in(exc: BaseException) -> box_mod.BoxEnding | None:
    """The box ending `exc` ends the run on (bare, or carried by a group with nothing that
    propagates first), the fence before a lost box; else `None`. A group holding both box
    endings names the fence, as the oracle's fence-first order does (#1421 O8, O9)."""
    fence = carried_unless_overridden(exc, box_mod.BoxOutputLimitExceeded, PROPAGATE_FIRST)
    if fence is not None:
        return fence
    return carried_unless_overridden(exc, box_mod.BoxEnding, PROPAGATE_FIRST)


def _box(exc: BaseException) -> RunEnding | None:
    """The box is unusable, or a process wrote past its helper (#1421 O8, O9). Its own words
    are logged once, by the site; the records carry only its class."""
    found = box_ending_in(exc)
    if found is None:
        return None
    return RunEnding(found, found.exit_class, type(found).__name__, plain=True)


def _call_record(exc: BaseException) -> RunEnding | None:
    """A call record the run could not write (A12, #1234). Nothing overrides it: the record is
    what failed, and the group is stamped with the record that did."""
    found = carried(exc, run_end.CallRecordWriteFailed)
    if found is None:
        return None
    return RunEnding(found, found.record, "CallRecordWriteFailed", plain=True)


def _proxy_access(exc: BaseException) -> RunEnding | None:
    """The run's access to the credential proxy is lost (#1363 O7, D4): ours, for the whole
    process, so it overrides a provider outage or refusal beside it. Like them it yields to a
    budget kill, an abort and a box ending, but not to a serving abort: a sibling that holds both
    ends `proxy-access`, not as the oracle's unservable world."""
    found = carried_unless_overridden(
        exc, run_end.ProxyAccessLost, (BudgetKill, RunAborted, box_mod.BoxEnding))
    if found is None:
        return None
    return RunEnding(found, run_end.TRUNCATED_BY_PROXY_ACCESS, str(found))


def _provider_down(exc: BaseException) -> RunEnding | None:
    """A model request kept failing temporarily past the retrier (#1243): an infrastructure
    end, so like the budget kill it writes no report."""
    found = carried_unless_overridden(
        exc, providers.ProviderDown,
        (BudgetKill, RunAborted, box_mod.BoxEnding, run_end.ProxyAccessLost))
    if found is None:
        return None
    return RunEnding(found, run_end.TRUNCATED_BY_PROVIDER_DOWN, "ProviderDown")


#: What a refusal yields to: an interrupt, kill or abort, a box ending, lost access, an outage.
_REFUSAL_YIELDS_TO = (BudgetKill, RunAborted, box_mod.BoxEnding, run_end.ProxyAccessLost,
                      providers.ProviderDown)


def _provider_rejected(exc: BaseException) -> RunEnding | None:
    """A lead's `ProviderRejected`, or MAIN's own refused request (#1243 r3)."""
    found = carried_unless_overridden(exc, providers.ProviderRejected, _REFUSAL_YIELDS_TO)
    if found is None:
        return None
    return RunEnding(found, run_end.TRUNCATED_BY_PROVIDER_REJECTED, "ProviderRejected",
                     keep_traceback=True)


def _provider_refused_by_status(exc: BaseException) -> RunEnding | None:
    """MAIN's own request refused for good, arriving as the bare HTTP error (#1243 r3). Every
    HTTP error the group carries is read, not only the first: a temporary one ahead of a refusal
    must not hide it. Ranked after the refusal that arrives as `ProviderRejected`."""
    # Lazy: the agent framework is not installed where operator tools load this module (the
    # lead-zero census), and only the driver's sites ask this row.
    from pydantic_ai.exceptions import ModelHTTPError

    if carried_unless_overridden(exc, ModelHTTPError, _REFUSAL_YIELDS_TO) is None:
        return None
    pending = [exc]
    while pending:
        leaf = pending.pop(0)
        if isinstance(leaf, BaseExceptionGroup):
            pending.extend(leaf.exceptions)
        elif isinstance(leaf, ModelHTTPError) and (rejection := providers.rejected(leaf)):
            return RunEnding(rejection, run_end.TRUNCATED_BY_PROVIDER_REJECTED,
                             "ProviderRejected", keep_traceback=True)
    return None


#: The endings, most overriding first. The ending a new failure adds is one row here.
BOX = EndingRow("box", _box)
CALL_RECORD = EndingRow("call-record", _call_record)
PROXY_ACCESS = EndingRow("proxy-access", _proxy_access)
PROVIDER_DOWN = EndingRow("provider-down", _provider_down)
PROVIDER_REJECTED = EndingRow("provider-rejected", _provider_rejected)
PROVIDER_REFUSED_BY_STATUS = EndingRow("provider-refused-by-status", _provider_refused_by_status)
ENDINGS: tuple[EndingRow, ...] = (
    BOX, CALL_RECORD, PROXY_ACCESS, PROVIDER_DOWN, PROVIDER_REJECTED, PROVIDER_REFUSED_BY_STATUS,
)

#: Sites that take part in fewer endings name them here, in table order. The driver's main
#: loop takes all of them; the gather lead's stamp only the two that are not stamped where
#: they are raised.
CORRELATION_ENDINGS = tuple(row for row in ENDINGS if row is not CALL_RECORD)
STAMPED_ON_THE_WAY_UP = (BOX, PROXY_ACCESS, PROVIDER_DOWN)
LEAD_ZERO_PROPAGATES = (PROXY_ACCESS, PROVIDER_DOWN, PROVIDER_REJECTED)


def ending_in(exc: BaseException, among: tuple[EndingRow, ...] = ENDINGS) -> RunEnding | None:
    """The ending `exc` carries: the first of `among`, in table order, that holds; else
    `None`."""
    for row in among:
        found = row.find(exc)
        if found is not None:
            return found
    return None


def carries_box_ending(exc: BaseException) -> bool:
    """Whether `exc` is or carries a box ending at all, even beside a kill or abort. The lead
    zero dispatch lets such a group through to the driver instead of naming it, and the driver
    decides which of the two wins."""
    return carried(exc, box_mod.BoxEnding) is not None


def log_ending(logger: logging.Logger, found: RunEnding, exc: BaseException, how: str) -> None:
    """Log `found` once, in its own words; `how` is what the site does next ("ending the run"),
    appended unless the ending's words stand alone."""
    message = f"{found.error}" if found.plain else f"{found.error}; {how}"
    logger.error(message, exc_info=exc if found.keep_traceback else None)
