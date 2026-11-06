"""The box ending a run ends on (#1421 O8, O9), read the same way at every site that ends a run or
stamps a lead: the driver's main and correlation sites and the gather lead's own stamp.

Concurrent leads may deliver an ending inside an exception group. A group that also carries an
interrupt, a budget kill, a breaker abort or a serving abort propagates as itself: each of those
has its own ending, which a box ending must not replace (a world that went unservable still exits
3). A group holding both box endings names the fence, as the oracle's fence-first order does.
"""
from __future__ import annotations

from defender import box as box_mod
from defender._exception_groups import carried_unless_overridden
from defender.hooks.budget_enforcer import BudgetKill
from defender.systems.circuit_breaker import RunAborted
from defender.systems.verbs import ServingAbort

#: The failures that propagate before a box ending, beside an interrupt or a cancellation.
PROPAGATE_FIRST: tuple[type[BaseException], ...] = (BudgetKill, RunAborted, ServingAbort)


def box_ending_in(exc: BaseException) -> box_mod.BoxEnding | None:
    """The box ending `exc` ends the run on (bare, or carried by a group with nothing that
    propagates first), the fence before a lost box; else `None`."""
    fence = carried_unless_overridden(exc, box_mod.BoxOutputLimitExceeded, PROPAGATE_FIRST)
    if fence is not None:
        return fence
    return carried_unless_overridden(exc, box_mod.BoxEnding, PROPAGATE_FIRST)
