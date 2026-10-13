"""Lead-0 vocabulary: the correlation lead's id, provenance and endings. Imports none of its siblings."""
from __future__ import annotations

from defender.runtime.agent_role import CORRELATION_GRANT_HOLDER
from defender.runtime.verb_dispositions import (
    HEALTH_CHECK,
    Disposition,
    grant_for,
)
from defender.runtime.verb_grant import GrantError, VerbGrant


L3 = "l-00c"
RESERVED_LEAD_IDS = (L3,)
CORRELATION_REQUEST_LIMIT = 8


def correlation_grant(rows: tuple[Disposition, ...]) -> VerbGrant:
    """Item 3's grant: the verb-disposition table's projection for the correlation lead.

    The table can grant or withhold; the granted pair must match the configured template,
    which `_agreement` checks at run start. A function over rows, not a constant, because each
    run projects its own tenant's table.
    """
    return grant_for(CORRELATION_GRANT_HOLDER, rows)


def correlation_system(grant: VerbGrant) -> str | None:
    """The one system item 3 is dispatched against, or `None` when there is nothing to dispatch.

    `None` when the grant holds nothing but `health-check`: the table withheld the lead, which
    degrades the run (item 3 is skipped and ORIENT says so) rather than stopping it.
    Health-check alone is not a target either: the lead would spend its budget on a ping.

    Raises on two systems (the loader already refuses that; this guards other grants): the
    system selects the template tier and cache lane, so it must be authored, not picked.
    """
    systems = sorted({s for s, v, _ in grant.entries if v != HEALTH_CHECK})
    if not systems:
        return None
    if len(systems) != 1:
        raise GrantError(
            f"the correlation grant for role {grant.role!r} reaches {len(systems)} systems "
            f"({systems}) — the dispatched system is derived from it and only a single-system "
            "grant determines one."
        )
    return systems[0]


PROVENANCE_KEY = "provenance"
HARNESS_PROVENANCE = "harness"

#: The heading of the one correlation section in MAIN's opening message (A4, M1). It names the
#: reserved id; the outcome (the lead's framed summary, or one ending's sentence) sits under it.
CORRELATION_HEADING = f"## Correlation lead ({L3})"

#: A2's closed list of the lead's own endings, in the order the classifier tries them.
ENDING_WITHHELD = "withheld"
ENDING_DISPATCH_RAISED = "dispatch_raised"
ENDING_CLAIM_COLLIDED = "claim_collided"
ENDING_CLAIM_FAILED = "claim_failed"
ENDING_REQUEST_LIMIT = "request_limit"
ENDING_TRIPPED_BREAKER = "tripped_breaker"
ENDING_EMPTY_OUTPUT = "empty_output"
ENDING_EVERY_CALL_FAILED = "every_call_failed"
ENDING_TIMED_OUT = "timed_out"

#: The run-level end the correlation lead's own deadline names on its session
#: (`session_store.TRUNCATED_BY_TIMED_OUT`).
