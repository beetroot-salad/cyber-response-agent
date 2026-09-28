"""Lead-0 vocabulary: lead ids, statuses, field names. Imports none of its siblings."""
from __future__ import annotations

import re

from defender.runtime.agent_role import CORRELATION_GRANT_HOLDER
from defender.runtime.verb_dispositions import (
    HEALTH_CHECK,
    Disposition,
    grant_for,
)
from defender.runtime.verb_grant import GrantError, VerbGrant


L0 = "l-000"
L3 = "l-00c"
RESERVED_LEAD_IDS = (L0, L3)
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


#: Item 1's own system, not the run's `correlation_system`. Every item-1 backend call names it,
#: so its `:L findings` row must too; the correlation system can name a different vendor.
ITEM1_SYSTEM = "elastic"

PROVENANCE_KEY = "provenance"
HARNESS_PROVENANCE = "harness"

LEAD_ZERO_HEADING = "## Alert ancestors"

STATUS_FAILED = "failed"
STATUS_EMPTY = "succeeded-empty"
STATUS_TRUNCATED = "succeeded-truncated"
#: Every requested ancestor document resolved.
STATUS_RESOLVED = "succeeded-resolved"

UNAVAILABLE = "_(unavailable:"
SHORTFALL = "_(incomplete:"
ELIDED = "_(elided:"

#: The per-document `message` rendering budget. Any value that keeps the block materially
#: smaller than a large payload will do; the exact number is not load-bearing.
MESSAGE_CHAR_BUDGET = 4000

ALERT_ID_FIELD = "kibana.alert.uuid"
GROUP_ID_FIELD = "kibana.alert.group.id"
BUILDING_BLOCK_FIELD = "kibana.alert.building_block_type"

ITEM1_GOAL = (
    "Resolve this alert's ancestor documents (the constituent events of its EQL sequence, "
    "or the ancestor_events batch) so MAIN has their timestamp/message/structured fields at "
    "ORIENT without spending a lead or a gather round on it."
)
ITEM1_WHAT_TO_SUMMARIZE = [
    "each resolved ancestor document's timestamp, message and structured fields",
]

_ANY_RUN_TAG = re.compile(r"</?run-[0-9a-zA-Z]*-[a-z-]+>")
#: A markdown code-fence run. Item 3's goal is emitted inside a fenced block, so a fence run in
#: attacker-authored content would close it early and let the text pose as harness prose.

_FENCE_RUN = re.compile(r"`{3,}")
