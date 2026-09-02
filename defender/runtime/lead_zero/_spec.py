"""Harness-executed lead-0.

Before MAIN's first ORIENT turn, the runtime resolves the alert's ancestor documents (item 1)
and dispatches one tightly-bounded correlation gather lead (item 3), both writing into the
run's leads/queries tables under the reserved ids ``l-000``/``l-00c`` so the learning loop and
the review gate cite them like any model-dispatched lead.

This module owns every backend call, run-dir write and dispatch those two items add;
``orient.py`` stays a pure text-assembler that calls ``resolve_lead_zero`` and formats the
returned block as one more ORIENT section.

The vocabulary turn-zero work is written against: lead ids, statuses, field names.

Split out of `lead_zero.py` at 1215 lines; imports none of its siblings.
"""
from __future__ import annotations

import re

from defender.runtime.agent_role import CORRELATION_GRANT_HOLDER
from defender.runtime.verb_dispositions import (
    HEALTH_CHECK,
    Disposition,
    grant_for,
    shipped_dispositions,
)
from defender.runtime.verb_grant import GrantError, VerbGrant


L0 = "l-000"
L3 = "l-00c"
RESERVED_LEAD_IDS = (L0, L3)
CORRELATION_REQUEST_LIMIT = 8


def correlation_grant(rows: tuple[Disposition, ...]) -> VerbGrant:
    """Item 3's grant: the verb-disposition table's projection for the correlation lead.

    Until #999 this was a `VerbGrant` literal here — the one grant the table could neither
    widen nor withdraw, so a withholding written in the table was honoured by item 1 and every
    model-dispatched lead and ignored by item 3. Now it is `grant_for`'s filter over the rows,
    which invents nothing (#995's standing property), and the two pairs are AUTHORED in the
    table under `CORRELATION_GRANT_HOLDER` and nowhere else.

    A function over rows, not only the constant below, because `shipped_dispositions` is
    cached per process: a test that plants a table hands its rows here.
    """
    return grant_for(CORRELATION_GRANT_HOLDER, rows)


def correlation_system(grant: VerbGrant) -> str | None:
    """The one system item 3 is dispatched against, or `None` when there is nothing to dispatch.

    `None`, not a raise, when the grant holds no verb other than `health-check`: that is the
    table WITHHOLDING the lead's query verb — a decision an author wrote down with a reason —
    and it degrades the run (item 3 is neither claimed nor dispatched, and ORIENT says so)
    rather than stopping it. The predecessor raised on an empty grant, which made "skip, do
    not die" impossible. Health-check alone is not a target either: a lead whose template
    index is empty spends its whole budget discovering that.

    Two systems is unreachable past `load_dispositions`, which refuses a table naming them for
    this holder; the raise stays as this function's own contract for a grant that did not
    come through the loader. The choice is deliberate authoring (it selects the template
    index's on-target tier and the prompt-cache lane), never `sorted(...)[0]` at run time.
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


#: Item 3's grant and its dispatched system, projected ONCE at import from the table the rest
#: of the runtime already reads (`driver/_build.py` loads and caches it before this package is
#: ever imported, so a bad table stops the run there, not here). The grant is the authority —
#: it is what `decide` consults — and `system` is only ever a rendering/routing key derived
#: from it, so the two cannot drift. `None` means the table withheld the lead.
CORRELATION_GRANT = correlation_grant(shipped_dispositions())
CORRELATION_SYSTEM: str | None = correlation_system(CORRELATION_GRANT)

#: The catalog template item 3's contract names outright. The grant admits exactly one query
#: verb (`alerts`), and every other elastic template binds `esql` or `query` — so without this
#: template grant ∩ catalog is empty and the dispatch renders `_INDEX_NONE_GRANTED`, leaving a
#: lead to spend its whole budget discovering why nothing is runnable.
CORRELATION_TEMPLATE = "elastic.correlate-alerts-by-entity"

#: Item 1's OWN system, and deliberately not `CORRELATION_SYSTEM`. Every backend call item 1
#: issues names this string directly — `_capture_issue`'s `args`, `_record_manual_row`'s row +
#: `query_id` + `raw_command`, `_breaker_failures`' per-system state read, `_CallLedger.call`'s
#: registry lookup — so its `:L findings` row must be labelled from the SAME anchor. Labelling
#: it from the correlation grant's derived system looks like a dedup while the two are the same
#: string, and mislabels item 1's row the moment `CORRELATION_GRANT` names a different vendor.
ITEM1_SYSTEM = "elastic"

PROVENANCE_KEY = "provenance"
HARNESS_PROVENANCE = "harness"

LEAD_ZERO_HEADING = "## Alert ancestors"

STATUS_FAILED = "failed"
STATUS_EMPTY = "succeeded-empty"
STATUS_TRUNCATED = "succeeded-truncated"
#: Every requested ancestor document resolved. Derived from `saw_success` / `docs` /
#: `requested`; `prepare_correlation_lead`'s gate reads it as "item 1 resolved documents".
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
#: A markdown code-fence run. Neutralized because item 1's rendered block is interpolated into
#: item 3's goal, which `tools_gather._gather_prompt` emits INSIDE a fenced block: a fence run
#: in an attacker-authored `message` (a captured command line, a shell transcript) closes that
#: fence early, so the harness's own `what_to_summarize` block renders as free prose the lead
#: reads as document content.
_FENCE_RUN = re.compile(r"`{3,}")
