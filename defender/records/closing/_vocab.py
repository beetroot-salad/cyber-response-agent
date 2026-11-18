"""The closing record's column and entry vocabularies, and its bounds (#1534).

Moved down from `investigation/close_tool.py` (outcomes, causes, failure kinds) and from invlang
(ceiling states, anchor and grounding kinds), so the record can check its own values; the close
and the invlang parsers import them from here."""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

# -- outcomes ---------------------------------------------------------------------------------

#: The drafted disposition is committed unchanged: the review never ran, or it ran and the
#: counter-story did not survive, or the challenger declined to argue one.
STANDS = "stands"
#: The drafted disposition is overridden to the host's own `unresolved`. (The value's name is
#: kept because fleet queries and run pages key on it.) The cause says which refusal it was.
FORCED_INCONCLUSIVE = "forced-inconclusive"
#: What a closing record can record; a challenged attempt commits nothing.
OUTCOMES: tuple[str, ...] = (STANDS, FORCED_INCONCLUSIVE)

# -- failure kinds ----------------------------------------------------------------------------
# How the review failed: the typed, countable half of "why". `None` whenever the review did not
# fail, including an override the evidence produced. Each member has a different response.

#: A stage was still pending at its deadline (capacity: move the bound or chase latency).
TIMEOUT = "timeout"
#: A stage call raised, or no reviewer was bound to call (a defect to chase).
STAGE_ERROR = "error"
#: A stage answered outside its output contract (the prompt or contract needs work).
UNREADABLE = "unreadable"
FAILURE_KINDS: tuple[str, ...] = (TIMEOUT, STAGE_ERROR, UNREADABLE)

# -- causes -----------------------------------------------------------------------------------
# The host picks the cause from this closed set; each key is its own sentence (the record and
# its readers carry the sentence the review record always named). Coarser than the conditions:
# where `failure_kind` already separates two conditions, the sentence does not separate them.

CAUSE_NOT_REVIEWED = "the disposition was recorded without a challenge review"
CAUSE_STORY_SETTLED = "the challenge review ran and left nothing about the finding unsettled"
#: Shared by a stage that raised or timed out, an unreadable stage reply, and unbound stages;
#: `failure_kind` tells them apart.
CAUSE_REVIEW_INCOMPLETE = "the challenge review did not complete"
CAUSE_EVIDENCE_CANNOT_DISCRIMINATE = (
    "the evidence gathered cannot discriminate what the challenge review left unsettled")
CAUSE_TURN_BUDGET_SPENT = (
    "the forced-turn budget was spent without settling what the challenge review raised")
CAUSE_NOTHING_LEFT_TO_ASK = (
    "nothing discriminating remains that the investigation was not already asked for")
#: A composer `holds` on an `inconclusive` close judges the ceiling claim, not a verdict.
CAUSE_CEILING_EXAMINED = (
    "the challenge review examined the ceiling claim and found nothing further measurable")

CAUSES: tuple[str, ...] = (
    CAUSE_NOT_REVIEWED, CAUSE_STORY_SETTLED, CAUSE_REVIEW_INCOMPLETE,
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, CAUSE_TURN_BUDGET_SPENT, CAUSE_NOTHING_LEFT_TO_ASK,
    CAUSE_CEILING_EXAMINED,
)
#: Each cause's sentence, for the ticket's first line and the judge's header.
CAUSE_SENTENCES: Mapping[str, str] = MappingProxyType({cause: cause for cause in CAUSES})

#: The stock sentence an `unresolved` record's summary opens with, per (cause, failure kind)
#: that can produce `unresolved` (design OD14). Total over those pairs by construction: the
#: record type refuses any other pair on an `unresolved` record.
OPENERS: Mapping[tuple[str, str | None], str] = MappingProxyType({
    (CAUSE_NOT_REVIEWED, None):
        "The run was cut short before the investigation closed, so the host recorded it unresolved.",
    (CAUSE_REVIEW_INCOMPLETE, TIMEOUT):
        "The challenge review did not finish in time, so the drafted verdict was not allowed to stand.",
    (CAUSE_REVIEW_INCOMPLETE, STAGE_ERROR):
        "The challenge review could not run, so the drafted verdict was not allowed to stand.",
    (CAUSE_REVIEW_INCOMPLETE, UNREADABLE):
        "The challenge review's answer could not be read, so the drafted verdict was not allowed to stand.",
    (CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, None):
        "The challenge review raised a question the gathered evidence cannot settle, so the drafted "
        "verdict was overruled.",
    (CAUSE_TURN_BUDGET_SPENT, None):
        "The investigation ran out of turns before settling what the challenge review raised.",
    (CAUSE_NOTHING_LEFT_TO_ASK, None):
        "The challenge review's open questions had already been asked without being settled, so the "
        "drafted verdict was overruled.",
})

# -- entry vocabularies (moved from invlang) --------------------------------------------------

#: The closed states a `ceiling_test` receipt may claim. Three because that is all current
#: instrumentation distinguishes without reading the model's words: whether the lead's
#: retrieval came back with something, and whether it carries a `fail_reason`.
CEILING_QUERY_FAILED = "query-failed"
CEILING_QUERY_EMPTY = "query-empty"
CEILING_NOTHING_TO_TRY = "nothing-to-try"
CEILING_STATES: tuple[str, ...] = (CEILING_QUERY_FAILED, CEILING_QUERY_EMPTY, CEILING_NOTHING_TO_TRY)

#: `:R authz` / `:R consultations` anchor kinds.
ANCHOR_KINDS: tuple[str, ...] = (
    "iam-policy", "gpo", "cap-rule", "change-mgmt",
    "data-classification-policy", "k8s-policy", "federation-policy",
    "endpoint-policy", "approved-source-list", "runtime-evidence",
    "tacit-knowledge",
    "other",
)

#: `:R consultations`' `grounding` cell. `past-case` is excluded: grounding a baseline on a
#: past case is precedent-by-similarity.
GROUNDING_KINDS: tuple[str, ...] = ("org-authority", "telemetry-baseline")


def grounding_acceptable(value: str) -> bool:
    """Whether `value` may stand in a baseline's `grounding` cell: one of `GROUNDING_KINDS`, or
    empty (the cell is optional). The one check the invlang write gate, the baseline walker and
    `BaselineEntry` share, so a baseline the gate accepts is one the record keeps."""
    return value == "" or value in GROUNDING_KINDS

# -- bounds (characters of treated text) ------------------------------------------------------

SUMMARY_BOUND = 1500
NOTE_BOUND = 400
ANCHOR_ID_BOUND = 200
LEAD_BOUND = 64
RESULT_BOUND = 400
REASONING_BOUND = 400
#: At most this many ceiling receipts on one record.
CEILING_COUNT_CAP = 16
#: Characters of a column's rendered lines, joined by "\n" (separators counted). The ceiling
#: aggregate counts every receipt's line, noted or not.
CEILING_LINES_BOUND = 2048
BASELINE_LINES_BOUND = 2048

#: What a cut text ends with, inside its bound.
ELLIPSIS = "…"
