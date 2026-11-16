from __future__ import annotations

import logging

from defender._model import model
from defender.records.formats import ReportUnreadable, require_report
from defender.records import Run
from defender.tenancy.case_record import CaseTicketError

_logger = logging.getLogger(__name__)


#: The one bound on the posted comment body, tag line included, in UTF-8 bytes. The cut rounds
#: down to a whole character and the ellipsis fits inside the bound.
WIRE_BOUND_BYTES = 4096
_ELLIPSIS = "…"

#: How every comment the host posts opens (#1221): one plain-text line marking it model-made and
#: naming the run that wrote it. A later run's gather reads it as a past case, never a person's
#: finding, so the teaching (`skills/gather/SKILL.md`, `skills/invlang/SKILL.md`) quotes this
#: prefix verbatim. Plain text with no markup, JSON escape or line break, so it reads the same
#: in a vendor UI and in gather's escaped view; at the START of the body because gather's view
#: keeps only the first characters of a long comment (`payload_view.LEAF_MAX_CHARS`).
AGENT_TAG_PREFIX = "[defender agent comment, run "

#: A run whose report yields no parsable disposition still comments, with this fixed sentence
#: and no narrative. Reached only via `ReportNotParsable`, i.e. `_report.read_report`'s own
#: verdict, not a separate emptiness check.
UNREADABLE_COMMENT_BODY = (
    "No disposition could be recorded for this case: report.md was missing or carried no "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    "parsable disposition to record."
)

#: A run cut short with no verdict leaves the case open and asks a person to escalate.
#: `{exit}` is the driver's exit class, from a closed vocabulary — never box-written text.
ESCALATION_COMMENT_BODY = (
    "Investigation ended without a verdict (exit: {exit}) — the environment appears "
    "unreachable or unconfigured, or the investigation could not complete automatically. Escalate for manual "
    "review; this ticket is left open."
)


class ReportNotParsable(CaseTicketError):
    """`_report.read_report` found no disposition — the unreadable-report branch, never a
    mapping or template defect."""


@model(frozen=True)
class CaseRecord:
    """What a run's report tells the ticket step: the run and its disposition. Nothing the model wrote reaches the
    comment (#1471 P-6)."""

    case_id: str
    disposition: str


def read_case_record(run: Run) -> CaseRecord:
    # The bridge writes to a real ticket system off this record, so an unreadable headline must
    # take the unreadable branch (`ReportNotParsable`) rather than the ordinary one. Re-raised
    # from the shared accessor's own refusal, so this classification is a CONSUMER of
    # `_report.read_report`'s verdict rather than a second, bespoke emptiness check (§7 R10).
    try:
        report = require_report(run.documents.report)
    except ReportUnreadable as e:
        raise ReportNotParsable(str(e)) from e
    return CaseRecord(case_id=str(run.id), disposition=report.disposition)


# --------------------------------------------------------------------------------------------
# The comment's parts (#1471 P-6)
# --------------------------------------------------------------------------------------------


def _bound_wire_bytes(text: str) -> str:
    """Bound the whole posted body to `WIRE_BOUND_BYTES`, cutting at a whole character with
    the ellipsis inside the bound."""
    encoded = text.encode("utf-8")
    if len(encoded) <= WIRE_BOUND_BYTES:
        return text
    budget = WIRE_BOUND_BYTES - len(_ELLIPSIS.encode("utf-8"))
    cut = encoded[:budget].decode("utf-8", errors="ignore")
    return cut + _ELLIPSIS


def agent_comment_tag(run_id: str) -> str:
    """The tag line naming the run that wrote a comment: `AGENT_TAG_PREFIX`, the run id, `]`."""
    return f"{AGENT_TAG_PREFIX}{run_id}]"


def carries_agent_tag(text: str, run_id: str) -> bool:
    """Is `text` the comment `run_id` wrote (#1374 P3)? One of its lines is that run's tag line,
    which stores keep whatever they do to a body; the tag quoted inside a sentence is not."""
    tag = agent_comment_tag(run_id)
    return any(line.strip() == tag for line in text.splitlines())


def posted_comment(body: str, *, run_id: str) -> str:
    """@owns comment body — the body as it reaches the store: the agent tag line naming
    `run_id`, then the comment's parts (each a constant, a closed-set word or an id, #1471 P-6), the whole bounded to
    `WIRE_BOUND_BYTES`.
    The bound cuts from the end, so the tag line always survives it. `run_id` is the run's, not
    the case key, which on the platform is the vendor's ticket id."""
    return _bound_wire_bytes(f"{agent_comment_tag(run_id)}\n{body}")


def unreadable_comment_body() -> str:
    """The unreadable-report branch's comment: a fixed host sentence in place of a rendered
    narrative — never `(unreadable)` as an accidental literal, never the report's own (unparsable)
    text."""
    return UNREADABLE_COMMENT_BODY


def escalation_comment_body(truncated_by: str) -> str:
    """The cut-short branch's comment (#1047 O2): a fixed host sentence naming the exit class,
    and no verdict — the case stays open for a person."""
    return ESCALATION_COMMENT_BODY.format(exit=truncated_by)


def read_posted_comments(run: Run) -> list[tuple[str, str]]:
    """Every comment this run posted on its case ticket, as `(key, body)` in posting order —
    its own writes to the world (`ticket_writer._record_posted_comment`). `[]` when it posted
    none. A record
    that cannot be read, or a line that is not a `{key, body}` of strings, is a warning and is
    left out: the oracle is then not told that write."""
    rows, torn, read = run.observability.ticket_comments.read_rows()
    if read.reason is not None and not read.absent:
        _logger.warning(f"{run.run_dir.name}: its posted-comment record could not be read "
                        f"({read.reason})")
        return []
    out = [(r["key"], r["body"]) for r in rows
           if isinstance(r.get("key"), str) and isinstance(r.get("body"), str)]
    if torn or len(out) != len(rows):
        _logger.warning(f"{run.run_dir.name}: {torn + len(rows) - len(out)} line(s) of its "
                        "posted-comment record could not be read")
    return out
