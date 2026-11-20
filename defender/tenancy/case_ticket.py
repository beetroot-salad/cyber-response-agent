from __future__ import annotations

import logging

from defender.records import closing
from defender._model import model
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

#: A run that never closed (the lookup's `NeverClosed`: no closing record) still comments, with
#: this fixed sentence (#1534).
NEVER_CLOSED_COMMENT_BODY = "No disposition was recorded for this case: the investigation did not close."

#: A run cut short with no verdict leaves the case open and asks a person to escalate.
#: `{exit}` is the driver's exit class, from a closed vocabulary — never box-written text.
ESCALATION_COMMENT_BODY = (
    "Investigation ended without a verdict (exit: {exit}) — the environment appears "
    "unreachable or unconfigured, or the investigation could not complete automatically. Escalate for manual "
    "review; this ticket is left open."
)


class NeverClosed(CaseTicketError):
    """The run has no closing record (`closing.NeverClosed`): the not-recorded branch, never a
    mapping defect."""


class RecordUnreadable(CaseTicketError):
    """The run's closing record could not be looked up (`closing.CouldNotLook`). The message is
    the kind's fixed wording only (`wording`); `detail`, which may name a path, is for the log."""

    def __init__(self, fault: closing.CouldNotLook) -> None:
        super().__init__(fault.wording)
        self.kind = fault.kind
        self.wording = fault.wording
        self.detail = fault.detail


@model(frozen=True)
class CaseRecord:
    """What a run's closing record tells the ticket step: the run and its disposition. Nothing the model wrote reaches the
    comment (#1471 P-6)."""

    case_id: str
    disposition: str


def read_case_record(run: Run) -> CaseRecord:
    """The run's closing record (`closing.for_run`) as the comment's fields. `NeverClosed` and
    `RecordUnreadable` are the two branches a record that is not there takes; the bridge writes to
    a real ticket system, so a fault is never read as an absence."""
    found = closing.for_run(run)
    if isinstance(found, closing.NeverClosed):
        raise NeverClosed("the run has no closing record")
    if isinstance(found, closing.CouldNotLook):
        raise RecordUnreadable(found)
    return CaseRecord(case_id=str(run.id), disposition=found.record.disposition)


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


def never_closed_comment_body() -> str:
    """The not-recorded branch's comment: a fixed host sentence in place of the disposition word."""
    return NEVER_CLOSED_COMMENT_BODY


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
