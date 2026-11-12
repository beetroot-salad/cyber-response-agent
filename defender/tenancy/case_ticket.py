from __future__ import annotations

import re
import logging
from typing import TYPE_CHECKING

from defender.records import formats
from defender._model import model
from defender.records.formats import ReportUnreadable, require_report
from defender.records import Run

if TYPE_CHECKING:
    from defender.tenancy.models import CaseRecord as StoredCaseRecord

_logger = logging.getLogger(__name__)


#: The tenant's case-record file inside its `settings/` folder (#1359): which system records its
#: cases and the comment body template. Optional: a tenant with no case system has none.
CASE_RECORD_REL = "case-record.yaml"

_SIGNATURE_FALLBACK = "unknown"

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

#: The empty-narrative marker, rendered in the narrative segment alone.
NO_NOTES = "(no notes)"

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


class CaseTicketError(Exception):
    pass


class ReportNotParsable(CaseTicketError):
    """`_report.read_report` found no disposition — the unreadable-report branch, never a
    mapping or template defect."""


@model(frozen=True)
class CaseRecord:

    case_id: str
    signature_id: str
    disposition: str
    #: The host's own sentence (frontmatter `cause`), always present on a close-tool report.
    cause: str
    #: The report's body, verbatim — fence-stripping is applied at render time
    #: (`case_record_to_comment`) and the wire bound when posted (`posted_comment`), never here.
    narrative: str


@model(frozen=True)
class CaseRecordSettings:
    """One tenant's `settings/case-record.yaml`, parsed ONCE when the run's tenant is resolved and
    read-only from then on (#1359): the system that records cases, and the comment body template."""

    system: str
    body: str


#: How a case-record fault names the record when its caller names it no other way: the retired file.
CASE_RECORD_FILE = f"settings/{CASE_RECORD_REL}"


def parse_case_record(text: str, *, named: str = CASE_RECORD_FILE) -> CaseRecordSettings:
    """The case record's text as settings, or `CaseTicketError` naming it as `named` (the record, a file, a folder's
    entry): a YAML mapping with a non-empty text `system` and a `comment` mapping whose `body` is non-empty text (no
    product default: the body is the tenant's)."""

    def _fault(text: str) -> CaseTicketError:
        return CaseTicketError(f"{named} {text}")

    import yaml

    from defender._yaml import safe_load

    try:
        data = safe_load(text)
    except (yaml.YAMLError, RecursionError):
        raise _fault("is not valid YAML") from None
    if not isinstance(data, dict):
        raise _fault("must be a YAML mapping with a `system` and a `comment.body`")
    system = data.get("system")
    if not isinstance(system, str) or not system.strip():
        raise _fault("must name the case system in `system` (a non-empty string)")
    comment = data.get("comment")
    body = comment.get("body") if isinstance(comment, dict) else None
    if not isinstance(body, str) or not body.strip():
        raise _fault("must carry a `comment.body` template (a non-empty string)")
    try:
        # A template that cannot render is the file's fault whichever branch is posted (an
        # escalation does not use it, but a tenant who wrote `{0}` is told so all the same).
        _format(body, _ctx(), "comment.body")
    except CaseTicketError as bad:
        raise _fault(f"is unusable: {bad}") from None
    return CaseRecordSettings(system=system.strip(), body=body)


def case_record_text(record: StoredCaseRecord) -> str:
    """A stored case record (#1366) as the case-record text `parse_case_record` reads."""
    from defender._yaml import safe_dump

    return safe_dump({"system": record.system_id, "comment": {"body": record.comment_body}}, sort_keys=False)


def _format(template: str, ctx: dict[str, str], where: str) -> str:
    """`str.format_map`, with every bad-template fault folded into `CaseTicketError` so a
    broken tenant template refuses with a receipt like any other case-settings fault."""
    try:
        return template.format_map(ctx)
    except KeyError as e:
        raise CaseTicketError(
            f"the case record's `{where}` names a render key the context does not "
            f"carry: {e}"
        ) from e
    except (ValueError, IndexError, AttributeError, TypeError) as e:
        raise CaseTicketError(
            f"the case record's `{where}` is not a valid template: {e}"
        ) from e


def _ctx(**kw: str) -> dict[str, str]:
    base = {k: "" for k in ("case_id", "signature", "summary", "disposition",
                            "cause", "narrative", "event_time")}
    base.update(kw)
    return base


def read_case_record(run: Run) -> CaseRecord:
    # The bridge writes to a real ticket system off this record, so an unreadable headline must
    # take the unreadable branch (`ReportNotParsable`) rather than the ordinary one. Re-raised
    # from the shared accessor's own refusal, so this classification is a CONSUMER of
    # `_report.read_report`'s verdict rather than a second, bespoke emptiness check (§7 R10).
    try:
        report = require_report(run.documents.report)
    except ReportUnreadable as e:
        raise ReportNotParsable(str(e)) from e
    fm, body, disposition = report.frontmatter, report.body, report.disposition
    case_id = str(run.id)
    cause = str(fm.get("cause") or "")

    # The signature is the run's recorded one (A1): never read off the alert again. A folder
    # with no usable record has none, and the existing fallback label stands.
    record = formats.parse_alert_record(run.facts.alert_record.read() or "")
    signature_id = (record.signature if record is not None else None) or _SIGNATURE_FALLBACK

    return CaseRecord(
        case_id=case_id,
        signature_id=signature_id,
        disposition=disposition,
        cause=cause,
        narrative=body,
    )


# --------------------------------------------------------------------------------------------
# The comment renderer
# --------------------------------------------------------------------------------------------

# Strips an attacker-planted frontmatter delimiter from free text. Only a standalone `---`
# line counts (indentation allowed); `----` rules and `--- | ---` table rows survive. Line
# breaks are normalised first (`_LINE_BREAKS`), since a UI may break on `\r` or U+2028.
_FENCE_SPLIT = re.compile(r"(?m)^[ \t]*---[ \t]*$")  # lint-frontmatter: ok — strips a planted delimiter from free text, not a frontmatter parse
_LINE_BREAKS = re.compile("\r\n|\r|\u2028|\u2029|\x85|\x0b|\x0c")


def _strip_planted_fence(text: str) -> str:
    """Strip everything from the first line-anchored `---` onward (a planted frontmatter
    fence). Runs before the wire bound, so a cut cannot produce a bare fence. Applied to every
    free-text slot, `cause` included, even though `cause` is host-composed today."""
    return _FENCE_SPLIT.split(_LINE_BREAKS.sub("\n", text))[0].strip()


def _prepare_narrative(narrative: str) -> str:
    """`_strip_planted_fence`, with the no-notes marker for an empty result."""
    stripped = _strip_planted_fence(narrative)
    return stripped if stripped else NO_NOTES


def _bound_wire_bytes(text: str) -> str:
    """Bound the whole posted body to `WIRE_BOUND_BYTES`, cutting at a whole character with
    the ellipsis inside the bound."""
    encoded = text.encode("utf-8")
    if len(encoded) <= WIRE_BOUND_BYTES:
        return text
    budget = WIRE_BOUND_BYTES - len(_ELLIPSIS.encode("utf-8"))
    cut = encoded[:budget].decode("utf-8", errors="ignore")
    return cut + _ELLIPSIS


def case_record_to_comment(rec: CaseRecord, *, settings: CaseRecordSettings) -> str:
    """The comment body: the tenant's own `comment.body` template (default
    `"{disposition} — {cause}\\n\\n{narrative}"`) rendered over the record, fence-stripped.
    The wire bound is applied once, to the posted body with its tag (`posted_comment`)."""
    ctx = _ctx(
        case_id=rec.case_id,
        signature=rec.signature_id,
        disposition=rec.disposition,
        cause=_strip_planted_fence(rec.cause),
        narrative=_prepare_narrative(rec.narrative),
    )
    return _format(settings.body, ctx, "comment.body")


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
    `run_id`, then the comment the template rendered, the whole bounded to `WIRE_BOUND_BYTES`.
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
