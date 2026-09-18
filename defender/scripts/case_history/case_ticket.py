#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._report import ReportUnreadable, require_report
from defender._run_paths import RunPaths


_MAPPING_RELPATH = "knowledge/environment/systems/case-history/mapping.yaml"

_SIGNATURE_FALLBACK = "unknown"
_SUMMARY_FALLBACK = "(no rule description)"

#: #767 D3/O8 — ONE bound, 4096 UTF-8 BYTES on the rendered comment body. The cut rounds DOWN
#: to the last whole character and the ellipsis sits INSIDE the bound. Retires the old
#: `_TICKET_REASON_MAX` (472 characters), sized against the `close.resolution` field D5 deletes.
WIRE_BOUND_BYTES = 4096
_ELLIPSIS = "…"

#: D3's empty-narrative marker — rendered in the narrative segment alone.
NO_NOTES = "(no notes)"

#: D2 — a run whose report yields no parsable disposition still comments, with this fixed host
#: sentence and no narrative (§7 R10/FK06). Never built as a bespoke emptiness check: this
#: branch is reached only through `_report.read_report`'s own verdict (`read_case_record`
#: below), via `ReportNotParsable`.
UNREADABLE_COMMENT_BODY = (
    "No disposition could be recorded for this case: report.md was missing or carried no "
    "parsable disposition to record."
)

#: #1047 O2 — a run cut short with no verdict (an `aborted` exit, or a forced-close-set exit
#: whose own forced report is unusable) leaves the case open and asks a person to escalate.
#: `{exit}` is the exit class the driver stamped; it is the one rendered value, and it comes
#: from the driver's closed vocabulary, never from anything the box wrote.
ESCALATION_COMMENT_BODY = (
    "Investigation ended without a verdict (exit: {exit}) — the environment appears "
    "unreachable or the investigation could not complete automatically. Escalate for manual "
    "review; this ticket is left open."
)


class CaseTicketError(Exception):
    pass


class ReportNotParsable(CaseTicketError):
    """`read_case_record`'s own signal that `_report.read_report` found no disposition — the
    unreadable-report branch, never a mapping or template defect (§7 R10)."""


@dataclass(frozen=True)
class CaseRecord:

    case_id: str
    signature_id: str
    disposition: str
    #: The host's own sentence (frontmatter `cause`), always present on a close-tool report.
    cause: str
    #: The report's body, verbatim — fence-stripping and the wire bound are applied at render
    #: time (`case_record_to_comment`), never here.
    narrative: str


def _mapping_path() -> Path:
    base = os.environ.get("DEFENDER_DIR")
    root = Path(base) if base else Path(__file__).resolve().parents[2]
    return root / _MAPPING_RELPATH


def _load_mapping() -> dict[str, Any]:
    path = _mapping_path()
    if not path.is_file():
        raise CaseTicketError(f"case-history mapping not found: {path}")
    import yaml

    from defender._yaml import safe_load

    try:
        data = safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise CaseTicketError(f"case-history mapping is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise CaseTicketError(f"case-history mapping is not a mapping: {path}")
    return data


def _dig(obj: Any, dotted: str) -> Any:
    cur = obj
    for key in dotted.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _render(value: Any, ctx: dict[str, str]) -> Any:
    if isinstance(value, str):
        return value.format_map(ctx)
    if isinstance(value, list):
        return [_render(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: _render(v, ctx) for k, v in value.items()}
    return value


def _ctx(**kw: str) -> dict[str, str]:
    base = {k: "" for k in ("case_id", "signature", "summary", "disposition",
                            "cause", "narrative", "event_time")}
    base.update(kw)
    return base


def _signature_id(alert: dict[str, Any], mapping: dict[str, Any]) -> str:
    path = _dig(mapping, "source.signature") or "rule.id"
    val = _dig(alert, str(path))
    return str(val) if val else _SIGNATURE_FALLBACK


def _event_time(alert: dict[str, Any], mapping: dict[str, Any]) -> str:
    path = _dig(mapping, "source.event_time") or "timestamp"
    val = _dig(alert, str(path))
    return str(val) if val else ""


def alert_event_time(alert: dict[str, Any]) -> str | None:
    return _event_time(alert, _load_mapping()) or None


def read_case_record(run_dir: Path) -> CaseRecord:
    # The bridge writes to a real ticket system off this record, so an unreadable headline must
    # take the unreadable branch (`ReportNotParsable`) rather than the ordinary one. Re-raised
    # from the shared accessor's own refusal, so this classification is a CONSUMER of
    # `_report.read_report`'s verdict rather than a second, bespoke emptiness check (§7 R10).
    try:
        report = require_report(RunPaths(run_dir).report)
    except ReportUnreadable as e:
        raise ReportNotParsable(str(e)) from e
    fm, body, disposition = report.frontmatter, report.body, report.disposition
    case_id = run_dir.name
    cause = str(fm.get("cause") or "")

    mapping = _load_mapping()
    signature_id = _SIGNATURE_FALLBACK
    alert_path = RunPaths(run_dir).alert
    if alert_path.is_file():
        with contextlib.suppress(json.JSONDecodeError, OSError):
            signature_id = _signature_id(json.loads(alert_path.read_text(encoding="utf-8")), mapping)

    return CaseRecord(
        case_id=case_id,
        signature_id=signature_id,
        disposition=disposition,
        cause=cause,
        narrative=body,
    )


def alert_to_open_payload(alert: dict[str, Any], case_id: str) -> dict[str, Any]:
    mapping = _load_mapping()
    signature = _signature_id(alert, mapping)
    summary = _dig(alert, str(_dig(mapping, "source.summary") or "rule.description"))
    ctx = _ctx(
        case_id=case_id,
        signature=signature,
        summary=str(summary) if summary else _SUMMARY_FALLBACK,
        event_time=_event_time(alert, mapping),
    )
    payload = _render(mapping.get("open") or {}, ctx)
    if isinstance(payload.get("labels"), list):
        bare = {p for p in _open_label_prefixes(mapping) if p}
        payload["labels"] = [lbl for lbl in payload["labels"] if lbl not in bare]
    return payload


def _open_label_prefixes(mapping: dict[str, Any]) -> list[str]:
    out = []
    for tmpl in _dig(mapping, "open.labels") or []:
        if isinstance(tmpl, str):
            i = tmpl.find("{")
            if i > 0:
                out.append(tmpl[:i])
    return out


def _open_label_prefix(mapping: dict[str, Any], placeholder: str) -> str | None:
    ph = "{" + placeholder + "}"
    for tmpl in _dig(mapping, "open.labels") or []:
        if not isinstance(tmpl, str):
            continue
        i = tmpl.find(ph)
        if i == -1:
            continue
        prefix = tmpl[:i]
        if "{" in prefix:
            return None
        return prefix or None
    return None


def signature_label(alert: dict[str, Any]) -> str | None:
    mapping = _load_mapping()
    signature = _signature_id(alert, mapping)
    labels = _render(_dig(mapping, "open.labels") or [], _ctx(signature=signature))
    prefix = _open_label_prefix(mapping, "signature")
    if prefix:
        for lbl in labels:
            if isinstance(lbl, str) and lbl.startswith(prefix):
                return lbl
    return labels[0] if labels else None


# --------------------------------------------------------------------------------------------
# D3 — the comment renderer and D1's mapping accessors
# --------------------------------------------------------------------------------------------

# Not a document's own fence: this strips an ATTACKER-PLANTED delimiter from free text (never
# required to start with a fence), the same reasoning the retired `_sanitize_ticket_reason`
# carried for the same regex. Tolerates LEADING WHITESPACE before the dashes — a fence
# indented by even one space is still a standalone `---` line by any reasonable reading of
# "standalone" (S4), and a narrower match here would let that one variant survive verbatim.
_FENCE_SPLIT = re.compile(r"(?m)^[ \t]*---")  # lint-frontmatter: ok — see comment above


def _resolve_comment_author(mapping: dict[str, Any]) -> str:
    """§7 R1/FAM-1: fail closed rather than send an unattributable comment."""
    section = mapping.get("comment")
    if not isinstance(section, dict):
        raise CaseTicketError(
            "case-history mapping has no `comment` section (comment.author/comment.body "
            "required)"
        )
    author = section.get("author")
    if not isinstance(author, str) or not author.strip():
        raise CaseTicketError("case-history mapping's `comment.author` is missing or empty")
    return author


def _resolve_comment_body_template(mapping: dict[str, Any]) -> str:
    section = mapping.get("comment")
    if not isinstance(section, dict):
        raise CaseTicketError(
            "case-history mapping has no `comment` section (comment.author/comment.body "
            "required)"
        )
    body = section.get("body")
    if not isinstance(body, str):
        raise CaseTicketError("case-history mapping's `comment.body` is missing")
    return body


def _strip_planted_fence(text: str) -> str:
    """Strip everything from the first line-anchored `---` onward (a planted frontmatter
    fence, second and later fences included — S4/`d_first_fence_wins`). Runs BEFORE the wire
    bound (§7 FK07: strip first, then bound) — a cut inside `---foo` can only ever yield
    `---…`, never a bare standalone fence. Applied to every free-text render slot
    (`cause` as well as `narrative`): `cause` is host-composed from a closed vocabulary today
    (c3) and never needs this in practice, but the guard is a property of the RENDERED SLOT,
    not an assumption about who is allowed to have populated it."""
    return _FENCE_SPLIT.split(text)[0].strip()


def _prepare_narrative(narrative: str) -> str:
    """`_strip_planted_fence`, then substitute the no-notes marker for an empty result — the
    narrative-only half of fence protection (the no-notes marker is `narrative`'s own)."""
    stripped = _strip_planted_fence(narrative)
    return stripped if stripped else NO_NOTES


def _bound_wire_bytes(text: str) -> str:
    """§7 R2/FK01: ONE bound, 4096 UTF-8 bytes, on the whole rendered body. The cut rounds DOWN
    to the last whole character and the ellipsis sits INSIDE the bound."""
    encoded = text.encode("utf-8")
    if len(encoded) <= WIRE_BOUND_BYTES:
        return text
    budget = WIRE_BOUND_BYTES - len(_ELLIPSIS.encode("utf-8"))
    cut = encoded[:budget].decode("utf-8", errors="ignore")
    return cut + _ELLIPSIS


def case_record_to_comment(rec: CaseRecord) -> dict[str, Any]:
    """D3 replaces `case_record_to_close`: `{author, body}` and nothing else (S1). `body` is
    the mapping's own `"{disposition} — {cause}\\n\\n{narrative}"` rendering, fence-stripped
    and bounded on the wire."""
    mapping = _load_mapping()
    author = _resolve_comment_author(mapping)
    body_template = _resolve_comment_body_template(mapping)
    narrative = _prepare_narrative(rec.narrative)
    ctx = _ctx(
        case_id=rec.case_id,
        signature=rec.signature_id,
        disposition=rec.disposition,
        cause=_strip_planted_fence(rec.cause),
        narrative=narrative,
    )
    try:
        rendered = body_template.format_map(ctx)
    except KeyError as e:
        raise CaseTicketError(
            f"case-history mapping's `comment.body` names a render key the context does not "
            f"carry: {e}"
        ) from e
    return {"author": author, "body": _bound_wire_bytes(rendered)}


def unreadable_comment_payload() -> dict[str, Any]:
    """The unreadable-report branch's outbound comment: still attributed (O3), but a fixed
    host sentence in place of a rendered narrative — never `(unreadable)` as an accidental
    literal, never the report's own (unparsable) text."""
    mapping = _load_mapping()
    author = _resolve_comment_author(mapping)
    return {"author": author, "body": UNREADABLE_COMMENT_BODY}


def escalation_comment_payload(truncated_by: str) -> dict[str, Any]:
    """The cut-short branch's outbound comment (#1047 O2): attributed like every other comment
    the host makes, a fixed host sentence naming the exit class, and no verdict — the case
    stays open for a person."""
    mapping = _load_mapping()
    author = _resolve_comment_author(mapping)
    return {"author": author, "body": ESCALATION_COMMENT_BODY.format(exit=truncated_by)}


# --------------------------------------------------------------------------------------------
# D4 — the release predicate, safe by construction (§7 R1)
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ReleasePredicate:
    """A case is RELEASED when a person has moved it to the mapping's `released.status` —
    the lifecycle state the vendor's own store enforces as a closed vocabulary. One question,
    asked of the ticket alone: the status is compared exactly (the store canonicalises it;
    nothing here trims, folds or tolerates), and an undecidable ticket — not an object, no
    string status — reads as UNRELEASED, the direction that serves nothing (FAM-1).

    There is deliberately no "who wrote this comment" predicate beside it. A comment's
    `author` is whatever the client that posted it chose to send, so a rule built on it was
    never sound; the screen serves an unreleased ticket's comments to nobody and a released
    ticket's comments whole, and the person's close is the one act that moves between them."""

    released_status: str

    def is_released(self, ticket: Any) -> bool:
        if not isinstance(ticket, dict):
            return False
        status = ticket.get("status")
        return isinstance(status, str) and status == self.released_status


def release_predicate() -> ReleasePredicate:
    """§7 R1's downstream consequence: the predicate is SAFE BY CONSTRUCTION — this raises in
    every unsafe mapping state rather than merely behaving correctly when configured right.
    The caller (the read screen) is what degrades on a raise; this function never does.

    The configured status is stripped ONCE, here, so a quoted YAML scalar with stray
    whitespace configures the same state the ticket carries rather than one nothing can ever
    reach."""
    mapping = _load_mapping()
    section = mapping.get("released")
    if not isinstance(section, dict):
        raise CaseTicketError(
            "case-history mapping has no `released` section (released.status required)"
        )
    status = section.get("status")
    if not isinstance(status, str) or not status.strip():
        raise CaseTicketError(
            "case-history mapping's `released.status` must be a non-empty string"
        )
    open_status = _dig(mapping, "open.status")
    if isinstance(open_status, str) and open_status.strip() == status.strip():
        raise CaseTicketError(
            f"case-history mapping's `open.status` and `released.status` are both "
            f"{status.strip()!r} — every case would open already released"
        )
    return ReleasePredicate(released_status=status.strip())


def is_released(ticket: Any) -> bool:
    return release_predicate().is_released(ticket)


# --------------------------------------------------------------------------------------------
# The seed-era helpers D5 deliberately leaves (RF1/g13) — no obligation here retires them.
# --------------------------------------------------------------------------------------------


def ticket_created(ticket: Any) -> str | None:
    return ticket.get("created") if isinstance(ticket, dict) else None


def ticket_event_time(ticket: Any) -> str | None:
    if not isinstance(ticket, dict):
        return None
    labels = ticket.get("labels")
    if not isinstance(labels, list):
        return None
    try:
        prefix = _open_label_prefix(_load_mapping(), "event_time")
    except CaseTicketError:
        return None
    if not prefix:
        return None
    for lbl in labels:
        if isinstance(lbl, str) and lbl.startswith(prefix):
            return lbl[len(prefix):] or None
    return None
