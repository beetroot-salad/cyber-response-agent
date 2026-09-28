#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import copy
import json
import re
from pathlib import Path
from typing import Any

from defender._model import model
from defender._report import ReportUnreadable, require_report
from defender._run_paths import RunPaths


#: The mapping's path inside a tenant's `settings/` folder, which every reader is handed.
_MAPPING_RELPATH = "systems/case-history/mapping.yaml"

_SIGNATURE_FALLBACK = "unknown"
_SUMMARY_FALLBACK = "(no rule description)"

#: The one bound on the rendered comment body, in UTF-8 bytes. The cut rounds down to a whole
#: character and the ellipsis fits inside the bound.
WIRE_BOUND_BYTES = 4096
_ELLIPSIS = "…"

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
    "unreachable or the investigation could not complete automatically. Escalate for manual "
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
    #: The report's body, verbatim — fence-stripping and the wire bound are applied at render
    #: time (`case_record_to_comment`), never here.
    narrative: str


def _mapping_path(settings_dir: Path) -> Path:
    return Path(settings_dir) / _MAPPING_RELPATH


#: One parsed mapping per (path, bytes). Read on every call so operator edits take effect,
#: but parsed and validated only when the bytes change.
_MAPPING_CACHE: dict[Path, tuple[bytes, dict[str, Any]]] = {}


def _load_mapping(settings_dir: Path) -> dict[str, Any]:
    path = _mapping_path(settings_dir)
    if not path.is_file():
        raise CaseTicketError(f"case-history mapping not found: {path}")
    raw = path.read_bytes()
    cached = _MAPPING_CACHE.get(path)
    if cached is not None and cached[0] == raw:
        return copy.deepcopy(cached[1])
    import yaml

    from defender._yaml import safe_load

    try:
        data = safe_load(raw.decode("utf-8"))
    except UnicodeDecodeError as e:
        raise CaseTicketError(f"case-history mapping is not UTF-8: {e}") from e
    except yaml.YAMLError as e:
        raise CaseTicketError(f"case-history mapping is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise CaseTicketError(f"case-history mapping is not a mapping: {path}")
    _check_lifecycle(data)
    _MAPPING_CACHE[path] = (raw, data)
    return copy.deepcopy(data)


def _check_lifecycle(mapping: dict[str, Any]) -> None:
    """The invariant the gate rests on, checked in the loader so every reader gets it: nothing
    the host writes may put a case into the released state. `open.status` must be a literal (a
    `{placeholder}` would let alert text pick the status) and must differ from
    `released.status` (cases would open already released). Each is checked only when present;
    section presence is each consumer's concern."""
    open_status = _dig(mapping, "open.status")
    if open_status is not None and (not isinstance(open_status, str) or not open_status.strip()):
        raise CaseTicketError("case-history mapping's `open.status` must be a non-empty string")
    if isinstance(open_status, str) and "{" in open_status:
        raise CaseTicketError(
            f"case-history mapping's `open.status` must be a literal, not a template: "
            f"{open_status!r} — nothing rendered from an alert may move a case along its "
            "lifecycle"
        )
    released_status = _dig(mapping, "released.status")
    if (isinstance(open_status, str) and isinstance(released_status, str)
            and open_status.strip() == released_status.strip()):
        raise CaseTicketError(
            f"case-history mapping's `open.status` and `released.status` are both "
            f"{released_status.strip()!r} — every case would open already released"
        )


def _dig(obj: Any, dotted: str) -> Any:
    cur = obj
    for key in dotted.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _format(template: str, ctx: dict[str, str], where: str) -> str:
    """`str.format_map`, with every bad-template fault folded into `CaseTicketError` so a
    broken operator mapping refuses with a receipt like any other mapping fault."""
    try:
        return template.format_map(ctx)
    except KeyError as e:
        raise CaseTicketError(
            f"case-history mapping's `{where}` names a render key the context does not "
            f"carry: {e}"
        ) from e
    except (ValueError, IndexError, AttributeError, TypeError) as e:
        raise CaseTicketError(
            f"case-history mapping's `{where}` is not a valid template: {e}"
        ) from e


def _render(value: Any, ctx: dict[str, str], where: str = "open") -> Any:
    if isinstance(value, str):
        return _format(value, ctx, where)
    if isinstance(value, list):
        return [_render(v, ctx, where) for v in value]
    if isinstance(value, dict):
        return {k: _render(v, ctx, f"{where}.{k}") for k, v in value.items()}
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


def alert_event_time(alert: dict[str, Any], *, settings_dir: Path) -> str | None:
    return _event_time(alert, _load_mapping(settings_dir)) or None


def read_case_record(run_dir: Path, *, settings_dir: Path) -> CaseRecord:
    # An unreadable headline must take the unreadable branch, since the bridge writes to a
    # real ticket system from this record. Classified from `require_report`'s own refusal.
    try:
        report = require_report(RunPaths(run_dir).report)
    except ReportUnreadable as e:
        raise ReportNotParsable(str(e)) from e
    fm, body, disposition = report.frontmatter, report.body, report.disposition
    case_id = run_dir.name
    cause = str(fm.get("cause") or "")

    mapping = _load_mapping(settings_dir)
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


def alert_to_open_payload(
    alert: dict[str, Any], case_id: str, *, settings_dir: Path,
) -> dict[str, Any]:
    mapping = _load_mapping(settings_dir)
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


def signature_label(alert: dict[str, Any], *, settings_dir: Path) -> str | None:
    mapping = _load_mapping(settings_dir)
    signature = _signature_id(alert, mapping)
    labels = _render(_dig(mapping, "open.labels") or [], _ctx(signature=signature),
                     "open.labels")
    prefix = _open_label_prefix(mapping, "signature")
    if prefix:
        for lbl in labels:
            if isinstance(lbl, str) and lbl.startswith(prefix):
                return lbl
    return labels[0] if labels else None


# --------------------------------------------------------------------------------------------
# The comment renderer and the mapping accessors
# --------------------------------------------------------------------------------------------

# Strips an attacker-planted frontmatter delimiter from free text. Only a standalone `---`
# line counts (indentation allowed); `----` rules and `--- | ---` table rows survive. Line
# breaks are normalised first (`_LINE_BREAKS`), since a UI may break on `\r` or U+2028.
_FENCE_SPLIT = re.compile(r"(?m)^[ \t]*---[ \t]*$")  # lint-frontmatter: ok — strips a planted delimiter from free text, not a frontmatter parse
_LINE_BREAKS = re.compile("\r\n|\r|\u2028|\u2029|\x85|\x0b|\x0c")


def _comment_section(mapping: dict[str, Any]) -> dict[str, Any]:
    section = mapping.get("comment")
    if not isinstance(section, dict):
        raise CaseTicketError(
            "case-history mapping has no `comment` section (comment.author/comment.body "
            "required)"
        )
    return section


def _resolve_comment_author(mapping: dict[str, Any]) -> str:
    """Fail closed rather than send an unattributable comment. Stripped, like
    `released.status`."""
    author = _comment_section(mapping).get("author")
    if not isinstance(author, str) or not author.strip():
        raise CaseTicketError("case-history mapping's `comment.author` is missing or empty")
    return author.strip()


def _resolve_comment_body_template(mapping: dict[str, Any]) -> str:
    body = _comment_section(mapping).get("body")
    if not isinstance(body, str) or not body.strip():
        raise CaseTicketError("case-history mapping's `comment.body` is missing or empty")
    return body


def _host_comment(body: str, settings_dir: Path) -> dict[str, Any]:
    """An attributed comment whose body is a fixed host sentence, nothing rendered into it."""
    return {"author": _resolve_comment_author(_load_mapping(settings_dir)), "body": body}


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
    """Bound the whole rendered body to `WIRE_BOUND_BYTES`, cutting at a whole character with
    the ellipsis inside the bound."""
    encoded = text.encode("utf-8")
    if len(encoded) <= WIRE_BOUND_BYTES:
        return text
    budget = WIRE_BOUND_BYTES - len(_ELLIPSIS.encode("utf-8"))
    cut = encoded[:budget].decode("utf-8", errors="ignore")
    return cut + _ELLIPSIS


def case_record_to_comment(rec: CaseRecord, *, settings_dir: Path) -> dict[str, Any]:
    """`{author, body}` and nothing else. `body` is the mapping's rendering (e.g.
    `"{disposition} — {cause}\\n\\n{narrative}"`), fence-stripped and bounded."""
    mapping = _load_mapping(settings_dir)
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
    rendered = _format(body_template, ctx, "comment.body")
    return {"author": author, "body": _bound_wire_bytes(rendered)}


def unreadable_comment_payload(*, settings_dir: Path) -> dict[str, Any]:
    """The unreadable-report branch's comment: attributed, with a fixed host sentence rather
    than the report's own text."""
    return _host_comment(UNREADABLE_COMMENT_BODY, settings_dir)


def escalation_comment_payload(truncated_by: str, *, settings_dir: Path) -> dict[str, Any]:
    """The cut-short branch's comment: attributed, a fixed sentence naming the exit class, no
    verdict — the case stays open for a person."""
    return _host_comment(ESCALATION_COMMENT_BODY.format(exit=truncated_by), settings_dir)


# --------------------------------------------------------------------------------------------
# The release predicate
# --------------------------------------------------------------------------------------------


@model(frozen=True)
class ReleasePredicate:
    """A case is released when a person has moved it to the mapping's `released.status`.
    Compared exactly (the store canonicalises it); an undecidable ticket reads as unreleased,
    the direction that serves nothing.

    There is no "who wrote this comment" predicate: a comment's `author` is whatever the
    posting client sent. Unreleased tickets' comments are served to nobody, released ones'
    whole."""

    released_status: str

    def is_released(self, ticket: Any) -> bool:
        if not isinstance(ticket, dict):
            return False
        status = ticket.get("status")
        return isinstance(status, str) and status == self.released_status


def release_predicate(settings_dir: Path) -> ReleasePredicate:
    """The release predicate, safe by construction: raises in every unsafe mapping state (the
    read screen degrades on the raise). The status is stripped once here so stray whitespace
    in a quoted scalar still matches."""
    mapping = _load_mapping(settings_dir)
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
    # The open/released collision and literal-status rules live in `_check_lifecycle`.
    return ReleasePredicate(released_status=status.strip())


def is_released(ticket: Any, *, settings_dir: Path) -> bool:
    return release_predicate(settings_dir).is_released(ticket)


# --------------------------------------------------------------------------------------------
# Ticket field helpers
# --------------------------------------------------------------------------------------------


def ticket_created(ticket: Any) -> str | None:
    return ticket.get("created") if isinstance(ticket, dict) else None


def ticket_event_time(ticket: Any, *, settings_dir: Path) -> str | None:
    if not isinstance(ticket, dict):
        return None
    labels = ticket.get("labels")
    if not isinstance(labels, list):
        return None
    try:
        prefix = _open_label_prefix(_load_mapping(settings_dir), "event_time")
    except CaseTicketError:
        return None
    if not prefix:
        return None
    for lbl in labels:
        if isinstance(lbl, str) and lbl.startswith(prefix):
            return lbl[len(prefix):] or None
    return None
