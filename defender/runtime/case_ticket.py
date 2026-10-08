from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

from defender._model import model
from defender._report import ReportUnreadable, require_report
from defender.run_repository import RunPaths
from defender.runtime.tenant_settings import pointer_to, read_regular_bytes
from defender._io import read_text_utf8


#: The mapping's path inside a tenant's `settings/` folder, which every reader is handed.
_MAPPING_RELPATH = "systems/case-history/mapping.yaml"

_SIGNATURE_FALLBACK = "unknown"
_SUMMARY_FALLBACK = "(no rule description)"

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


def _mapping_path(settings: Path) -> Path:
    return Path(settings) / _MAPPING_RELPATH


def _freeze(value: Any) -> Any:
    """A deep read-only view: mappings become `MappingProxyType`, lists become tuples."""
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, set):
        return frozenset(_freeze(v) for v in value)
    return value


def _thaw(value: Any) -> Any:
    """A fresh plain-data copy of a `_freeze`d value — what a consumer that edits works on."""
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    if isinstance(value, frozenset):
        return {_thaw(v) for v in value}
    return value


class CaseMapping(Mapping[str, Any]):
    """One tenant's `systems/case-history/mapping.yaml`, parsed and checked ONCE when the tenant
    is resolved and read-only from then on (O2): a consumer that edits what it builds from it
    works on its own copy (`plain`), and the next consumer sees the resolve-time content."""

    __slots__ = ("_data",)
    _data: Mapping[str, Any]

    def __init__(self, data: dict[str, Any]) -> None:
        object.__setattr__(self, "_data", _freeze(data))

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("CaseMapping is read-only")

    def plain(self) -> dict[str, Any]:
        """A fresh plain `dict` of the whole mapping — safe to edit."""
        return _thaw(self._data)


def load_case_mapping(settings: Path) -> CaseMapping:
    """The tenant's mapping file, parsed and lifecycle-checked, or `CaseTicketError`. @owns ticket_mapping

    Called once per run, by `run_tenant.resolve_run_tenant`; every consumer is handed the result
    and none reads the file."""
    path = _mapping_path(settings)
    shown = pointer_to(_MAPPING_RELPATH)
    try:
        raw = read_regular_bytes(path)
    except OSError as e:
        raise CaseTicketError(f"case-history mapping not readable: {shown}: {e.strerror}") from e
    import yaml

    from defender._yaml import safe_load

    try:
        data = safe_load(raw.decode("utf-8"))
    except UnicodeDecodeError as e:
        raise CaseTicketError(f"case-history mapping {path} is not UTF-8: {e}") from e
    except yaml.YAMLError as e:
        raise CaseTicketError(f"case-history mapping {path} is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise CaseTicketError(f"case-history mapping is not a mapping: {shown}")
    _check_lifecycle(data)
    return CaseMapping(data)


def _thawed(mapping: CaseMapping | CaseTicketError) -> dict[str, Any]:
    """The mapping as a fresh plain dict, or the kept error re-raised (a new instance, so the
    record's own error is never handed a second traceback)."""
    if isinstance(mapping, CaseTicketError):
        raise CaseTicketError(str(mapping)) from None
    return mapping.plain()


def check_mapping(settings: Path) -> None:
    """The tenant's case-history mapping parses and keeps its lifecycle invariant, or
    `CaseTicketError` naming it — `tenant.py setup`'s settings-parse rule, since no run reads
    the mapping before its post-run ticket write.

    An operator command on the host, so the refusal names the file's own path: the loader
    names some faults only by their place in the tenant's folder, because its message can
    reach a run's record."""
    try:
        load_case_mapping(settings)
    except CaseTicketError as bad:
        path = str(_mapping_path(settings))
        if path in str(bad):
            raise
        raise CaseTicketError(f"{path}: {bad}") from bad


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


def alert_event_time(alert: dict[str, Any], *, mapping: CaseMapping | CaseTicketError) -> str | None:
    return _event_time(alert, _thawed(mapping)) or None


def read_case_record(run_dir: Path, *, mapping: CaseMapping | CaseTicketError) -> CaseRecord:
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

    plain = _thawed(mapping)
    signature_id = _SIGNATURE_FALLBACK
    alert_path = RunPaths(run_dir).alert
    if alert_path.is_file():
        with contextlib.suppress(json.JSONDecodeError, OSError):
            signature_id = _signature_id(json.loads(read_text_utf8(alert_path)), plain)

    return CaseRecord(
        case_id=case_id,
        signature_id=signature_id,
        disposition=disposition,
        cause=cause,
        narrative=body,
    )


def alert_to_open_payload(
    alert: dict[str, Any], case_id: str, *, mapping: CaseMapping | CaseTicketError,
) -> dict[str, Any]:
    plain = _thawed(mapping)
    signature = _signature_id(alert, plain)
    summary = _dig(alert, str(_dig(plain, "source.summary") or "rule.description"))
    ctx = _ctx(
        case_id=case_id,
        signature=signature,
        summary=str(summary) if summary else _SUMMARY_FALLBACK,
        event_time=_event_time(alert, plain),
    )
    payload = _render(plain.get("open") or {}, ctx)
    if isinstance(payload.get("labels"), list):
        bare = {p for p in _open_label_prefixes(plain) if p}
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


def signature_label(alert: dict[str, Any], *, mapping: CaseMapping | CaseTicketError) -> str | None:
    plain = _thawed(mapping)
    signature = _signature_id(alert, plain)
    labels = _render(_dig(plain, "open.labels") or [], _ctx(signature=signature),
                     "open.labels")
    prefix = _open_label_prefix(plain, "signature")
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


def _host_comment(body: str, mapping: CaseMapping | CaseTicketError) -> dict[str, Any]:
    """A comment whose body is a FIXED host sentence — attributed like every other comment the
    host makes, with nothing rendered into it."""
    return {"author": _resolve_comment_author(_thawed(mapping)), "body": body}


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


def case_record_to_comment(
    rec: CaseRecord, *, mapping: CaseMapping | CaseTicketError,
) -> dict[str, Any]:
    """D3 replaces `case_record_to_close`: `{author, body}` and nothing else (S1). `body` is
    the mapping's own `"{disposition} — {cause}\\n\\n{narrative}"` rendering, fence-stripped.
    The wire bound is applied once, to the posted body with its tag (`posted_comment`)."""
    plain = _thawed(mapping)
    author = _resolve_comment_author(plain)
    body_template = _resolve_comment_body_template(plain)
    narrative = _prepare_narrative(rec.narrative)
    ctx = _ctx(
        case_id=rec.case_id,
        signature=rec.signature_id,
        disposition=rec.disposition,
        cause=_strip_planted_fence(rec.cause),
        narrative=narrative,
    )
    rendered = _format(body_template, ctx, "comment.body")
    return {"author": author, "body": rendered}


def agent_comment_tag(run_id: str) -> str:
    """The tag line naming the run that wrote a comment: `AGENT_TAG_PREFIX`, the run id, `]`."""
    return f"{AGENT_TAG_PREFIX}{run_id}]"


def posted_comment(payload: Mapping[str, Any], *, run_id: str) -> dict[str, Any]:
    """@owns comment body — the body as it reaches the store: the agent tag line naming
    `run_id`, then the comment the mapping rendered, the whole bounded to `WIRE_BOUND_BYTES`.
    The bound cuts from the end, so the tag line always survives it. `run_id` is the run's, not
    the case key, which on the platform is the vendor's ticket id."""
    body = f"{agent_comment_tag(run_id)}\n{payload['body']}"
    return {**payload, "body": _bound_wire_bytes(body)}


def unreadable_comment_payload(*, mapping: CaseMapping | CaseTicketError) -> dict[str, Any]:
    """The unreadable-report branch's outbound comment: still attributed (O3), but a fixed
    host sentence in place of a rendered narrative — never `(unreadable)` as an accidental
    literal, never the report's own (unparsable) text."""
    return _host_comment(UNREADABLE_COMMENT_BODY, mapping)


def escalation_comment_payload(
    truncated_by: str, *, mapping: CaseMapping | CaseTicketError,
) -> dict[str, Any]:
    """The cut-short branch's outbound comment (#1047 O2): attributed like every other comment
    the host makes, a fixed host sentence naming the exit class, and no verdict — the case
    stays open for a person."""
    return _host_comment(ESCALATION_COMMENT_BODY.format(exit=truncated_by), mapping)


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


def release_predicate(mapping: CaseMapping | CaseTicketError) -> ReleasePredicate:
    """§7 R1's downstream consequence: the predicate is SAFE BY CONSTRUCTION — this raises in
    every unsafe mapping state rather than merely behaving correctly when configured right.
    The caller (the writer's released check) is what degrades on a raise; this function never
    does.

    The configured status is stripped ONCE, here, so a quoted YAML scalar with stray
    whitespace configures the same state the ticket carries rather than one nothing can ever
    reach.

    `mapping` is the record's `ticket_mapping` (#1107), handed in by the caller, which already
    holds the record and never reads the file. Since #1221 the writer is its only caller: no read
    path screens a ticket by its status."""
    section = _thawed(mapping).get("released")
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


def is_released(ticket: Any, *, mapping: CaseMapping | CaseTicketError) -> bool:
    return release_predicate(mapping).is_released(ticket)


# --------------------------------------------------------------------------------------------
# Ticket field helpers
# --------------------------------------------------------------------------------------------


def ticket_created(ticket: Any) -> str | None:
    return ticket.get("created") if isinstance(ticket, dict) else None


def ticket_event_time(ticket: Any, *, mapping: CaseMapping | CaseTicketError) -> str | None:
    if not isinstance(ticket, dict):
        return None
    labels = ticket.get("labels")
    if not isinstance(labels, list):
        return None
    try:
        prefix = _open_label_prefix(_thawed(mapping), "event_time")
    except CaseTicketError:
        return None
    if not prefix:
        return None
    for lbl in labels:
        if isinstance(lbl, str) and lbl.startswith(prefix):
            return lbl[len(prefix):] or None
    return None
