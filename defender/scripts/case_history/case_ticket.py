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
    "No disposition could be recorded for this case: report.md carried no parsable "
    "disposition to record."
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


def _label_template_can_render(template: str, approved_label: str) -> bool:
    """Is `template` a shape that could render down to what `is_approved` accepts?

    A property of the TEMPLATE, not of any alert (§7 R5/FAM-2): only the literal prefix before
    the FIRST placeholder can ever be pinned, so a template is safe iff `approved_label` cannot
    start with that prefix. The comparison is made against the same reading `is_approved`
    makes of a label — surrounding whitespace stripped (FK22) — so a prefix that is ONLY
    whitespace pins nothing, and a template with no literal prefix at all can render to
    anything."""
    idx = template.find("{")
    if idx == -1:
        return template.strip() == approved_label
    prefix = template[:idx].lstrip()
    if not prefix:
        return True
    return approved_label.startswith(prefix)


def _label_templates(section: dict[str, Any]) -> list[str]:
    """Every string template `section.labels` could ship: a list's string entries, or a bare
    string, which `_render` sends as one label just the same."""
    labels = section.get("labels")
    if isinstance(labels, str):
        return [labels]
    if isinstance(labels, list):
        return [t for t in labels if isinstance(t, str)]
    return []


def _refuse_colliding_approved_label(data: dict[str, Any]) -> None:
    """D1's loader refusal: walk every label-producing template under `open:` (and a stale
    `close:`'s, FK27) and refuse the whole mapping if any could render the approved label's
    exact spelling. Exhaustive over the section, not two named entries (FK26) — `open:` ships
    to the wire unfiltered (g7), so a guard pinned to two names guards a fixed subset."""
    approved = data.get("approved")
    if not isinstance(approved, dict):
        return
    label = approved.get("label")
    if not isinstance(label, str) or not label:
        return
    for section_name in ("open", "close"):
        section = data.get(section_name)
        if not isinstance(section, dict):
            continue
        for template in _label_templates(section):
            if _label_template_can_render(template, label):
                raise CaseTicketError(
                    f"case-history mapping's `{section_name}.labels` template {template!r} "
                    f"could render the approved label {label!r} — refusing to load a mapping "
                    "that could let an attacker-influenced field approve its own case"
                )


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
    _refuse_colliding_approved_label(data)
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
# D3 — the comment renderer, and D1's mapping accessors it shares with D4's predicates
# --------------------------------------------------------------------------------------------

# Not a document's own fence: this strips an ATTACKER-PLANTED delimiter from free text (never
# required to start with a fence), the same reasoning the retired `_sanitize_ticket_reason`
# carried for the same regex. Tolerates LEADING WHITESPACE before the dashes — a fence
# indented by even one space is still a standalone `---` line by any reasonable reading of
# "standalone" (S4), and a narrower match here would let that one variant survive verbatim.
_FENCE_SPLIT = re.compile(r"(?m)^[ \t]*---")  # lint-frontmatter: ok — see comment above


def _resolve_comment_author(mapping: dict[str, Any]) -> str:
    """§7 R1/FAM-1: fail closed rather than send an unattributable comment. Raised by both the
    writer's render path and D4's `approval_predicates` — the same section, the same refusal."""
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


# --------------------------------------------------------------------------------------------
# D4 — the approval screen's predicates, safe by construction (§7 R1)
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ApprovalPredicates:

    approved_label: str
    agent_identities: frozenset[str]

    def is_approved(self, ticket: Any) -> bool:
        if not isinstance(ticket, dict):
            return False
        labels = ticket.get("labels")
        if not isinstance(labels, list):
            return False
        return any(
            isinstance(lbl, str) and lbl.strip() == self.approved_label for lbl in labels
        )

    def is_agent_comment(self, comment: Any) -> bool:
        # FAM-1 (FK15): undecidable — not a dict, no author, or a non-string author — reads as
        # AGENT-AUTHORED, the protective direction. `is_agent_comment` is a POSITIVE match
        # against the identity set otherwise (FK23): a third identity (the stub's own `system`
        # transition stamp, a retired lane's `learning`) is NOT agent-authored.
        if not isinstance(comment, dict):
            return True
        author = comment.get("author")
        if not isinstance(author, str):
            return True
        return author in self.agent_identities

    def as_pair(self) -> tuple[Any, Any]:
        """The two predicates as a plain pair — O5's own demand: the caller (the query tool)
        reaches them without ever spelling the vendor tag's own literal in its own source."""
        return self.is_approved, self.is_agent_comment


def approval_predicates() -> ApprovalPredicates:
    """§7 R1's downstream consequence: the predicates are SAFE BY CONSTRUCTION — this raises
    in every unsafe mapping state (FK11-FK19) rather than merely behaving correctly when
    configured right. The caller (the read screen) is what degrades on a raise; this function
    never does."""
    mapping = _load_mapping()
    author = _resolve_comment_author(mapping)
    _resolve_comment_body_template(mapping)
    section = mapping.get("comment") or {}
    aliases = section.get("author_aliases")
    if aliases is not None and (
        not isinstance(aliases, list) or not all(isinstance(a, str) for a in aliases)
    ):
        raise CaseTicketError(
            "case-history mapping's `comment.author_aliases` must be a list of strings"
        )
    approved_section = mapping.get("approved")
    if not isinstance(approved_section, dict):
        raise CaseTicketError(
            "case-history mapping has no `approved` section (approved.label required)"
        )
    label = approved_section.get("label")
    if not isinstance(label, str) or not label:
        raise CaseTicketError(
            "case-history mapping's `approved.label` must be a non-empty string"
        )
    identities = frozenset({author, *(aliases or [])})
    return ApprovalPredicates(approved_label=label, agent_identities=identities)


def is_approved(ticket: Any) -> bool:
    return approval_predicates().is_approved(ticket)


def is_agent_comment(comment: Any) -> bool:
    return approval_predicates().is_agent_comment(comment)


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
