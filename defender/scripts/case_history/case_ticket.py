#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._frontmatter import FrontmatterError, parse_frontmatter
from defender._run_paths import RunPaths

DISPOSITION_ENUM = {"benign", "inconclusive", "malicious"}

_SEED_ELIGIBLE_OUTCOMES = {"caught", "skip-passthrough"}

_MAPPING_RELPATH = "knowledge/environment/systems/case-history/mapping.yaml"

_SIGNATURE_FALLBACK = "unknown"
_SUMMARY_FALLBACK = "(no rule description)"
_CONFIDENCE_FALLBACK = "n/a"


class CaseTicketError(Exception):
    pass


@dataclass(frozen=True)
class CaseRecord:

    case_id: str
    signature_id: str
    disposition: str
    confidence: str
    reason: str




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
                            "reason", "confidence", "outcome", "seed_eligible",
                            "event_time")}
    base.update(kw)
    return base




def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    try:
        return parse_frontmatter(text)
    except FrontmatterError as e:
        raise CaseTicketError(f"report.md {e}") from e


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
    report = RunPaths(run_dir).report
    if not report.is_file():
        raise CaseTicketError(f"report.md not found: {report}")
    fm, body = _parse_frontmatter(report.read_text(encoding="utf-8"))

    disposition = fm.get("disposition")
    if disposition not in DISPOSITION_ENUM:
        raise CaseTicketError(
            f"report.md disposition={disposition!r} not in {sorted(DISPOSITION_ENUM)}"
        )
    case_id = run_dir.name
    confidence = str(fm.get("confidence") or "")

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
        confidence=confidence,
        reason=body,
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


def case_record_to_close(rec: CaseRecord) -> dict[str, Any]:
    mapping = _load_mapping()
    ctx = _ctx(
        case_id=rec.case_id,
        signature=rec.signature_id,
        disposition=rec.disposition,
        reason=rec.reason,
        confidence=rec.confidence or _CONFIDENCE_FALLBACK,
    )
    return _render(mapping.get("close") or {}, ctx)


def _disposition_separator(mapping: dict[str, Any]) -> str | None:
    tmpl = _dig(mapping, "close.resolution")
    if not isinstance(tmpl, str):
        return None
    marker = "{disposition}"
    i = tmpl.find(marker)
    if i != 0:
        return None
    rest = tmpl[len(marker):]
    nxt = rest.find("{")
    sep = rest[:nxt] if nxt != -1 else rest
    return sep or None


def parse_disposition_from_resolution(resolution: str | None) -> str | None:
    if not resolution:
        return None
    try:
        sep = _disposition_separator(_load_mapping())
    except CaseTicketError:
        return None
    if not sep:
        return None
    head = resolution.split(sep, 1)[0].strip()
    return head if head in DISPOSITION_ENUM else None




def outcome_seeds_eligible(outcome: str) -> bool:
    return outcome in _SEED_ELIGIBLE_OUTCOMES


def enrichment_to_comment(outcome: str) -> dict[str, Any]:
    mapping = _load_mapping()
    eligible = outcome_seeds_eligible(outcome)
    ctx = _ctx(outcome=outcome, seed_eligible="true" if eligible else "false")
    return _render(mapping.get("annotate") or {}, ctx)


def _seed_marker_and_separator(mapping: dict[str, Any]) -> tuple[str | None, str | None]:
    tmpl = _dig(mapping, "annotate.body")
    if not isinstance(tmpl, str):
        return None, None
    ph = "{seed_eligible}"
    i = tmpl.find(ph)
    if i == -1:
        return None, None
    marker = tmpl[:i]
    if "{" in marker:
        return None, None
    rest = tmpl[i + len(ph):]
    nxt = rest.find("{")
    sep = rest[:nxt] if nxt != -1 else rest
    return (marker or None), (sep or None)


def parse_survival_from_comments(comments: Any) -> bool | None:
    try:
        marker, sep = _seed_marker_and_separator(_load_mapping())
    except CaseTicketError:
        return None
    if not marker:
        return None
    result: bool | None = None
    for c in comments or []:
        body = c.get("body") if isinstance(c, dict) else None
        if not isinstance(body, str) or not body.startswith(marker):
            continue
        tail = body[len(marker):]
        token = (tail.split(sep, 1)[0] if sep else tail).strip()
        if token == "true":
            result = True
        elif token == "false":
            result = False
    return result




def _resolution_method_marker(mapping: dict[str, Any]) -> tuple[str | None, str | None]:
    tmpl = _dig(mapping, "enrich.resolution_method_suffix")
    if not isinstance(tmpl, str):
        return None, None
    ph = "{resolution_method}"
    i = tmpl.find(ph)
    if i == -1:
        return None, None
    marker = tmpl[:i]
    if "{" in marker:
        return None, None
    rest = tmpl[i + len(ph):]
    nxt = rest.find("{")
    sep = rest[:nxt] if nxt != -1 else rest
    return (marker or None), (sep or None)


def append_resolution_method(resolution: str, method: str) -> str:
    if not resolution or not method or not method.strip():
        return resolution
    try:
        marker, sep = _resolution_method_marker(_load_mapping())
    except CaseTicketError:
        return resolution
    if not marker or resolution_method_from_resolution(resolution) is not None:
        return resolution
    method = " ".join(method.split())
    return f"{resolution}{marker}{method}{sep or ''}"


def resolution_method_from_resolution(resolution: str | None) -> str | None:
    if not resolution:
        return None
    try:
        marker, sep = _resolution_method_marker(_load_mapping())
    except CaseTicketError:
        return None
    if not marker or marker not in resolution:
        return None
    if sep and not resolution.endswith(sep):
        return None
    tail = resolution.rsplit(marker, 1)[1]
    seg = tail.rsplit(sep, 1)[0] if sep and sep in tail else tail
    return seg.strip() or None




def ticket_key(ticket: Any) -> str | None:
    return ticket.get("key") if isinstance(ticket, dict) else None


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


def ticket_disposition(ticket: Any) -> str | None:
    if not isinstance(ticket, dict):
        return None
    return parse_disposition_from_resolution(ticket.get("resolution"))


def ticket_reason(ticket: Any) -> str | None:
    if not isinstance(ticket, dict):
        return None
    resolution = ticket.get("resolution")
    if not isinstance(resolution, str):
        return None
    try:
        mapping = _load_mapping()
        sep = _disposition_separator(mapping)
    except CaseTicketError:
        return None
    if not sep or sep not in resolution:
        return None
    tail = resolution.split(sep, 1)[1]
    marker, msep = _resolution_method_marker(mapping)
    if marker and marker in tail and (not msep or resolution.endswith(msep)):
        tail = tail.rsplit(marker, 1)[0]
    return tail.strip() or None


def ticket_resolution_method(ticket: Any) -> str | None:
    if not isinstance(ticket, dict):
        return None
    return resolution_method_from_resolution(ticket.get("resolution"))


def ticket_seed_eligible(ticket: Any) -> bool | None:
    if not isinstance(ticket, dict):
        return None
    return parse_survival_from_comments(ticket.get("comments"))
