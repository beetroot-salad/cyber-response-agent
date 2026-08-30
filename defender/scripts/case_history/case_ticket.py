#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._vocab import DISPOSITION_VALUES, HOST_ONLY_DISPOSITION, normalized_disposition
from defender._report import ReportUnreadable, require_report
from defender._run_paths import RunPaths

_SEED_ELIGIBLE_OUTCOMES = {"caught", "skip-passthrough"}

_MAPPING_RELPATH = "knowledge/environment/systems/case-history/mapping.yaml"

_SIGNATURE_FALLBACK = "unknown"
_SUMMARY_FALLBACK = "(no rule description)"
_CONFIDENCE_FALLBACK = "n/a"

#: The bound on `CaseRecord.reason` once it leaves the process through the ticket bridge's
#: outbound `resolution` — a field a PERSON and the judge model both read back. #923 makes
#: `inconclusive`'s `ceiling_test` rows mandatory on every priced close (not just the two
#: fixture documents that used to carry one), so model-authored text reaches this lane
#: routinely rather than rarely.
#: Held WELL under 512: `reason` does not render alone — `close.resolution`'s template
#: (`mapping.yaml`) is `"{disposition} — {reason}"`, and the bound this demand pins is on the
#: RENDERED resolution field on the wire, not on this input in isolation. The longest
#: disposition (`false-positive`) plus its separator is 17 characters; 40 leaves a wide margin.
_TICKET_REASON_MAX = 512 - 40


def _sanitize_ticket_reason(text: str) -> str:
    """Strip injection-shaped structure from a reason before it leaves the process, and bound
    its length — by TRUNCATION, never substitution, so a long claim is visibly cut rather than
    silently swapped for a host placeholder that tells nobody what was not retrieved.

    Only the frontmatter delimiter is stripped, structurally: everything from the first
    standalone `---` onward is dropped, which removes a spoofed second frontmatter block (a
    fabricated `disposition:`/`cause:` pair) and whatever text rides after it (an injected
    instruction, in the one case observed) in one cut — a model-authored row cannot open a
    second delimited block in a field that already left one. The legitimate half of the row,
    which comes BEFORE any such attempt, survives untouched; a sanitizer that instead deleted
    or replaced the whole reason would satisfy every negative here while telling the analyst
    and the judge model nothing about the actual gap (#923, J29).

    A LINE-ANCHORED match, not `split("\n---")`: the report BODY this falls back to is
    everything after the document's own closing fence, so a planted block can be the very
    FIRST thing in it and then carries no preceding newline. Splitting on `"\n---"` left
    exactly that spelling — `---\ndisposition: malicious\n---\n<instruction>` — with its
    fence and its spoofed verdict intact on the wire."""
    # Not parsing a document's OWN frontmatter: this text is a `reason` field's contents, never
    # required to start with `---\n`, so `_frontmatter.split_frontmatter` does not apply — it
    # demands a leading fence and raises without one. This looks for an ATTACKER-PLANTED
    # delimiter anywhere in the string, a different question with a different answer.
    cleaned = re.split(r"(?m)^---", text)[0].strip()  # lint-frontmatter: ok — not a document's own fence, see above
    if len(cleaned) > _TICKET_REASON_MAX:
        cleaned = cleaned[: _TICKET_REASON_MAX - 1].rstrip() + "…"
    return cleaned


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
    # stop it. Re-raise the shared accessor's refusal (text unchanged) as this lane's error
    # type, which is what every caller here catches.
    try:
        report = require_report(RunPaths(run_dir).report)
    except ReportUnreadable as e:
        raise CaseTicketError(str(e)) from e
    fm, body, disposition = report.frontmatter, report.body, report.disposition
    case_id = run_dir.name
    confidence = str(fm.get("confidence") or "")
    # The reason is `cause` when the report carries one, and the body otherwise.
    #
    # The close gate host-renders the body from a closed vocabulary, so it is the SAME sentence
    # on every close ("Disposition recorded by the close gate. outcome=…"). Using it as the
    # reason hands a constant to three consumers: the judge's prompt, the outbound ticket
    # comment, and — worst — the closed-ticket pool the challenge gate samples for base rates,
    # where this close's own boilerplate comes back as evidence about prior closes. `cause` is
    # the host's typed sentence for the disposition and has exactly one home, the frontmatter.
    # Reports with no `cause` (anything the close gate did not write) keep the body verbatim.
    #
    # #923 §7 round 4's receipt redesign moved the gap CLAIM itself: `ceiling_test` in the
    # frontmatter is now `ref`/`state`/`cap` alone — a closed vocabulary plus an id, host-
    # verified, never free text — and the model's human-facing NOTE for each receipt is
    # rendered into the BODY by `close_tool.render_report`. So for a priced `inconclusive`
    # close with no `cause`, the body ALREADY carries the gap claim; no second lookup into
    # `ceiling_test` is needed (or even meaningful — that key no longer holds prose).
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
        confidence=confidence,
        reason=_sanitize_ticket_reason(cause or body),
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
    head, _, tail = resolution.partition(sep)
    head = head.strip()
    # The resolution line is analyst-editable and read back by the benign judge, so decode it
    # through the shared vocabulary — same answer the report and the investigation give.
    decoded = normalized_disposition(head)
    # #923: the THIRD authoring surface the host-only verdict is refused at — the close tool's
    # argument and the invlang document's `conclude.disposition` are the other two. This
    # decoder made a host-owned verdict analyst-writable: before this refusal, a person typing
    # `unresolved` into a ticket's resolution field decoded cleanly and indistinguishably from
    # a host-forced close. Written FOR A PERSON — the field they edited, and what it may say
    # instead — since this is the one surface whose author is neither the host nor a model.
    #
    # The host's OWN egress round-trips through this same function
    # (`case_record_to_close` -> `{disposition} — {reason}`, decoded straight back by
    # `ticket_disposition`), and its `reason` is one of the closed `REPORT_CAUSES` sentences
    # whenever the report carries a `cause` — which every host-terminated close does. So the
    # refusal fires only when the tail is NOT one of those sentences: the host's own resolution
    # decodes cleanly, and a person's hand-typed tail (which cannot coincide with a
    # closed host sentence except by deliberately copying one) is refused.
    if decoded == HOST_ONLY_DISPOSITION:
        from defender.runtime.close_tool import REPORT_CAUSES

        # `startswith`, not equality: the host's own resolution is APPENDED to in this very
        # module (`append_resolution_method` stamps ` [grounded: …]` onto it after the
        # adversarial leg settles), and an analyst may add a note after the host's sentence.
        # Under equality any such suffix made the host's own verdict undecodable — the ticket
        # then falls out of every disposition-keyed pool through `ticket_disposition`'s
        # degrade-to-`None`. What the refusal keys on is that the reason clause BEGINS with a
        # closed host sentence, which a hand-typed one still cannot without copying it.
        if not any(tail.strip().startswith(cause) for cause in REPORT_CAUSES):
            # Derived from the vocabulary, never re-spelled: this list is exactly "the members
            # a person MAY write", and a sixth member added at the owner has to reach the
            # analyst being told what to write instead.
            others = ", ".join(d for d in DISPOSITION_VALUES if d != HOST_ONLY_DISPOSITION)
            raise CaseTicketError(
                f"the case `resolution` field cannot record {decoded!r} — that verdict is "
                f"written by the host, not by a person closing a ticket. Record one of "
                f"{others} in `resolution` instead, or leave the disposition off it for the "
                f"host to fill in."
            )
    return decoded




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
    """The READ side of `parse_disposition_from_resolution`, degrading rather than raising.

    #923: that decoder now refuses a person's hand-typed host-only verdict (`CaseTicketError`)
    — a refusal written for the AUTHORING surface, an analyst editing one field. This is a
    different lane: a walk over every closed ticket a person could have edited (the benign seed
    sampler, in particular), where one ticket's decode fault must cost that ticket and not the
    whole pool — the same "one broken record degrades, it does not crash the walk" rule
    `_report.read_report` applies to a malformed `report.md`. `None` here reads exactly like
    any other undecodable resolution; the refusal itself still reaches whoever calls the
    decoder directly to author or validate one ticket."""
    if not isinstance(ticket, dict):
        return None
    try:
        return parse_disposition_from_resolution(ticket.get("resolution"))
    except CaseTicketError:
        return None


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
