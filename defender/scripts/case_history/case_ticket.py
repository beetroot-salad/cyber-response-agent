#!/usr/bin/env python3
"""Case-history ticket mapper — the anti-corruption layer (issue #317, write path).

The defender's *internal* model of a case is `report.md` (+ `alert.json`); the
*external* model is the ticket-server's frozen v1 schema. These are two separate
models, and this module is the **only** code that knows both: it parses the internal
artifacts into a `CaseRecord` and maps that to/from external ticket payloads.

The mapping itself — which internal facts land in which ticket fields, the label and
resolution conventions — is **configuration, not code**: it lives in
`knowledge/environment/systems/case-history/mapping.yaml` and is rendered here.
Change the convention by editing that file; no code change required. Keeping the
translation in one module + one config means the drivers, the report schema, and
(PR 2) the learning reader never bind to ticket field names — when the store changes
(e.g. Elastic Cases), only this module, the transport, and the mapping move.

Pure by construction: no network, no transport import. `read_case_record` /
`_load_mapping` do file reads only. The I/O — posting payloads, the run-dir
receipt — lives in `ticket_writer.py`, which imports this module.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Mirrors defender.learning._loop_config.DISPOSITION_ENUM. Defined locally so the
# write path carries no `defender.learning` import (the runtime/learning decoupling
# goal of #317); test_case_ticket asserts the two stay in sync.
DISPOSITION_ENUM = {"benign", "inconclusive", "malicious"}

# The adversarial-probe outcomes (defender.learning._loop_config.OUTCOME_ENUM) that
# make a benign-disposed case a SAFE cover-story seed. Polarity is load-bearing: the
# benign case ran the *adversarial* leg (hunt the missed attack), so `survived` means
# the attack got through = the defender MISSED it = a poisonous seed → excluded. Only
# a `caught` (actuals refuted the attack) or `skip-passthrough` (no coherent attack
# to even try) marks the benign call trustworthy. `undecidable`/`incoherent` do not
# qualify. This decision is applied once here, at write time, and stored as the
# {seed_eligible} boolean; the reader never re-derives it. The local copy keeps the
# write path free of a `defender.learning` import — test_case_ticket guards the subset.
_SEED_ELIGIBLE_OUTCOMES = {"caught", "skip-passthrough"}

_MAPPING_RELPATH = "knowledge/environment/systems/case-history/mapping.yaml"

# Fallbacks for internal facts that are absent (not "configuration" — these are how
# the code behaves when an artifact is thin, which the mapping templates don't cover).
_SIGNATURE_FALLBACK = "unknown"
_SUMMARY_FALLBACK = "(no rule description)"
_CONFIDENCE_FALLBACK = "n/a"


class CaseTicketError(Exception):
    """The internal artifacts (report.md / alert.json) or the mapping config are
    missing or malformed. Raised here; `ticket_writer` catches it and downgrades to
    a non-fatal WARN (a crashed run with no report.md leaves the ticket open)."""


@dataclass(frozen=True)
class CaseRecord:
    """The internal model of a finished case — parsed from `report.md` + `alert.json`.

    Deliberately thin (#317 scope 4): the offline loop (PR 2) enriches the stored
    resolution with grounded predicates + the survival flag; the runtime writes
    only what it knows at disposition time."""

    case_id: str
    signature_id: str
    disposition: str
    confidence: str
    reason: str


# ---------------------------------------------------------------------------
# Mapping config (the de-facto schema) — read from a file, not hardcoded
# ---------------------------------------------------------------------------


def _mapping_path() -> Path:
    """Resolve mapping.yaml. Honors $DEFENDER_DIR (mirrors `_stub_transport`), else
    resolves relative to this file so it's found regardless of cwd."""
    base = os.environ.get("DEFENDER_DIR")
    root = Path(base) if base else Path(__file__).resolve().parents[2]
    return root / _MAPPING_RELPATH


def _load_mapping() -> dict[str, Any]:
    path = _mapping_path()
    if not path.is_file():
        raise CaseTicketError(f"case-history mapping not found: {path}")
    import yaml  # the defender venv's one runtime dep

    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise CaseTicketError(f"case-history mapping is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise CaseTicketError(f"case-history mapping is not a mapping: {path}")
    return data


def _dig(obj: Any, dotted: str) -> Any:
    """Follow a dotted path into a nested mapping; None if any hop is absent."""
    cur = obj
    for key in dotted.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _render(value: Any, ctx: dict[str, str]) -> Any:
    """Recursively render template strings (and lists/dicts of them) against ctx."""
    if isinstance(value, str):
        return value.format_map(ctx)
    if isinstance(value, list):
        return [_render(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: _render(v, ctx) for k, v in value.items()}
    return value


def _ctx(**kw: str) -> dict[str, str]:
    """A template context with every placeholder present (so a template referencing
    a field this call doesn't set renders empty rather than raising KeyError)."""
    base = {k: "" for k in ("case_id", "signature", "summary", "disposition",
                            "reason", "confidence", "outcome", "seed_eligible",
                            "event_time")}
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# Internal model: report.md (+ alert.json) -> CaseRecord
# ---------------------------------------------------------------------------


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Return (frontmatter mapping, body). Mirrors _loop_validate._parse_frontmatter
    but also hands back the body paragraph and stays out of defender.learning."""
    if not text.startswith("---\n"):
        raise CaseTicketError("report.md missing leading '---' frontmatter fence")
    end = text.find("\n---", 4)
    if end == -1:
        raise CaseTicketError("report.md missing closing '---' frontmatter fence")
    import yaml

    try:
        fm = yaml.safe_load(text[4:end])
    except yaml.YAMLError as e:
        raise CaseTicketError(f"report.md frontmatter is not valid YAML: {e}") from e
    if not isinstance(fm, dict):
        raise CaseTicketError("report.md frontmatter is not a YAML mapping")
    nl = text.find("\n", end + 1)
    body = text[nl + 1:].strip() if nl != -1 else ""
    return fm, body


def _signature_id(alert: dict[str, Any], mapping: dict[str, Any]) -> str:
    path = _dig(mapping, "source.signature") or "rule.id"
    val = _dig(alert, str(path))
    # A present-but-empty value (e.g. rule.id == "") is as useless as a missing
    # one, so fall back on any falsy value, not just None.
    return str(val) if val else _SIGNATURE_FALLBACK


def _event_time(alert: dict[str, Any], mapping: dict[str, Any]) -> str:
    """The SIEM event time from the alert (ISO-8601), or "" if absent. Unlike the
    signature there is no sentinel fallback: a case with no event time simply can't
    be windowed, so the reader drops it from the seed pool rather than mis-dating it."""
    path = _dig(mapping, "source.event_time") or "timestamp"
    val = _dig(alert, str(path))
    return str(val) if val else ""


def alert_event_time(alert: dict[str, Any]) -> str | None:
    """The alert's SIEM event time (ISO-8601), or None if absent. The seed sampler
    anchors its recency window on this — the time the activity happened — so a
    replayed alert windows against its own date, not wall-clock now."""
    return _event_time(alert, _load_mapping()) or None


def read_case_record(run_dir: Path) -> CaseRecord:
    """Parse the run dir's `report.md` + `alert.json` into a `CaseRecord`.

    Raises `CaseTicketError` if `report.md` is absent/malformed or the disposition
    is out of enum — the caller (ticket_writer) treats that as "leave it open"."""
    report = run_dir / "report.md"
    if not report.is_file():
        raise CaseTicketError(f"report.md not found: {report}")
    fm, body = _parse_frontmatter(report.read_text())

    disposition = fm.get("disposition")
    if disposition not in DISPOSITION_ENUM:
        raise CaseTicketError(
            f"report.md disposition={disposition!r} not in {sorted(DISPOSITION_ENUM)}"
        )
    # The ticket key is the run-dir basename — the identity open_case_ticket
    # keyed the create under. open runs at materialize (before report.md
    # exists), so run_dir.name is the only id it has; close MUST target that
    # same key. Derive it from the run dir, not the LLM-authored `case_id:`
    # frontmatter: a divergent value there would transition a key that was
    # never created (404 → the opened ticket is silently left open forever).
    case_id = run_dir.name
    confidence = str(fm.get("confidence") or "")

    mapping = _load_mapping()
    signature_id = _SIGNATURE_FALLBACK
    alert_path = run_dir / "alert.json"
    if alert_path.is_file():
        try:
            signature_id = _signature_id(json.loads(alert_path.read_text()), mapping)
        except (json.JSONDecodeError, OSError):
            pass  # signature stays fallback; non-fatal, the disposition still records

    return CaseRecord(
        case_id=case_id,
        signature_id=signature_id,
        disposition=disposition,
        confidence=confidence,
        reason=body,
    )


# ---------------------------------------------------------------------------
# Mapper: internal <-> external ticket payloads (rendered from mapping.yaml)
# ---------------------------------------------------------------------------


def alert_to_open_payload(alert: dict[str, Any], case_id: str) -> dict[str, Any]:
    """Build the `POST /tickets` body for the bridge create (an OPEN ticket).

    Shape and conventions come from `mapping.yaml` (`open` section + `source.*`)."""
    mapping = _load_mapping()
    signature = _signature_id(alert, mapping)
    summary = _dig(alert, str(_dig(mapping, "source.summary") or "rule.description"))
    ctx = _ctx(
        case_id=case_id,
        signature=signature,
        # Fall back on a present-but-empty description too, so the open ticket
        # never ends up with a blank summary.
        summary=str(summary) if summary else _SUMMARY_FALLBACK,
        event_time=_event_time(alert, mapping),
    )
    payload = _render(mapping.get("open") or {}, ctx)
    if isinstance(payload.get("labels"), list):
        # Drop any convention label whose placeholder rendered empty (e.g. `evt:`
        # when the alert carries no event time) so no value-less label hits the
        # store; `sig:` always has a fallback, so only optional stamps are affected.
        bare = {p for p in _open_label_prefixes(mapping) if p}
        payload["labels"] = [l for l in payload["labels"] if l not in bare]
    return payload


def _open_label_prefixes(mapping: dict[str, Any]) -> list[str]:
    """The literal prefix (text before the first ``{``) of every templated
    `open.labels` entry — used to recognize a label whose placeholder rendered empty
    (a bare prefix), so the write side can drop it."""
    out = []
    for tmpl in _dig(mapping, "open.labels") or []:
        if isinstance(tmpl, str):
            i = tmpl.find("{")
            if i > 0:
                out.append(tmpl[:i])
    return out


def _open_label_prefix(mapping: dict[str, Any], placeholder: str) -> str | None:
    """The pure-literal prefix of the `open.labels` entry carrying ``{placeholder}``
    (e.g. ``sig:`` for ``signature``) — the single source of the marker both the
    write side renders and a reader matches on. None if no such label, or its prefix
    is not a pure literal (then it can't identify a label unambiguously)."""
    ph = "{" + placeholder + "}"
    for tmpl in _dig(mapping, "open.labels") or []:
        if not isinstance(tmpl, str):
            continue
        i = tmpl.find(ph)
        if i == -1:
            continue
        prefix = tmpl[:i]
        if "{" in prefix:  # the prefix must be a pure literal to be a marker
            return None
        return prefix or None
    return None


def signature_label(alert: dict[str, Any]) -> str | None:
    """The ticket label that identifies this alert's signature (e.g. ``sig:5710``),
    rendered from ``mapping.open.labels`` — the SAME label the bridge create stamps,
    so a reader (the seed sampler) can filter the store to this signature without
    knowing the label convention. None if no signature label is configured.

    Matched by its ``sig:`` prefix, not by position, so adding other labels (the
    ``evt:`` event-time stamp) can't shift which one this returns."""
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
    """Build the `POST /tickets/{key}/transitions` body for the close.

    Shape and conventions come from `mapping.yaml` (`close` section)."""
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
    """The literal text that follows {disposition} in the `close.resolution` template
    — the single source for both encoding (above) and decoding (below)."""
    tmpl = _dig(mapping, "close.resolution")
    if not isinstance(tmpl, str):
        return None
    marker = "{disposition}"
    i = tmpl.find(marker)
    if i != 0:  # disposition must lead for the decode to be unambiguous
        return None
    rest = tmpl[len(marker):]
    nxt = rest.find("{")
    sep = rest[:nxt] if nxt != -1 else rest
    return sep or None


def parse_disposition_from_resolution(resolution: str | None) -> str | None:
    """Inverse of the disposition encoding in `case_record_to_close`.

    Returns the disposition token, or None if the resolution wasn't written by us
    (e.g. a human-edited close). Seeds PR 2's reader; the round-trip is tested."""
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


# ---------------------------------------------------------------------------
# Offline enrichment: adversarial-probe verdict -> seed-eligibility comment
# ---------------------------------------------------------------------------


def enrichment_to_comment(outcome: str) -> dict[str, Any]:
    """Build the `POST /tickets/{key}/comments` body stamping seed-eligibility.

    `outcome` is the adversarial-probe verdict (an `OUTCOME_ENUM` token). The
    polarity decision rides `_SEED_ELIGIBLE_OUTCOMES` and is rendered into the
    {seed_eligible} boolean here, so the reader (`parse_survival_from_comments`)
    never re-derives it. Shape + conventions come from `mapping.yaml` (`annotate`)."""
    mapping = _load_mapping()
    eligible = outcome in _SEED_ELIGIBLE_OUTCOMES
    ctx = _ctx(outcome=outcome, seed_eligible="true" if eligible else "false")
    return _render(mapping.get("annotate") or {}, ctx)


def _seed_marker_and_separator(mapping: dict[str, Any]) -> tuple[str | None, str | None]:
    """The pure-literal prefix before {seed_eligible} in `annotate.body` (the
    comment-identity marker) and the literal that follows it (the value separator)
    — the single source for both encoding (above) and decoding (below)."""
    tmpl = _dig(mapping, "annotate.body")
    if not isinstance(tmpl, str):
        return None, None
    ph = "{seed_eligible}"
    i = tmpl.find(ph)
    if i == -1:
        return None, None
    marker = tmpl[:i]
    if "{" in marker:  # the marker must be a pure literal to identify our comment
        return None, None
    rest = tmpl[i + len(ph):]
    nxt = rest.find("{")
    sep = rest[:nxt] if nxt != -1 else rest
    return (marker or None), (sep or None)


def parse_survival_from_comments(comments: Any) -> bool | None:
    """Tri-state read of the seed-eligibility flag from a ticket's `comments`.

    Returns True (a covering benign case — safe seed), False (probed, not eligible),
    or None (no enrichment comment yet — the runtime close-comment is NOT mistaken
    for one, since only the `annotate.body` marker matches). The latest matching
    comment wins, so a re-stamp is read consistently. Inverse of
    `enrichment_to_comment`; the round-trip is tested."""
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


# ---------------------------------------------------------------------------
# Thin external-ticket accessors — so learning-side readers (the seed sampler)
# call these instead of indexing raw ticket dicts (the anti-corruption boundary:
# ticket field names stay known only here).
# ---------------------------------------------------------------------------


def ticket_key(ticket: Any) -> str | None:
    return ticket.get("key") if isinstance(ticket, dict) else None


def ticket_created(ticket: Any) -> str | None:
    """The ISO-8601 ticket-creation timestamp, set server-side at the bridge open.
    This is *materialize* time (when we investigated), which drifts from the alert
    event time under replay — window on `ticket_event_time`, not this."""
    return ticket.get("created") if isinstance(ticket, dict) else None


def ticket_event_time(ticket: Any) -> str | None:
    """The alert's SIEM event time (ISO-8601), read back from the `evt:` label the
    bridge open stamped — the time the activity happened, the key the seed sampler
    windows on. None if absent (no label / no event time at open)."""
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
    """The disposition decoded from the close `resolution` (None if not ours)."""
    if not isinstance(ticket, dict):
        return None
    return parse_disposition_from_resolution(ticket.get("resolution"))


def ticket_reason(ticket: Any) -> str | None:
    """The free-text reason from the close `resolution` (the text after the
    disposition separator), or None if the resolution wasn't written by us."""
    if not isinstance(ticket, dict):
        return None
    resolution = ticket.get("resolution")
    if not isinstance(resolution, str):
        return None
    try:
        sep = _disposition_separator(_load_mapping())
    except CaseTicketError:
        return None
    if not sep or sep not in resolution:
        return None
    return resolution.split(sep, 1)[1].strip() or None


def ticket_seed_eligible(ticket: Any) -> bool | None:
    """The seed-eligibility flag decoded from the ticket's enrichment comment."""
    if not isinstance(ticket, dict):
        return None
    return parse_survival_from_comments(ticket.get("comments"))
