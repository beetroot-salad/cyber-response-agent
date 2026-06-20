#!/usr/bin/env python3
"""Case-history ticket mapper — the anti-corruption layer (issue #317, write path).

The defender's *internal* model of a case is `report.md` (+ `alert.json`); the
*external* model is the ticket-server's frozen v1 schema. These are two separate
models, and this module is the **only** place that knows both: it parses the
internal artifacts into a `CaseRecord` and maps that to/from external ticket
payloads. Keeping the translation here means the runtime drivers, the report
schema, and (in PR 2) the learning-loop reader never bind to ticket field names —
when the store changes (e.g. Elastic Cases), only this module and the transport move.

Pure by construction: no network, no transport import. `read_case_record` does
run-dir file reads only. The I/O — posting payloads, the run-dir receipt — lives in
`ticket_writer.py`, which imports this module.

De-facto schema convention (the frozen v1 ticket has no disposition or signature
field, so they ride existing fields):

- ``key``          ← case_id (the run-dir basename)
- ``labels``       ← ``["sig:<rule_id>"]`` (signature, set at create)
- ``summary``      ← the alert rule description (set at create)
- ``resolution``   ← ``"<disposition> — <reason>"`` (set at close; disposition
                     parses back out via ``parse_disposition_from_resolution``)
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Mirrors defender.learning._loop_config.DISPOSITION_ENUM. Defined locally so the
# write path carries no `defender.learning` import (the runtime/learning decoupling
# goal of #317); test_case_ticket asserts the two stay in sync.
DISPOSITION_ENUM = {"benign", "inconclusive", "malicious"}

# Convention markers owned by this layer (see module docstring).
SIGNATURE_LABEL_PREFIX = "sig:"
RESOLUTION_SEP = " — "

CLOSE_AUTHOR = "defender"


class CaseTicketError(Exception):
    """The internal artifacts (report.md / alert.json) are missing or malformed.

    Raised by `read_case_record`; `ticket_writer` catches it and downgrades to a
    non-fatal WARN (a crashed run with no report.md leaves the ticket open)."""


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
    import yaml  # local import: yaml is the defender venv's one runtime dep

    try:
        fm = yaml.safe_load(text[4:end])
    except yaml.YAMLError as e:
        raise CaseTicketError(f"report.md frontmatter is not valid YAML: {e}") from e
    if not isinstance(fm, dict):
        raise CaseTicketError("report.md frontmatter is not a YAML mapping")
    # Body is everything after the closing fence line.
    nl = text.find("\n", end + 1)
    body = text[nl + 1:].strip() if nl != -1 else ""
    return fm, body


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
    case_id = str(fm.get("case_id") or run_dir.name)
    confidence = str(fm.get("confidence") or "")

    signature_id = "unknown"
    alert_path = run_dir / "alert.json"
    if alert_path.is_file():
        try:
            alert = json.loads(alert_path.read_text())
            signature_id = _signature_id(alert)
        except (json.JSONDecodeError, OSError):
            pass  # signature stays "unknown"; non-fatal, the disposition still records

    return CaseRecord(
        case_id=case_id,
        signature_id=signature_id,
        disposition=disposition,
        confidence=confidence,
        reason=body,
    )


def _signature_id(alert: dict[str, Any]) -> str:
    rule = alert.get("rule") or {}
    return str(rule.get("id") or "unknown")


# ---------------------------------------------------------------------------
# Mapper: internal <-> external ticket payloads (pure dict in/out)
# ---------------------------------------------------------------------------


def alert_to_open_payload(alert: dict[str, Any], case_id: str) -> dict[str, Any]:
    """Build the `POST /tickets` body for the bridge create (an OPEN ticket).

    Matches the ticket-server `TicketCreate` shape. The signature rides a label so
    the read PR can sample per-signature (`list-tickets --label sig:<id>`)."""
    rule = alert.get("rule") or {}
    rule_id = _signature_id(alert)
    summary = str(rule.get("description") or "(no rule description)")
    return {
        "key": case_id,
        "summary": summary,
        "description": f"Auto-created from alert {case_id} (rule {rule_id}).",
        "status": "open",
        "reporter": CLOSE_AUTHOR,
        "labels": [f"{SIGNATURE_LABEL_PREFIX}{rule_id}"],
    }


def case_record_to_close(rec: CaseRecord) -> dict[str, Any]:
    """Build the `POST /tickets/{key}/transitions` body for the close.

    Matches the ticket-server `Transition` shape. Disposition rides the resolution
    prefix (the frozen schema has no disposition field); recoverable via
    `parse_disposition_from_resolution`."""
    return {
        "status": "closed",
        "resolution": f"{rec.disposition}{RESOLUTION_SEP}{rec.reason}".strip(),
        "author": CLOSE_AUTHOR,
        "comment": f"Disposition: {rec.disposition} (confidence: {rec.confidence or 'n/a'}).",
    }


def parse_disposition_from_resolution(resolution: str | None) -> str | None:
    """Inverse of the disposition encoding in `case_record_to_close`.

    Returns the disposition token, or None if the resolution wasn't written by us
    (e.g. a human-edited close). Seeds PR 2's reader; the round-trip is tested."""
    if not resolution:
        return None
    head = resolution.split(RESOLUTION_SEP, 1)[0].strip()
    return head if head in DISPOSITION_ENUM else None
