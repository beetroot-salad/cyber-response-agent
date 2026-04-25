"""Manifest-consumption helper for hook-saved raw tool outputs.

The `save_raw_tool_output.py` PostToolUse hook appends one JSONL line per
matched tool call to `{run_dir}/raw_query_outputs/manifest.jsonl`. Each
line carries `{ts, session_id, tool_use_id, agent_id, agent_type, tool_name,
schema, loop_n, path, bytes, command_summary}`.

Gather handlers consume manifest entries via `consume_new_entries(run_dir)`
after the gather subagent returns. Consumption is cursor-based: a sidecar
file `_consumed_offset` tracks the byte offset into manifest.jsonl already
processed. Each call returns the entries written since the last consume
and advances the cursor.

The main investigate loop dispatches subagents sequentially, so cursor-based
consumption correctly scopes "new entries" to the most recent subagent
invocation without needing per-agent_id correlation.

Per-lead correlation lives in `correlate_to_leads`: matches manifest entries
to leads via command_summary substring search against each lead's
`query.query` string. Unmatched entries are appended to the first lead's
bucket (a fallback that handles consultations with no query, leads whose
query string isn't a clean substring, etc.).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


MANIFEST_FILENAME = "manifest.jsonl"
CURSOR_FILENAME = "_consumed_offset"


def _manifest_dir(run_dir: Path) -> Path:
    return run_dir / "raw_query_outputs"


def consume_new_entries(run_dir: Path) -> list[dict[str, Any]]:
    """Return manifest entries appended since the last consume, advance cursor.

    Idempotent across repeated calls within one consume window: a second
    immediate call returns []. Returns [] when the manifest doesn't exist
    or is empty.

    Errors are silenced — manifest reading must never fail the gather flow.
    """
    manifest = _manifest_dir(run_dir) / MANIFEST_FILENAME
    cursor = _manifest_dir(run_dir) / CURSOR_FILENAME
    if not manifest.exists():
        return []
    try:
        offset = int(cursor.read_text().strip()) if cursor.exists() else 0
    except (OSError, ValueError):
        offset = 0

    try:
        with manifest.open("rb") as f:
            f.seek(offset)
            tail = f.read()
            new_offset = f.tell()
    except OSError:
        return []

    if not tail:
        return []

    entries: list[dict[str, Any]] = []
    for line in tail.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    try:
        cursor.write_text(str(new_offset))
    except OSError:
        pass

    return entries


def _query_string(lead: dict[str, Any]) -> str:
    """Pull a query string out of a lead's `query` field (dict or str)."""
    q = lead.get("query")
    if isinstance(q, dict):
        return str(q.get("query") or "")
    if isinstance(q, str):
        return q
    return ""


def correlate_to_leads(
    entries: list[dict[str, Any]],
    leads: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group manifest entries by lead id.

    Strategy:
      1. For each entry, look for a lead whose `query.query` substring
         appears in `command_summary`. First match wins.
      2. Unmatched entries fall through to the first lead.
      3. Leads with no entries get an empty list.
      4. If `leads` is empty, returns {}.

    The first-lead fallback covers: consultations with no query string,
    pre-query setup commands, leads whose query was substituted in non-
    obvious ways. False attribution is recoverable downstream — the
    file content is verbatim regardless of which lead it's grouped under.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    if not leads:
        return grouped

    lead_ids: list[str] = []
    for lead in leads:
        lid = lead.get("id")
        if isinstance(lid, str) and lid:
            grouped[lid] = []
            lead_ids.append(lid)

    if not lead_ids:
        return grouped

    fallback_id = lead_ids[0]

    for entry in entries:
        summary = entry.get("command_summary") or ""
        matched_id: str | None = None
        for lead in leads:
            lid = lead.get("id")
            if not isinstance(lid, str) or not lid:
                continue
            qs = _query_string(lead)
            if qs and qs in summary:
                matched_id = lid
                break
        target = matched_id or fallback_id
        grouped.setdefault(target, []).append(entry)

    return grouped


def attach_paths_to_envelope(
    raw_by_lead: dict[str, dict[str, Any]],
    grouped: dict[str, list[dict[str, Any]]],
) -> None:
    """Mutate `raw_by_lead` in-place: add a `paths` list per lead from
    grouped manifest entries.

    Phase B is purely additive: existing `siem_response` / `consultations`
    keys are preserved. Downstream consumers can read either field.

    Each path entry carries `{path, schema, bytes, ts}` for downstream
    consumption — the file path is load-bearing; the rest is metadata.
    """
    for lead_id, manifest_entries in grouped.items():
        if not manifest_entries:
            continue
        slot = raw_by_lead.setdefault(lead_id, {})
        path_records = []
        for e in manifest_entries:
            path = e.get("path")
            if not isinstance(path, str) or not path:
                continue
            path_records.append({
                "path": path,
                "schema": e.get("schema"),
                "bytes": e.get("bytes"),
                "ts": e.get("ts"),
            })
        if path_records:
            existing = slot.get("paths") or []
            slot["paths"] = list(existing) + path_records
