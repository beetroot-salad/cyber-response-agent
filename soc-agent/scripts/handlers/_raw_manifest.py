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

import contextlib
import json
from pathlib import Path
from typing import Any
from collections.abc import Iterable


MANIFEST_FILENAME = "manifest.jsonl"
CURSOR_FILENAME = "_consumed_offset"


def _manifest_dir(run_dir: Path) -> Path:
    return run_dir / "raw_query_outputs"


def _read_manifest_tail(run_dir: Path) -> tuple[Path, str, int]:
    """Read manifest bytes past the cursor.

    Returns (cursor_path, decoded_tail, new_offset). `decoded_tail` is "" when
    the manifest is missing or there's nothing new — callers can treat that
    as the empty case. Errors are swallowed to keep the gather flow resilient.
    """
    manifest = _manifest_dir(run_dir) / MANIFEST_FILENAME
    cursor = _manifest_dir(run_dir) / CURSOR_FILENAME
    if not manifest.exists():
        return cursor, "", 0
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
        return cursor, "", 0
    return cursor, tail.decode("utf-8", errors="replace"), new_offset


def _advance_cursor(cursor: Path, new_offset: int) -> None:
    with contextlib.suppress(OSError):
        cursor.write_text(str(new_offset))


def consume_new_entries(run_dir: Path) -> list[dict[str, Any]]:
    """Return manifest entries appended since the last consume, advance cursor.

    Idempotent across repeated calls within one consume window: a second
    immediate call returns []. Returns [] when the manifest doesn't exist
    or is empty.

    Errors are silenced — manifest reading must never fail the gather flow.

    ASSUMPTION: callers dispatch subagents sequentially. For concurrent
    dispatches, use `consume_entries_by_session` instead — it partitions
    the same cursor window by `session_id` (recorded in each entry).
    """
    cursor, tail, new_offset = _read_manifest_tail(run_dir)
    if not tail:
        return []

    entries: list[dict[str, Any]] = []
    for line in tail.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    _advance_cursor(cursor, new_offset)
    return entries


def consume_entries_by_session(
    run_dir: Path, session_ids: Iterable[str],
) -> dict[str, list[dict[str, Any]]]:
    """Like `consume_new_entries`, but partitions the cursor window by
    `session_id` for the requested set only.

    Returns `{session_id: [entries...]}` for every session_id in the input
    (empty list if no entries matched). Entries whose `session_id` is not
    in the requested set are dropped from the output but still consumed —
    the cursor advances past them so they don't leak into a later
    sequential consume. This matches the parallel-dispatch invariant: the
    orchestrator pre-mints UUIDs for the N subagents it spawns, calls them
    in parallel, and reads back exactly those N partitions; foreign entries
    in the same window belong to the orchestrator's own tool calls and are
    not relevant to per-lead correlation.

    Errors are silenced — manifest reading must never fail the gather flow.
    """
    requested = set(session_ids)
    grouped: dict[str, list[dict[str, Any]]] = {sid: [] for sid in requested}

    cursor, tail, new_offset = _read_manifest_tail(run_dir)
    if not tail:
        return grouped

    for line in tail.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        sid = entry.get("session_id")
        if isinstance(sid, str) and sid in requested:
            grouped[sid].append(entry)

    _advance_cursor(cursor, new_offset)
    return grouped


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
