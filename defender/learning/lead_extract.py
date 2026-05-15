#!/usr/bin/env python3
"""Read ``lead_sequence.yaml`` from a defender run and emit ExecutedLeads.

One ``ExecutedLead`` per ``queries[]`` entry inside each ``entries[]``
record — *not* one per outer entry. The current
``project_lead_sequence.py`` projector emits a single query per
entry, but the schema allows multi-query fan-out and a future
projector may exercise it; the extractor is symmetric so the
lead-author driver handles both cases identically.

Result-ref globbing is intentionally narrow: ``{position}.json`` is the
canonical payload; ``{position}{single-letter}.json`` (e.g. ``2a.json``)
catches fan-out variants the gather tooling reserves; everything else
(``0.lead.json`` sidecars, ``10.json`` when position=1) is excluded.
A bare ``glob({position}*.json)`` would prefix-collide and pull in
sidecars — both wrong in different ways.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


# Maps the ``{system}`` prefix of a ``query_id`` to its CLI script.
# Used by the lead-author driver to scope subprocess permissions.
# ``None`` means ad-hoc / unknown — the driver treats the lead as
# Mode B and the CLI is unavailable.
CLI_REGISTRY: dict[str, str] = {
    "wazuh": "wazuh_cli.py",
    "host": "host_query.py",
}


@dataclass(frozen=True)
class ExecutedLead:
    """One executed query inside a defender run.

    A single ``entries[]`` record with multiple ``queries[]`` expands
    into multiple ExecutedLeads — they share ``position``,
    ``goal_text``, ``what_to_characterize``, and ``result_refs``, but
    each has its own ``query_index``, ``query_id``, ``params``, and
    ``cli``.
    """

    position: int
    query_index: int  # ordinal within the entry's queries[] list, 0-indexed
    query_id: str
    params: dict[str, Any]
    goal_text: str
    what_to_characterize: tuple[str, ...]
    result_refs: tuple[Path, ...]
    cli: str | None


def _resolve_cli(query_id: str) -> str | None:
    """Return the CLI script for a query_id's system prefix, or None."""
    if not query_id or "." not in query_id:
        return None
    system = query_id.split(".", 1)[0]
    return CLI_REGISTRY.get(system)


def _resolve_result_refs(run_dir: Path, position: int) -> tuple[Path, ...]:
    """Find ``{position}.json`` + fan-out variants under ``gather_raw/``.

    Matches: ``{N}.json`` and ``{N}{a..z}.json`` (single lowercase
    letter suffix). Excludes anything with more than one dot in the
    stem (filters ``0.lead.json`` sidecars). Returns paths in
    deterministic sorted order — canonical first, then variants in
    alphabetical order.
    """
    raw_dir = run_dir / "gather_raw"
    if not raw_dir.is_dir():
        return tuple()
    # Build the precise allowed-name set: "{N}.json" and "{N}{a..z}.json".
    canonical = f"{position}.json"
    variants = {f"{position}{c}.json" for c in "abcdefghijklmnopqrstuvwxyz"}
    out: list[Path] = []
    # Iterate the dir contents once rather than calling .glob twice.
    for entry in sorted(raw_dir.iterdir()):
        name = entry.name
        if name == canonical:
            out.append(entry)
            continue
        if name in variants:
            out.append(entry)
            continue
        # Defense in depth — explicitly reject multi-dot stems.
        # (Already excluded by the equality check above, but the
        # comment is the actual contract.)
    return tuple(out)


def extract(run_dir: Path) -> list[ExecutedLead]:
    """Read ``lead_sequence.yaml`` and emit one ExecutedLead per query.

    Skips entries whose result_refs come up empty — those represent
    leads that recorded no payload, which the lead-author has nothing
    to refine against.
    """
    seq_path = run_dir / "lead_sequence.yaml"
    if not seq_path.is_file():
        raise FileNotFoundError(seq_path)
    doc = yaml.safe_load(seq_path.read_text())
    if not isinstance(doc, dict):
        raise ValueError(f"{seq_path}: top-level mapping required")
    entries = doc.get("entries") or []
    if not isinstance(entries, list):
        raise ValueError(f"{seq_path}: entries must be a list")

    out: list[ExecutedLead] = []
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            continue
        position = raw_entry.get("position")
        if not isinstance(position, int):
            continue
        lead_desc = raw_entry.get("lead_description") or {}
        goal = lead_desc.get("goal") or ""
        wtc_raw = lead_desc.get("what_to_characterize") or []
        wtc = tuple(str(x) for x in wtc_raw if isinstance(x, (str, int)))

        queries = raw_entry.get("queries") or []
        if not isinstance(queries, list) or not queries:
            continue
        result_refs = _resolve_result_refs(run_dir, position)
        if not result_refs:
            # No payload on disk — nothing for the lead-author to learn
            # from. Skip.
            continue

        for q_idx, q in enumerate(queries):
            if not isinstance(q, dict):
                continue
            query_id = q.get("id") or ""
            params_raw = q.get("params") or {}
            params = (
                dict(params_raw) if isinstance(params_raw, dict) else {}
            )
            out.append(
                ExecutedLead(
                    position=position,
                    query_index=q_idx,
                    query_id=query_id,
                    params=params,
                    goal_text=goal,
                    what_to_characterize=wtc,
                    result_refs=result_refs,
                    cli=_resolve_cli(query_id),
                )
            )
    return out


# Public for use by the driver, which needs the regex behavior in
# isolation when verifying the ground-truth executed_leads set.
_VARIANT_RE = re.compile(r"^(\d+)([a-z])?\.json$")


def is_valid_result_ref(name: str, position: int) -> bool:
    """True if ``name`` is ``{position}.json`` or a single-letter variant."""
    m = _VARIANT_RE.match(name)
    if not m:
        return False
    return int(m.group(1)) == position
