#!/usr/bin/env python3
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning import lead_repository
from defender.learning.leads import lead_neighbors
from defender.learning.leads.draft_synthesis import (
    _draft_candidate_segments,
    _executed_query,
)


class LeadAuthorError(Exception):
    pass


@dataclass(frozen=True)
class ExecutedLead:
    lead_id: str
    query_index: int
    is_multi_query: bool
    entry_index: int
    query_id: str
    system: str
    verb: str
    params: dict[str, Any]
    raw_command: str
    goal_text: str
    what_to_summarize: tuple[str, ...]
    raw_ref: Path | None
    payload_status: str
    payload_digest: str
    error_class: str | None


_VALID_PAYLOAD_STATUSES = frozenset(
    {"ok", "empty", "suspect_empty", "error", "partial"}
)


def extract(run_dir: Path) -> tuple[list, list[ExecutedLead]]:
    joined = lead_repository.joined(run_dir)
    return joined, extract_from_joined(joined)


def extract_from_joined(joined_leads: list) -> list[ExecutedLead]:
    out: list[ExecutedLead] = []
    for entry_idx, jl in enumerate(joined_leads):
        goal = jl.goal or ""
        wtc = tuple(str(x) for x in jl.what_to_summarize if isinstance(x, (str, int)))
        is_multi = len(jl.queries) > 1
        for q_idx, q in enumerate(jl.queries):
            if q.raw_ref is None or not q.raw_ref.is_file():
                continue
            if q.payload_status not in _VALID_PAYLOAD_STATUSES:
                raise LeadAuthorError(
                    f"{jl.lead_id} seq {q.seq}: payload_status must be one of "
                    f"{sorted(_VALID_PAYLOAD_STATUSES)}, got {q.payload_status!r}"
                )
            out.append(
                ExecutedLead(
                    lead_id=jl.lead_id,
                    query_index=q_idx,
                    is_multi_query=is_multi,
                    entry_index=entry_idx,
                    query_id=q.query_id,
                    system=q.system,
                    verb=q.verb,
                    params=dict(q.params),
                    raw_command=q.raw_command,
                    goal_text=goal,
                    what_to_summarize=wtc,
                    raw_ref=q.raw_ref,
                    payload_status=q.payload_status,
                    payload_digest=str(q.payload_digest)[:200],
                    error_class=q.error_class,
                )
            )
    return out


def collect_general_failures(
    executed: list[ExecutedLead], run_dir: Path, *, catalog_dir: Path | None = None,
    catalog: list | None = None,
) -> list[dict]:
    if catalog is None:
        catalog = lead_neighbors.load_catalog(catalog_dir)
    by_id = {t.id for t in catalog}
    out: list[dict] = []
    for lead in executed:
        if lead.error_class != "agent-fixable":
            continue
        if not (lead.system or "").strip():
            continue
        if lead.query_id in by_id:
            continue
        if _draft_candidate_segments(lead.query_id, lead.verb, by_id) is not None:
            continue
        out.append(
            {
                "schema_version": 1,
                "pitfall_id": f"{run_dir.name}:{lead.lead_id}:{lead.query_index}",
                "source_run": run_dir.name,
                "system": lead.system,
                "query_id": lead.query_id,
                "goal": lead.goal_text,
                "executed_query": _executed_query(lead),
                "stderr_digest": lead.payload_digest,
                "error_class": lead.error_class,
            }
        )
    return out
