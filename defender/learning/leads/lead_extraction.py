#!/usr/bin/env python3
from __future__ import annotations

import sys
from defender._model import model
from pathlib import Path
from typing import Any

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._io import Bound
# Re-exported: this module is the class's public spelling (`_errors` says why it lives there).
from defender.learning.leads._errors import LeadAuthorError
from defender.learning import lead_repository
from defender.learning.leads import lead_neighbors
from defender.learning.leads.draft_synthesis import (
    _draft_candidate_segments,
    _executed_query,
    answered_identities,
)
from defender.scripts.gather_tools.record_query import BASH_SHIM_QUERY_ID


@model(frozen=True)
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
    #: `QueryRow.is_sentinel`, carried so collectors partition on the projection's predicate
    #: rather than re-deriving it from `query_id`. Defaults `False` for hand-built rows.
    is_sentinel: bool = False


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
        # `.rows`, sentinels included, in seq order: `query_index` keys `pitfall_id`, and
        # `collect_general_failures` needs the `∅.bash-shim` rows. Agent-facing projections
        # read `.queries` instead.
        rows = jl.rows
        is_multi = len(rows) > 1
        for q_idx, q in enumerate(rows):
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
                    is_sentinel=q.is_sentinel,
                )
            )
    return out


def _is_reducer_failure(lead: ExecutedLead) -> bool:
    """Is this row the reducer's mistake rather than a system's?

    Exact equality with the reserved sentinel, never a suffix or substring:
    `resolve_query_id` passes a well-formed `<system>.bash-shim` through verbatim, so a model
    must not be able to route its own row onto the reducer surface. `is_sentinel` is the
    projection's own verdict on the row.
    """
    return lead.is_sentinel and lead.query_id == BASH_SHIM_QUERY_ID


def collect_general_failures(
    executed: list[ExecutedLead], run_dir: Path, *, skills: Bound | None = None,
    where: Path | None = None, catalog: list | None = None,
) -> list[dict]:
    """The agent-fixable failures no draft will absorb, as pitfalls queue rows.

    Scored against `catalog` when given; otherwise against the catalog read through `skills`,
    the held `skills/` mount's view, spelled `where` (#1134). Without a catalog both are
    required: there is no `Path` fallback."""
    if catalog is None:
        if skills is None or where is None:
            raise TypeError(
                "collect_general_failures needs a loaded catalog, or the skills/ view and where="
            )
        catalog = lead_neighbors.load_lane_catalog(skills, where=where)
    # The same answered set `synthesize_drafts` mints against, so every `agent-fixable`
    # failure lands as either a draft or pitfalls residue, never neither.
    by_id = answered_identities(catalog)
    out: list[dict] = []
    for lead in executed:
        if lead.error_class != "agent-fixable":
            continue
        # Reducer rows are tested before the systemless guard: a failed `defender-sql` reduce
        # belongs to `defender-sql`, not the system whose payload it opened, so `system` is
        # normalized to `""` here and attributed rows sharing a diagnosis merge into one
        # record. The infra guard above still runs first.
        is_reducer = _is_reducer_failure(lead)
        if not is_reducer and not (lead.system or "").strip():
            continue
        if lead.query_id in by_id:
            continue
        if _draft_candidate_segments(
            lead.query_id, lead.verb, by_id, row_system=lead.system
        ) is not None:
            continue
        out.append(
            {
                "schema_version": 1,
                "pitfall_id": f"{run_dir.name}:{lead.lead_id}:{lead.query_index}",
                "source_run": run_dir.name,
                "system": "" if is_reducer else lead.system,
                "query_id": lead.query_id,
                "goal": lead.goal_text,
                "executed_query": _executed_query(lead),
                "stderr_digest": lead.payload_digest,
                "error_class": lead.error_class,
            }
        )
    return out
