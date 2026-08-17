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
from defender.scripts.gather_tools.record_query import BASH_SHIM_QUERY_ID


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
    #: `QueryRow.is_sentinel`, carried through so the collectors downstream partition on the
    #: SAME predicate the projection did (#841) rather than each re-deriving it from the
    #: `query_id` string. Defaults `False` so a hand-built row in a test is an ordinary query.
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
        # `.rows` — the WHOLE table for this lead, sentinels included, in the table's own seq
        # order. This is the one reader that must not take #841's split: `query_index` keys
        # `pitfall_id`, and `collect_general_failures` below is exactly the collector the
        # `∅.bash-shim` row was minted for (#823). The agent-facing projections are the ones
        # that read `.queries`.
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
    """#870 M5′ — is this row the REDUCER's mistake rather than a system's?

    EQUALITY with the reserved sentinel, never a suffix, a substring or `is_sentinel` alone:
    `resolve_query_id` returns a well-formed `<system>.bash-shim` verbatim (C15), so a model
    that spells a near miss must not be able to route its own row onto the reducer surface
    (U3). `is_sentinel` rides along because it is the projection's own verdict
    on the row (#841) — the collectors partition on the SAME predicate the split did rather
    than each re-deriving one from the string.
    """
    return lead.is_sentinel and lead.query_id == BASH_SHIM_QUERY_ID


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
        # #870 M5′: the reducer lane, tested BEFORE the systemless guard below. A failed
        # `… | defender-sql …` reduce belongs to `defender-sql`, not to whichever system's
        # payload it happened to open, so the row is admitted on the sentinel id alone and its
        # `system` is normalized to `""` HERE, at collection — which is what makes three
        # attributed rows carrying one diagnosis ONE record under `pitfall_key` (F2/C8)
        # instead of three bullets of one lesson. The infra guard above still runs first (N9):
        # a broken deployment is not a lesson any corpus file should carry.
        is_reducer = _is_reducer_failure(lead)
        if not is_reducer and not (lead.system or "").strip():
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
                "system": "" if is_reducer else lead.system,
                "query_id": lead.query_id,
                "goal": lead.goal_text,
                "executed_query": _executed_query(lead),
                "stderr_digest": lead.payload_digest,
                "error_class": lead.error_class,
            }
        )
    return out
