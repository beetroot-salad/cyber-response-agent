#!/usr/bin/env python3
"""Lead extraction (inlined from PR-209's lead_extract.py).

Joins the leads + queries tables into ``ExecutedLead`` records (one per executed
query) and collects the general-failure residue — agent-fixable errors that reach
no curator — into the cross-run pitfalls queue.

``LeadAuthorError`` (the lead author's fatal pre/post-flight error) is defined here,
the lowest module that raises it, so ``lead_author`` re-exports it rather than the
extraction layer importing it back from ``lead_author`` (which would cycle).
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Put the workspace root on sys.path so the `defender.*` namespace imports below
# resolve whether this file is imported directly or via lead_author.
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning import lead_repository
from defender.learning.leads import lead_neighbors
from defender.learning.leads.draft_synthesis import (
    _draft_candidate_segments,
    _executed_query,
)


class LeadAuthorError(Exception):
    """Fatal pre/post-flight error — caller should abort."""


@dataclass(frozen=True)
class ExecutedLead:
    lead_id: str                  # the :L row id (FK), e.g. "l-001"
    query_index: int              # positional index within this lead's queries
    is_multi_query: bool          # parent lead had >1 query
    entry_index: int              # index into the joined-leads list
    query_id: str
    system: str                   # adapter system (siem/cmdb/...), from the queries table
    verb: str                     # the honest registry verb the row freezes (#620)
    params: dict[str, Any]
    raw_command: str              # verbatim executed command (the literal query)
    goal_text: str
    what_to_summarize: tuple[str, ...]
    raw_ref: Path | None          # this query's payload, by-ref
    payload_status: str           # from the queries table (record_query)
    payload_digest: str
    error_class: str | None       # None / "infra" / "agent-fixable" (the failure taxonomy)


_VALID_PAYLOAD_STATUSES = frozenset(
    {"ok", "empty", "suspect_empty", "error", "partial"}
)


def extract(run_dir: Path) -> tuple[list, list[ExecutedLead]]:
    """Join the two tables via ``lead_repository`` and emit one ExecutedLead
    per executed query. Returns ``(joined_leads, executed)`` so a caller that
    needs the raw join surface too (for handoff building) reuses this single
    read instead of re-joining.

    Queries whose payload file is missing are dropped silently (the dispatch
    never landed). The payload status comes from the queries-table row
    (``record_query`` writes it deterministically); an out-of-vocabulary
    status is a loud failure — the loop refuses to author against it.
    """
    joined = lead_repository.joined(run_dir)
    return joined, extract_from_joined(joined)


def extract_from_joined(joined_leads: list) -> list[ExecutedLead]:
    """``extract`` over an already-joined leads list (no disk I/O).

    Lets a caller that already holds ``lead_repository.joined(run_dir)`` reuse
    it instead of re-reading both tables. ``joined_leads`` is a list of
    ``lead_repository.JoinedLead``.
    """
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
    """The general-failure residue: agent-fixable errors that reach no curator.

    A failed execution is the clearest pitfall signal — a labelled mistake with
    intent (``goal``) and self-diagnosis (the stderr digest) attached. Three
    homes split the signal; this collects the third:

    - **template failure** (``query_id`` resolves to a catalog template) — folds
      into that template's ``## Pitfalls`` via the existing handoff. Skipped here.
    - **draft candidate** (a coined ``{system}.{verb}`` with no template) —
      ``synthesize_drafts`` mints a ``_draft/`` skeleton the agent curates.
      Skipped here (the shared ``_draft_candidate_segments`` predicate keeps the
      two paths disjoint).
    - **general failure** (the residue: a non-candidate verb like ``siem.esql``
      — a bad ES|QL pipe — or another agent-fixable error that resolves to
      neither) — today ``build_handoff`` WARN-and-drops it and the signal
      vanishes. We capture it instead, for the execution.md curation mode.

    ``infra`` errors (a down system) and ``ok``/``empty`` rows are never
    collected — only ``error_class == "agent-fixable"``. ``pitfall_id`` is
    deterministic (``{run}:{lead}:{q_index}``) so a re-collection on the
    failure-retry path dedups rather than double-counts.

    ``catalog`` reuses the tick's once-loaded catalog when threaded. The
    pre-synthesis catalog is safe here: a freshly-minted draft id is omitted
    either way — via the ``query_id in by_id`` (template) branch on a
    post-synthesis reload, or the ``_draft_candidate_segments`` (draft) branch
    on the pre-synthesis set — so the collected residue is identical.
    """
    # catalog_dir is only consumed by this fallback load; load_catalog owns the
    # None→default, so forward it straight through rather than re-defaulting here.
    if catalog is None:
        catalog = lead_neighbors.load_catalog(catalog_dir)
    by_id = {t.id for t in catalog}
    out: list[dict] = []
    for lead in executed:
        if lead.error_class != "agent-fixable":          # skips None (ok) and infra
            continue
        if not (lead.system or "").strip():              # no {system} → no execution.md to fold into
            continue
        if lead.query_id in by_id:                       # template failure → existing fold
            continue
        if _draft_candidate_segments(lead.query_id, lead.verb, by_id) is not None:  # → a draft
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
                "stderr_digest": lead.payload_digest,    # "exit=N; <stderr[:160]>"
                "error_class": lead.error_class,
            }
        )
    return out
