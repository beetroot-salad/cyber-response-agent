#!/usr/bin/env python3
"""Composite-kind inference for the lead-author handoff.

Tags each invocation with one of ``atomic | sweep | join |
baseline_shift | drill_down`` so the agent knows which template
section (`## Filter binding` vs `## Baseline` vs `## Common pitfalls`)
is load-bearing.

v1 rules — keep it cheap; ambiguous cases collapse to ``atomic``.

1. lead entry has one query → ``atomic`` (unless rule 4 promotes).
2. lead entry has multiple queries, all same ``id`` → ``sweep``.
3. lead entry has multiple queries spanning ≥ 2 systems
   (different ``{system}`` prefix on the id) → ``join``.
4. Across the *whole run*, the same template id appears with
   ``window``/``shift``/``start``/``end`` params that differ
   substantially on otherwise-equal binding ⇒ ``baseline_shift``.
5. Otherwise → ``atomic``.

``drill_down`` is left as a follow-up; it requires inter-query
dependency tracking the current joined leads/queries shape does
not capture.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any


CompositeKind = str  # "atomic" | "sweep" | "join" | "baseline_shift" | "drill_down"


_WINDOW_KEYS = frozenset({"window", "shift", "start", "end", "window_start", "window_end"})


def _system_of(query_id: str) -> str:
    return query_id.split(".", 1)[0] if "." in query_id else query_id


def _params_without_window(params: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted((k, str(v)) for k, v in params.items() if k not in _WINDOW_KEYS)
    )


def _baseline_shift_ids(entries: list[dict[str, Any]]) -> set[tuple[str, tuple]]:
    """Collect (query_id, params-modulo-window) keys that appear in ≥2 entries.

    Each such key indicates the same template was dispatched twice with
    different time-window bindings — the textbook ``baseline_shift``
    signature.
    """
    seen: dict[tuple[str, tuple], set[tuple]] = defaultdict(set)
    for entry in entries:
        for q in entry.get("queries") or []:
            if not isinstance(q, dict):
                continue
            qid = q.get("id") or ""
            if not qid:
                continue
            params = q.get("params") or {}
            base = _params_without_window(params)
            window = tuple(
                sorted(
                    (k, str(v))
                    for k, v in params.items()
                    if k in _WINDOW_KEYS
                )
            )
            seen[(qid, base)].add(window)
    return {key for key, windows in seen.items() if len(windows) >= 2}


def infer_composite_kind(
    lead_entry: dict[str, Any],
    query: dict[str, Any],
    run_entries: list[dict[str, Any]],
) -> CompositeKind:
    """Classify one query within one lead entry.

    Parameters
    ----------
    lead_entry : the ``entries[]`` element this query came from.
    query : the specific ``queries[]`` element being classified.
    run_entries : all of the run's leads (one dict per joined lead), for
        cross-entry rules (baseline_shift).
    """
    queries = lead_entry.get("queries") or []
    qid = query.get("id") or ""
    params = query.get("params") or {}

    # Rule 4: cross-entry baseline shift (precedence over atomic).
    shift_keys = _baseline_shift_ids(run_entries)
    if (qid, _params_without_window(params)) in shift_keys:
        return "baseline_shift"

    if len(queries) <= 1:
        return "atomic"

    ids = [q.get("id") or "" for q in queries if isinstance(q, dict)]
    ids = [i for i in ids if i]
    if not ids:
        return "atomic"

    # Rule 3: cross-system join.
    systems = {_system_of(i) for i in ids}
    if len(systems) >= 2:
        return "join"

    # Rule 2: same id repeated → sweep.
    if len(set(ids)) == 1:
        return "sweep"

    return "atomic"


def co_dispatched_template_paths(
    lead_entry: dict[str, Any],
    query_index: int,
    template_path_by_id: dict[str, str],
) -> list[str]:
    """List the template paths of sibling queries in the same lead entry.

    The current invocation's own path is excluded. Unresolved ids are
    silently dropped.
    """
    out: list[str] = []
    for j, q in enumerate(lead_entry.get("queries") or []):
        if j == query_index or not isinstance(q, dict):
            continue
        sibling_id = q.get("id") or ""
        path = template_path_by_id.get(sibling_id)
        if path:
            out.append(path)
    return out
