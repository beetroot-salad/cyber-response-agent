#!/usr/bin/env python3
"""Composite-kind inference for the lead-author handoff.

Tags each invocation with one of ``atomic | sweep | join |
baseline_shift | drill_down`` so the agent knows what usage pattern the
template served this run and folds accordingly into the migrated
`## Goal` / `## Query` / `## Pitfalls` shape. ``baseline_shift`` means the
same wide query ran over two windows — evidence `## Query` is already a
capability, not a cue to mint a separate ``## Baseline`` section (that
section is retired; the aggregation in `## Query` covers it).

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

import re
from collections import defaultdict
from typing import Any


CompositeKind = str  # "atomic" | "sweep" | "join" | "baseline_shift" | "drill_down"


_WINDOW_KEYS = frozenset({"window", "shift", "start", "end", "window_start", "window_end"})

# ISO-8601 timestamp literal as bound into an ES|QL pipe, e.g.
# "2026-05-25T13:38:00Z" / "...T13:38:00.000Z" / "... 13:38:00+02:00".
# Under ES|QL the time window is not a named param — the whole query is one
# positional (``arg0``) with the window inlined as these literals — so the
# baseline_shift signal (same query shape, different window) is only legible
# after masking them out of the shape and into the window signature.
_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)


def _system_of(query_id: str) -> str:
    return query_id.split(".", 1)[0] if "." in query_id else query_id


def _shape_and_window(
    params: dict[str, Any],
) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    """Split params into a window-invariant **shape** key and a **window** signature.

    Two volatile-window sources are normalized out of the shape:

    - **named window params** (``start``/``end``/``window``/...) — the original
      pre-ES|QL form, removed wholesale;
    - **inlined ISO timestamp literals** inside a query-string value (``arg0``
      under ES|QL) — masked to ``<TS>`` in the shape, with the literals carried
      into the window. Only timestamps are masked: entity bindings (user, src,
      host) stay in the shape, so two queries that differ by *who* — not *when* —
      are correctly NOT a baseline_shift.

    Returns ``(shape, window)`` — both sorted tuples of ``(key, value)`` pairs.
    """
    shape: list[tuple[str, str]] = []
    window: list[tuple[str, str]] = []
    for k, v in params.items():
        if k in _WINDOW_KEYS:
            window.append((k, str(v)))
            continue
        sv = str(v)
        if isinstance(v, str) and (found := _TS_RE.findall(v)):
            shape.append((k, _TS_RE.sub("<TS>", sv)))
            window.extend((k, ts) for ts in found)
        else:
            shape.append((k, sv))
    return tuple(sorted(shape)), tuple(sorted(window))


def _params_without_window(params: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """The window-invariant shape key for ``params`` (see ``_shape_and_window``)."""
    return _shape_and_window(params)[0]


def _baseline_shift_ids(entries: list[dict[str, Any]]) -> set[tuple[str, tuple]]:
    """Collect (query_id, shape) keys that appear with ≥2 distinct windows.

    Each such key indicates the same query *shape* was dispatched twice over
    different time windows — the textbook ``baseline_shift`` signature. The
    window is masked out of the shape both for named params and for ES|QL
    timestamp literals inlined in the query string (see ``_shape_and_window``).
    """
    seen: dict[tuple[str, tuple], set[tuple]] = defaultdict(set)
    for entry in entries:
        for q in entry.get("queries") or []:
            if not isinstance(q, dict):
                continue
            qid = q.get("id") or ""
            if not qid:
                continue
            shape, window = _shape_and_window(q.get("params") or {})
            seen[(qid, shape)].add(window)
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
