"""Deterministic stage-B router for the oracle (footprint -> per-lead projections).

The oracle is split into two stages. Stage A (an LLM) enumerates the attack's
telemetry footprint as a flat list of events, each carrying its *true native
attributes* (which container, host, source IP, rule, timestamp, data source) —
with no view of the defender's leads, so there is nothing to overload. Stage B
(this module) is pure **matching**: it places each footprint event under the
lead positions whose query it actually satisfies, and drops the rest into
``uncovered``. Because placement is a containment test rather than a generative
act, the overload failure mode (an out-of-envelope event smuggled into the
nearest lead) is impossible by construction.

We do **not** parse any query language. Each lead query carries a structured
``filters`` block — ``index``, a time ``window``, and locator ``predicates``
(``event_attr`` + ``op`` + bound ``value``) — recovered upstream by
``scripts/lead_filters.py`` from the *template that produced the query*. Routing
is therefore plain dict containment over a closed set of operators
(``eq`` / ``set`` / ``substring``), identical whether the backend is Elastic,
Splunk, or Kusto. A query with no declared contract (``filters: null`` — ad-hoc
or non-event-stream leads) is **not guessed at**: its position is reported under
``unrouted_leads`` for the judge to assess from the raw query, and footprint
events it might cover surface in ``uncovered`` (which is therefore "uncovered
modulo unrouted_leads").
"""
from __future__ import annotations

from datetime import datetime


def _parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _event_values(event: dict, attr) -> set[str]:
    """String values an event carries for ``attr`` (a name or list of names).

    A list means "any of these" — e.g. a query that pins an IP that could land
    in either ``source_ip`` or ``host_ip`` on the event side.
    """
    attrs = attr if isinstance(attr, (list, tuple)) else [attr]
    out: set[str] = set()
    for a in attrs:
        v = event.get(a)
        if v is not None:
            out.add(str(v))
    return out


def _predicate_holds(event: dict, pred: dict) -> bool:
    """Evaluate one locator predicate against an event.

    ``eq``/``set`` compare the event's value(s) for ``event_attr`` against the
    pinned value(s) — a query that pins a field the event lacks excludes it.
    ``substring`` looks for the literal(s) inside the named attr, or the whole
    event when no ``event_attr`` is given. A predicate with neither ``value``
    nor ``values`` is non-discriminating (never excludes).
    """
    op = pred.get("op", "eq")
    attr = pred.get("event_attr")
    if "values" in pred:
        lits = [str(v) for v in pred["values"]]
    elif "value" in pred:
        lits = [str(pred["value"])]
    else:
        return True

    if op in ("eq", "set"):
        have = _event_values(event, attr)
        if not have:
            return False  # query pins this field; event has no value for it
        return bool(have & set(lits))
    if op == "substring":
        if attr:
            blob = " ".join(_event_values(event, attr)).lower()
        else:
            blob = " ".join(str(v) for v in event.values()).lower()
        return any(lit.lower() in blob for lit in lits)
    return True  # unknown op -> non-discriminating, never a false exclusion


def event_satisfies(event: dict, filters: dict) -> bool:
    """True iff this event would surface through a query with these filters."""
    index = filters.get("index")
    if index:
        ds = str(event.get("data_source") or event.get("index") or "")
        base = index.rstrip("*").rstrip("-.")
        # Mutual-prefix so "logs-*" matches everything and a bare "logs" event
        # isn't falsely excluded.
        if ds and base and not (ds.startswith(base) or base.startswith(ds)):
            return False
    window = filters.get("window") or {}
    lo, hi = _parse_ts(window.get("start")), _parse_ts(window.get("end"))
    if lo and hi:
        ts = _parse_ts(event.get("when"))
        if ts is None or not (lo <= ts <= hi):
            return False
    for pred in filters.get("predicates") or []:
        if not _predicate_holds(event, pred):
            return False
    return True


def route(footprint: list[dict], lead_sequence: dict) -> dict:
    """Return ``{projections, uncovered, unrouted_leads}``.

    Each footprint event is placed under every position with a structured
    filter it satisfies. A position whose queries carry **no** structured
    filters is reported in ``unrouted_leads`` (and projects empty); events
    matched by no *routed* position land in ``uncovered``.
    """
    entries = lead_sequence.get("entries") or []
    events = [ev.get("attrs", ev) if isinstance(ev, dict) else ev for ev in footprint]

    projections = []
    unrouted = []
    covered: set[int] = set()
    for entry in entries:
        position = entry.get("position")
        queries = entry.get("queries") or []
        filter_blocks = [q["filters"] for q in queries if isinstance(q.get("filters"), dict)]
        if not filter_blocks:
            unrouted.append({
                "position": position,
                "queries": [
                    {"id": q.get("id"), "params": q.get("params", {})} for q in queries
                ],
            })
            projections.append({"position": position, "events": []})
            continue
        matched = []
        for i, ev in enumerate(events):
            if any(event_satisfies(ev, f) for f in filter_blocks):
                matched.append(ev)
                covered.add(i)
        projections.append({"position": position, "events": matched})

    uncovered = [ev for i, ev in enumerate(events) if i not in covered]
    return {"projections": projections, "uncovered": uncovered, "unrouted_leads": unrouted}
