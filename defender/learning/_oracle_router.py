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

from datetime import datetime, timezone


def _parse_ts(value):
    """Parse an ISO-8601 timestamp to a *tz-aware* datetime (assume UTC if naive).

    Footprint events and recovered window bounds are independently authored, so
    one side may carry a ``Z``/offset and the other may not. Normalizing both to
    aware-UTC keeps ``lo <= ts <= hi`` from raising ``TypeError: can't compare
    offset-naive and offset-aware datetimes``. Only a *trailing* ``Z`` is the
    zulu marker — don't rewrite a ``Z`` embedded elsewhere in the string.
    """
    if not value:
        return None
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


# Routing/locator metadata an event carries for placement, not content. A
# no-`event_attr` substring scan must exclude these or it matches on the index
# name itself (e.g. a `substring: "falco"` self-matching every event whose
# `data_source` is `logs-falco.alerts`) and on the synthetic footprint id.
_NON_CONTENT_KEYS = {"data_source", "index", "id"}


def _event_attrs(ev):
    """The event's attribute mapping.

    Footprint events are ``{id, attrs}`` (footprint.md), but the LLM sometimes
    emits a flat event. Return the explicit ``attrs`` payload when the wrapper is
    present (verbatim — the caller's shape check rejects a non-mapping), else the
    event minus its synthetic ``id`` so that id never leaks into a projection as
    if it were a native telemetry field. Non-dict events pass through unchanged
    for the caller to reject.
    """
    if isinstance(ev, dict):
        if "attrs" in ev:
            return ev["attrs"]
        return {k: v for k, v in ev.items() if k != "id"}
    return ev


def _is_placeholder(value) -> bool:
    """True for an ``<angle-bracket>`` placeholder — an unspecified entity.

    The footprint stage emits these where a concrete value is unknown
    (footprint.md). They name nothing, so they must never positively satisfy a
    locator predicate: an event whose pinned field is a placeholder is *not*
    confirmed to be in any lead's envelope, so it belongs in ``uncovered``.
    """
    s = str(value).strip()
    return len(s) >= 2 and s[0] == "<" and s[-1] == ">"


def _event_values(event: dict, attr) -> set[str]:
    """String values an event carries for ``attr`` (a name or list of names).

    A list means "any of these" — e.g. a query that pins an IP that could land
    in either ``source_ip`` or ``host_ip`` on the event side. Placeholder values
    are skipped (treated as absent — an unspecified entity matches nothing).
    """
    attrs = attr if isinstance(attr, (list, tuple)) else [attr]
    out: set[str] = set()
    for a in attrs:
        v = event.get(a)
        if v is not None and not _is_placeholder(v):
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
            # Scan content fields only — never the index/data_source token or the
            # footprint id, which are placement metadata, not what the real
            # free-text query searches.
            blob = " ".join(
                str(v) for k, v in event.items()
                if k not in _NON_CONTENT_KEYS and not _is_placeholder(v)
            ).lower()
        return any(lit.lower() in blob for lit in lits)
    return True  # unknown op -> non-discriminating, never a false exclusion


def event_satisfies(event: dict, filters: dict) -> bool:
    """True iff this event would surface through a query with these filters."""
    index = filters.get("index")
    if index:
        ds = str(event.get("data_source") or event.get("index") or "")
        raw = index.rstrip("*")           # keep the trailing separator: "logs-"
        core = raw.rstrip("-.")           # the dataset core: "logs", "logs-system.auth"
        if core:
            # An event that names no source can't be proven to sit in this index,
            # so don't claim coverage for it (it falls through to `uncovered`).
            # Otherwise: exact dataset match, or — for a separator-terminated
            # wildcard pattern — a name that extends *past* that separator. This
            # is a token boundary, so "logs-*" matches "logs-system.auth" but not
            # "logstash-…", and "logs-system.auth-*" matches neither "logs-system"
            # nor "logs-system.authpriv".
            if ds == core:
                pass
            elif raw != core and ds.startswith(raw):
                pass
            else:
                return False
    window = filters.get("window") or {}
    start_raw, end_raw = window.get("start"), window.get("end")
    if start_raw or end_raw:
        # A declared window we can't fully evaluate must EXCLUDE the event (it
        # falls through to `uncovered`), never silently pass. An unparseable
        # bound (relative time like `now-24h`, epoch millis) previously skipped
        # the check entirely and over-claimed coverage past the query's real
        # time scope. recover_filters also abstains on such bounds upstream; this
        # is the fail-closed backstop.
        lo, hi = _parse_ts(start_raw), _parse_ts(end_raw)
        ts = _parse_ts(event.get("when"))
        if lo is None or hi is None or ts is None or not (lo <= ts <= hi):
            return False
    for pred in filters.get("predicates") or []:
        if not _predicate_holds(event, pred):
            return False
    return True


def route(footprint: list[dict], lead_sequence: dict) -> dict:
    """Return ``{projections, uncovered, unrouted_leads}``.

    Each footprint event is placed under every position with a structured
    filter it satisfies. Any query carrying **no** structured filter is reported
    in ``unrouted_leads`` (even when a sibling query in the same position has a
    filter); a position with no filtered query at all projects empty. Events
    matched by no *routed* query land in ``uncovered``.
    """
    entries = lead_sequence.get("entries") or []
    events = [_event_attrs(ev) for ev in footprint]

    projections = []
    unrouted = []
    covered: set[int] = set()
    for entry in entries:
        position = entry.get("position")
        queries = entry.get("queries") or []
        filter_blocks = [q["filters"] for q in queries if isinstance(q.get("filters"), dict)]
        # Report unrouted queries at per-query granularity: a position that mixes
        # a structured-filter query with a `filters: null` one still routes the
        # former, but the null query must surface in `unrouted_leads` so the judge
        # knows an event in `uncovered` might be caught by that raw query — gating
        # on the whole position having zero filters would drop it silently.
        unrouted_queries = [q for q in queries if not isinstance(q.get("filters"), dict)]
        if unrouted_queries:
            unrouted.append({
                "position": position,
                "queries": [
                    {"id": q.get("id"), "params": q.get("params", {})}
                    for q in unrouted_queries
                ],
            })
        if not filter_blocks:
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
