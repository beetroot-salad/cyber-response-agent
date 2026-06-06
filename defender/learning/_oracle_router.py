"""Deterministic stage-B router for the oracle (footprint -> per-lead projections).

The oracle is split into two stages. Stage A (an LLM) enumerates the attack's
telemetry footprint as a flat list of events, each carrying its *true native
attributes* (which container, host, source IP, rule, timestamp, index) — with no
view of the defender's leads, so there is nothing to overload. Stage B (this
module) is pure **matching**: it places each footprint event under the lead
positions whose query it actually satisfies, and drops the rest into
``uncovered``. Because placement is a containment test rather than a generative
act, the overload failure mode (an out-of-envelope event smuggled into the
nearest lead) is impossible by construction.

We do **not** parse arbitrary query-language. The filter forms our gather
templates emit are a small, closed set — ``field: "value"`` equalities (with
``OR`` groups), an ``@timestamp:[lo TO hi]`` range, ``_id`` lookups, and
``message: *"literal"*`` substrings — joined by top-level ``AND``. Anything we do
not recognise is treated as *non-discriminating* (it neither adds nor removes
coverage), so an unparsed clause can never cause a false exclusion.

Scope boundary: only **event-stream** leads (those with an Elastic ``index``)
route footprint events. Non-indexed leads (cmdb / host-state) are entity-state
lookups, not telemetry streams; they never "cover" a footprint event, and an
event matched by no event-stream lead is genuinely ``uncovered``.
"""
from __future__ import annotations

import re
from datetime import datetime

# KQL field token -> the footprint attribute(s) that carry the same value.
# Multiple attrs == "satisfied if any of them matches" (e.g. Falco records a
# container id under both container.id and, by a well-known quirk, container.name).
_FIELD_MAP: dict[str, tuple[str, ...]] = {
    "falco.output_fields.container.id": ("container_id",),
    "falco.output_fields.container.name": ("container_id",),
    "falco.rule": ("rule",),
    "falco.output_fields.proc.name": ("process",),
    "process.name": ("process",),
    "source.ip": ("source_ip",),
    "client.ip": ("source_ip",),
    "host.ip": ("host_ip", "source_ip"),
    "host.ipv4": ("host_ip",),
    "host.name": ("host",),
    "source.port": ("source_port",),
    "_id": ("event_id", "ancestor_event_id", "alert_id"),
}

_TS_RE = re.compile(r"@timestamp:\s*\[\s*([^\]]+?)\s+TO\s+([^\]]+?)\s*\]")
# field: *"literal"*  (wildcard substring on a free-text field, e.g. message)
_WILDCARD_RE = re.compile(r'([\w.]+):\s*\*"([^"]+)"\*')
# field: "value"  or  field: 123
_EQ_RE = re.compile(r'([\w.]+):\s*(?:"([^"]*)"|(\d+))')


def _parse_ts(s: str):
    try:
        return datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


class QueryScope:
    """A single executed query reduced to the predicates we can evaluate."""

    def __init__(self, index: str | None):
        self.index = (index or "").strip() or None
        self.eq: dict[str, set[str]] = {}        # kql field -> allowed values (OR within)
        self.substrings: list[str] = []          # message: *"lit"* literals (AND across)
        self.ts_lo = None
        self.ts_hi = None


def parse_query(arg0: str, index: str | None) -> QueryScope:
    scope = QueryScope(index)
    if not arg0:
        return scope
    m = _TS_RE.search(arg0)
    if m:
        scope.ts_lo, scope.ts_hi = _parse_ts(m.group(1)), _parse_ts(m.group(2))
    for fm in _WILDCARD_RE.finditer(arg0):
        scope.substrings.append(fm.group(2))
    # Equalities — skip the @timestamp/_id-internal and wildcard spans already consumed.
    consumed = arg0
    consumed = _TS_RE.sub(" ", consumed)
    consumed = _WILDCARD_RE.sub(" ", consumed)
    for em in _EQ_RE.finditer(consumed):
        field = em.group(1)
        val = em.group(2) if em.group(2) is not None else em.group(3)
        scope.eq.setdefault(field, set()).add(val)
    return scope


def _event_value_set(event: dict, attrs: tuple[str, ...]) -> set[str]:
    out: set[str] = set()
    for a in attrs:
        if a in event and event[a] is not None:
            out.add(str(event[a]))
    return out


def _is_placeholder(v: str) -> bool:
    return v.startswith("<") and v.endswith(">")


def event_satisfies(event: dict, scope: QueryScope) -> bool:
    """True iff this event would surface through this query.

    Conjunctive: every recognised predicate must hold. A predicate on a field we
    can map is decisive (mismatch -> excluded); a predicate on an unmapped field
    is non-discriminating (ignored), so we never falsely exclude on a clause we
    don't understand.
    """
    # index compatibility (pattern like "logs-falco.alerts-*"): the event's
    # data_source and the index pattern must share a dataset prefix. Mutual-prefix
    # so "logs-*" matches everything and a bare "logs" event isn't falsely excluded.
    if scope.index:
        ds = str(event.get("data_source") or event.get("index") or "")
        idx_base = scope.index.rstrip("*").rstrip("-.")
        if ds and idx_base and not (ds.startswith(idx_base) or idx_base.startswith(ds)):
            return False
    # timestamp window
    if scope.ts_lo and scope.ts_hi:
        ts = _parse_ts(str(event.get("when") or ""))
        if ts is None or not (scope.ts_lo <= ts <= scope.ts_hi):
            return False
    # field equalities (OR within a field, AND across fields)
    for field, allowed in scope.eq.items():
        attrs = _FIELD_MAP.get(field)
        if not attrs:
            continue  # unmapped field -> non-discriminating
        have = _event_value_set(event, attrs)
        if not have:
            return False  # query pins this field; event has no value for it
        # a placeholder event value can never equal a concrete pinned value
        if not (have & allowed):
            return False
    # message substrings: the literal must appear somewhere in the event's values
    if scope.substrings:
        blob = " ".join(str(v) for v in event.values()).lower()
        for lit in scope.substrings:
            if lit.lower() not in blob:
                return False
    return True


def route(footprint: list[dict], lead_sequence: dict) -> dict:
    """Return {projections: [{position, events}], uncovered: [events]}.

    An event is placed under every event-stream position with a query it
    satisfies; events matched by no event-stream position are ``uncovered``.
    """
    entries = lead_sequence.get("entries") or []
    # parse each position into its event-stream query scopes
    pos_scopes: list[tuple[int, list[QueryScope]]] = []
    for e in entries:
        scopes = []
        for q in e.get("queries") or []:
            p = q.get("params") or {}
            sc = parse_query(p.get("arg0", ""), p.get("index"))
            if sc.index and sc.index != "-":
                scopes.append(sc)
        pos_scopes.append((e.get("position"), scopes))

    projections = []
    covered_ids: set[int] = set()
    events = [ev.get("attrs", ev) if isinstance(ev, dict) else ev for ev in footprint]
    for position, scopes in pos_scopes:
        matched = []
        for i, ev in enumerate(events):
            if any(event_satisfies(ev, sc) for sc in scopes):
                matched.append(ev)
                covered_ids.add(i)
        projections.append({"position": position, "events": matched})
    uncovered = [ev for i, ev in enumerate(events) if i not in covered_ids]
    return {"projections": projections, "uncovered": uncovered}
