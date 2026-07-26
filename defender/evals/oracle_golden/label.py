#!/usr/bin/env python3
"""Derive a case's ground-truth labels from its captured telemetry (#711).

The one place the four result-class rules are *executed* rather than described.
Until now they lived in prose in `defender/docs/oracle-calibration.md` and were
applied by hand, and three of the six seed results did not survive the first
re-check. A label produced here is a function of (attack-window payload, control
payloads) and **the projection is not one of its inputs** — which is the
mechanical form of the rule the procedure doc states as
*a label may be corrected from the environment, never from the projection*.

    +event   the attack window has a distinguishable row every control lacks
    +noise   the attack window's rows are all present in the controls too
    -noise   the envelope is empty where the controls are non-empty
    0        empty either way, or the query's window never met the activity

Three things this module refuses to guess, because guessing them is how a labeler
silently biases every case the same way (#711 O6):

  - a **zero-byte payload is an errored query**, not an empty result
    (`runtime/query_tool.py` writes `""` on a non-zero exit). It is excluded from
    the comparison rather than read as `0`.
  - a query with **no control** cannot be classified into `+event`/`+noise` at
    all, and yields `needs-label` rather than defaulting to either.
  - a **state/lookup** system (cmdb, identity, threat-intel, change-mgmt,
    host-state) has no time dimension, so no window comparison decides it. Its
    class comes from a declared per-scenario rule; undeclared is `needs-label`,
    never `0`. Those systems happen to be `0` in every case captured so far, but
    that is a property of the activities captured, not a derivable rule.

Two limits are declared rather than papered over:

  - **"the same row" needs a per-template key.** The default derives it from the
    ES|QL `BY` clause and drops timestamp-valued keys, because a control window
    sits at a different absolute time by construction — keying on
    `BY minute = DATE_TRUNC(...)` would make every bucketed query a spurious
    `+event`. `ROW_KEY_OVERRIDES` is the escape hatch for a template the
    derivation gets wrong.
  - **an aggregate with no `BY` always returns one row.** Emptiness there is not
    `row_count == 0` but "every value in the summary row is zero or null" —
    case-001 `l-001` has a sub-query whose single row reads `total_failed: 95`,
    and its control reads `total_failed: 0`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

PLUS_EVENT = "+event"
PLUS_NOISE = "+noise"
MINUS_NOISE = "-noise"
ZERO = "0"

# Not result classes — states that must not be folded into one.
ERRORED = "errored"
STATE = "state"
NEEDS_LABEL = "needs-label"

#: Systems that answer with current configuration rather than an event stream.
STATE_SYSTEMS = frozenset({"cmdb", "identity", "threat-intel", "change-mgmt", "host-state"})

#: query_id -> the columns that make a row distinguishable. Required for a
#: doc-returning template, where there is no `BY` clause to derive one from and
#: the column list is the whole ECS document.
ROW_KEY_OVERRIDES: dict[str, tuple[str, ...]] = {}

#: Columns that cannot serve as a row key in THIS environment, however
#: distinguishing they look. playground-v2 assigns container addresses in start
#: order, so the same address is a different host after every lever-up
#: (`172.18.0.15` was db-1 through 2026-07-13 and office-ws-1 from ~07-17). A
#: control window on a prior week therefore compares an address to a different
#: machine, and every row reads as new. The procedure doc states the same rule
#: for humans: *label from `host.name`, and treat historical rows in an IP-scoped
#: payload as unattributed.*
#:
#: This is an ENVIRONMENT fact, not a general one. A real deployment with stable
#: addressing would want these in the key.
UNSTABLE_KEY_COLUMNS = frozenset({
    "source.ip", "destination.ip", "client.ip", "server.ip", "host.ip",
    "source.address", "destination.address", "related.ip",
    # Container ids are regenerated on every lever-up, exactly like addresses.
    "container.id", "falco.output_fields.container.id",
    # Per-run agent identity, not a property of the activity.
    "agent.ephemeral_id", "zeek.session_id", "event.id",
})

# `| STATS <aggs> BY a, b = expr(...)` — captured up to the next pipe or end.
_BY_CLAUSE = re.compile(r"\bBY\s+([^|]+)", re.IGNORECASE)
_STATS = re.compile(r"\|\s*STATS\b", re.IGNORECASE)
# `| KEEP a, `b.c`, d` — the query author's own statement of which fields matter.
_KEEP_CLAUSE = re.compile(r"\|\s*KEEP\s+([^|]+)", re.IGNORECASE)
_ISO_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")


def _is_rowset(payload: object) -> bool:
    """Is this the `esql` verb's row-set shape, or a state system's entity doc?"""
    return isinstance(payload, dict) and "row_count" in payload and "values" in payload


def by_columns(query: str) -> tuple[str, ...]:
    """Output column names of the ES|QL `BY` clause, aliases resolved.

    `BY source.ip, user.name` -> ("source.ip", "user.name")
    `BY minute = DATE_TRUNC(1 minute, @timestamp)` -> ("minute",)
    """
    match = _BY_CLAUSE.search(query or "")
    return _split_columns(match.group(1)) if match else ()


def keep_columns(query: str) -> tuple[str, ...]:
    """Columns of an ES|QL `KEEP` clause, backticks stripped.

    A doc-returning query's `KEEP` list is the author saying which fields are
    salient, which is a far better row key than the whole ECS document — and it
    is available without any per-template declaration.
    """
    match = _KEEP_CLAUSE.search(query or "")
    return tuple(c.strip("`") for c in _split_columns(match.group(1))) if match else ()


def _split_columns(clause: str) -> tuple[str, ...]:
    """Split a comma-separated ES|QL column list, respecting function parens."""
    out = []
    depth, current = 0, ""
    for ch in clause:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(current)
            current = ""
        else:
            current += ch
    out.append(current)
    names = []
    for item in out:
        item = item.strip()
        if not item:
            continue
        names.append((item.split("=", 1)[0] if "=" in item else item).strip())
    return tuple(names)


def _looks_like_timestamp(value: object) -> bool:
    return isinstance(value, str) and bool(_ISO_LIKE.match(value))


def row_key_columns(payload: dict, query: str, query_id: str = "") -> tuple[str, ...] | None:
    """Which columns make a row distinguishable from a baseline row.

    `None` means "cannot tell" — and that is a real answer, not a fallback:

    - a **doc-returning** query (no `| STATS`) has no `BY` clause to derive from,
      and its column list is the entire ECS document. Keying on all of it would
      include `@timestamp`, `event.id` and `zeek.session_id`, so no attack row
      could ever equal a control row and EVERY non-empty doc-returning query
      would grade `+event`. That is a systematic bias toward manufacturing
      catches, so such a template must declare its key in `ROW_KEY_OVERRIDES`.
    - a `BY` clause whose every column is a timestamp or an unstable address
      leaves nothing comparable behind.

    Timestamp-valued keys are dropped because the control window sits at a
    different absolute time by construction — keying on
    `BY minute = DATE_TRUNC(...)` would make every bucketed query a `+event`.
    """
    if query_id in ROW_KEY_OVERRIDES:
        return ROW_KEY_OVERRIDES[query_id]
    keys = by_columns(query)
    if not keys:
        if _STATS.search(query or ""):
            return ()          # bare aggregate: presence is decided by row CONTENT
        keys = keep_columns(query)
    if not keys:
        return None            # doc-returning, no KEEP, no declared key — undecidable
    rows = payload.get("values") or []
    usable = tuple(k for k in keys
                   if k not in UNSTABLE_KEY_COLUMNS
                   and not any(_looks_like_timestamp(r.get(k)) for r in rows))
    return usable or None


def _is_empty_summary_row(row: dict) -> bool:
    """A no-`BY` aggregate row that summarizes nothing: all zeros and nulls."""
    for value in row.values():
        if value is None:
            continue
        if isinstance(value, bool):
            return False
        if isinstance(value, (int, float)) and value == 0:
            continue
        return False
    return True


def distinguishing_rows(payload: dict, query: str,
                        query_id: str = "") -> set[tuple] | None:
    """The set of row keys this payload observed, or `None` if undecidable.

    An empty set means "this query saw nothing" — including the no-`BY` aggregate
    whose one row is all zeros, which `row_count` alone would report as a result.
    `None` propagates `row_key_columns`'s refusal to guess a key.
    """
    rows = payload.get("values") or []
    keys = row_key_columns(payload, query, query_id)
    if keys is None:
        return None
    if not rows:
        return set()
    if not keys:
        # A bare aggregate: one row that always exists. Presence is its content.
        return set() if all(_is_empty_summary_row(r) for r in rows) else {("<summary>",)}
    out = set()
    for row in rows:
        if _is_empty_summary_row(row):
            continue
        out.add(tuple(json.dumps(row.get(k), sort_keys=True, default=str) for k in keys))
    return out


def query_class(payload_text: str, controls: list[dict] | None, *,
                query: str = "", query_id: str = "", system: str = "",
                attack_contribution: dict | None = None) -> str:
    """Classify one query's observation. See the module docstring for the rules.

    `attack_contribution` replaces the stored payload for a query that carries no
    window of its own: the stored payload mixes the activity with all history, so
    the activity's delta is only visible in the window-restricted re-measurement
    `controls.py` records alongside the controls.
    """
    if system in STATE_SYSTEMS:
        return STATE
    contribution = (attack_contribution or {}).get("payload")
    if _is_rowset(contribution):
        assert isinstance(contribution, dict)
        return _compare(contribution, controls,
                        (attack_contribution or {}).get("query", query), query_id)
    if payload_text == "":
        return ERRORED                      # non-zero exit, not an empty result
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        return ERRORED
    if not _is_rowset(payload):
        return STATE                        # entity doc from a state/lookup system
    return _compare(payload, controls, query, query_id)


def _compare(payload: dict, controls: list[dict] | None,
             query: str, query_id: str) -> str:
    """The four-way comparison of an attack-window row set against its controls."""
    if controls is None or not controls:
        return NEEDS_LABEL                  # no control -> +event/+noise undecidable

    attack = distinguishing_rows(payload, query, query_id)
    if attack is None:
        return NEEDS_LABEL          # no defensible notion of "the same row" here

    baseline: set[tuple] = set()
    measured = 0
    always_present = True
    for control in controls:
        if control.get("live") is False:
            # The environment was levered down during this window. Not a quiet
            # baseline — no baseline was observable at all, and counting it as
            # empty would suppress every real `-noise`.
            continue
        control_payload = control.get("payload")
        if not isinstance(control_payload, dict) or not _is_rowset(control_payload):
            continue
        rows = distinguishing_rows(control_payload, control.get("query", query), query_id)
        if rows is None:
            return NEEDS_LABEL
        measured += 1
        baseline |= rows
        always_present = always_present and bool(rows)

    if not measured:
        return NEEDS_LABEL

    if attack:
        # `+noise` is an EXISTENTIAL claim about the baseline: seeing this row in
        # any control window is evidence the activity's instance is routine. The
        # union is therefore the right comparison, and it errs toward `+noise` —
        # away from manufacturing a catch.
        return PLUS_NOISE if attack <= baseline else PLUS_EVENT

    # `-noise` is a UNIVERSAL claim: the stream that these queries read was
    # removed. An empty envelope over an INTERMITTENT baseline is ordinary
    # silence, not suppression — case-003's web-1 lead is empty in-window and has
    # a baseline in only one of three control windows, and web-1's agent was
    # never touched. Requiring every control window to carry the stream is the
    # mechanical form of the procedure doc's "confirm the envelope is non-empty in
    # the control windowS first", and it stops the labeler committing exactly the
    # error the suite exists to catch in the oracle: inferring suppression from
    # absence.
    return MINUS_NOISE if always_present else ZERO


#: Strength order for folding sub-query classes into the lead's envelope class.
#: `+event` wins because envelope truth is the UNION of what the queries surface:
#: case-001 `l-006` mixes pre-attack baseline windows with attack-window buckets
#: and is `+event`, because the burst really is inside its envelope.
_STRENGTH = {ZERO: 0, PLUS_NOISE: 1, MINUS_NOISE: 2, PLUS_EVENT: 3}


def lead_class(query_classes: list[str]) -> str:
    """Fold per-query classes into the lead's envelope class."""
    decidable = [c for c in query_classes if c in _STRENGTH]
    if not decidable:
        return NEEDS_LABEL
    return max(decidable, key=lambda c: _STRENGTH[c])


def is_heterogeneous(query_classes: list[str]) -> bool | None:
    """AC 6: >=2 classifiable sub-queries whose observed result-classes differ.

    Errored and state queries are excluded — an errored query is not an
    observation, and comparing a state lookup against an event stream compares
    two things that were never the same kind of measurement.

    `None` — not `False` — when fewer than two sub-queries could be classified at
    all. "The sub-queries agree" and "we could not tell whether they agree" are
    different claims, and collapsing them would let an unmeasurable lead assert
    homogeneity, which is the same species of error as reading an errored query
    as an empty result.
    """
    decidable = [c for c in query_classes if c in _STRENGTH]
    if len(decidable) < 2:
        return None
    return len(set(decidable)) >= 2


def load_control_record(case_dir: Path, lead_id: str, seq: int) -> dict:
    """Whatever `controls.py` measured for one query — `{}` if it never ran."""
    path = case_dir / "hidden" / "controls" / lead_id / f"{seq}.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def declared_state_class(manifest: dict, system: str) -> str:
    """The case's declared rule for a state/lookup system's class.

    `needs-label` when the manifest does not declare one. A state system's class
    is a claim about whether the operation changed the configuration these
    lookups read, and only the case author knows that — defaulting it to `0`
    would make "the activity did not touch inventory" a free, unexamined pass on
    every case, which is precisely the cell #711 wants recruited against.
    """
    declared = (manifest.get("state_classes") or {}).get(system)
    return declared if declared in {ZERO, PLUS_EVENT, PLUS_NOISE, MINUS_NOISE} else NEEDS_LABEL


def query_system(query_id: str, fallback: str = "") -> str:
    """The system a single query belongs to, from its `{system}.{template}` id."""
    return query_id.split(".", 1)[0] if "." in query_id else fallback


def label_lead(case_dir: Path, lead_id: str, queries: list[dict], system: str,
               manifest: dict | None = None) -> dict:
    """Everything derivable for one lead: per-query classes, class, heterogeneous.

    `system` is the lead's HEADLINE system — what `score.py` stratifies by — but
    each query is classified under **its own** system. A real captured lead mixes
    them: case-009's `l-004` runs three cmdb lookups and one elastic search, and
    deciding the whole lead by the state rule would discard the only sub-query
    that can carry a delta.
    """
    manifest = manifest or {}
    per_query = []
    for seq, q in enumerate(queries):
        payload_path = case_dir / "hidden" / "observed" / lead_id / f"{seq}.json"
        payload_text = payload_path.read_text(encoding="utf-8") if payload_path.is_file() else ""
        params = q.get("params") or {}
        record = load_control_record(case_dir, lead_id, seq)
        query_id = q.get("query_id", "")
        per_query.append({
            "seq": seq,
            "query_id": query_id,
            "class": query_class(
                payload_text, record.get("controls") or None,
                query=params.get("query", "") or "",
                query_id=query_id, system=query_system(query_id, system),
                attack_contribution=record.get("attack_contribution")),
        })
    classes = [row["class"] for row in per_query]
    if not [c for c in classes if c in _STRENGTH]:
        # Nothing here was a window comparison — every query was a state lookup
        # (or errored). The case declares the class; it is never defaulted.
        return {"lead_id": lead_id, "system": system,
                "class": declared_state_class(manifest, system),
                "heterogeneous": None, "per_query": per_query}
    return {
        "lead_id": lead_id,
        "system": system,
        "class": lead_class(classes),
        "heterogeneous": is_heterogeneous(classes),
        "per_query": per_query,
    }
