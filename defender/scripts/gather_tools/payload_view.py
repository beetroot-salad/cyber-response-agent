#!/usr/bin/env python3
"""What a captured query payload looks like by the time a lead reads it (#832).

THE RULE, stated rather than inherited: a payload small enough to reason from arrives
**whole and uncommented**; one too large arrives **structurally reduced, with every reduction
marked where it happened**. Size decides, and nothing else does.

What this replaces. The decision used to be `_is_event_payload`: true if the payload was a list,
or a dict carrying one of `("hits","results","events","records","data","rows")`. That tuple is a
cross-vendor SIEM envelope-key list — Elasticsearch's `hits`, Splunk's `results`, Datadog's
`data`, Sentinel's `rows` — written when defender talked to one real vendor. Six of the seven
systems here are bespoke, and their authors named each list after its contents. Measured over 894
recorded payloads, `hits` matched; `results`/`events`/`records`/`data`/`rows` matched NOTHING,
while `values` `entries` `packages` `users` `hosts` `changes` `tickets` `indicators` `keys` all
bypassed the gate. So a 105-byte complete Lucene result was cut to three docs and stamped "Do NOT
count these", and a 19 KB package list went into context whole. Nothing chose either.

A whitelist could not have been rescued by lengthening it: "name the list after the thing" has
open range, so every new verb coins a name nobody remembers to add. The rule here has no list to
forget, and a new adapter is handled correctly on the day it is written, by nobody.

Two facts, kept apart. `Completeness` is what the SERVER did — read off the envelope's own
scalars (`total`/`returned`/`truncated`/`row_count`), which survive any reduction for free
because the metadata/bulk split is universal: scalars are metadata, arrays are bulk. `Elision` is
what THIS VIEW did. Conflating them is how a lead comes to believe rows are missing from the
world when they are merely absent from its context — and how, in the other direction, a complete
payload gets told not to count itself.

Which is the point of the empty envelope: `{total: 0, truncated: false, hits: []}` is complete,
94 bytes, and entirely visible. The old view answered it with "0 records ... Do NOT count these
or read values off them", forbidding the one exact fact it held. #809 is gather reporting a zero
it cannot stand behind; that view manufactured it. Here the payload is under the ceiling, so it
arrives verbatim and says nothing — `elisions == []` IS the proof of completeness, so the prose
never has to assert a limitation the payload does not have.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from defender._env import env_int

#: The in-context ceiling for ONE captured payload. Lowered from 65536 to 8192 with #832: at
#: 64 KB the reduction path fired 6 times in 894 payloads while a 33 KB result entered gather's
#: context whole and was re-read every turn (the cache-read tax `47f2dfb3` was chasing when it
#: reached for a shape gate instead). Every payload above 8 KB in the corpus is elastic; no
#: identity profile, host record, ticket, package list or authorized_keys reaches it, so those
#: pass whole BY RULE rather than by luck.
#:
#: NOT the cap on reading an authored file — `runtime/tools.py` holds that one separately, and
#: applies THIS ceiling to reads under `gather_raw/` so an on-disk read cannot defeat the bound
#: the capture chose (#832 O7).
PASSTHROUGH_MAX_BYTES_DEFAULT = 8192


def passthrough_max_bytes() -> int:
    return env_int("DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES", PASSTHROUGH_MAX_BYTES_DEFAULT)


#: A string value longer than this is bulk in its own right and clips, marked, AT THE LEAF.
#: Deliberately not a cap on the serialized record, which is what it used to be: clipping
#: `json.dumps(record)` drops whole trailing FIELDS, and 80 of 80 real elastic sample records
#: exceeded 600 chars, so every one arrived as a mid-token prefix — a "field-shape sample" that
#: dropped part of the field shape. A record keeps all its keys; only a bulky value is cut.
LEAF_MAX_CHARS = 600

#: Every reduction carries this, in the scope where it happened. A silently shortened array is
#: valid JSON that parses clean and counts wrong — the exact failure this module exists to stop —
#: so the marker is deliberately not JSON-shaped and cannot be read as data.
ELISION_PREFIX = "<<ELIDED"


@dataclass(frozen=True)
class Elision:
    """One region this VIEW dropped. Never a statement about the payload on disk, which is
    always whole: `kept`/`total` are counts of elements (a list) or characters (a string)."""

    path: str
    kind: str  # "list" | "string" | "fields" | "text"
    kept: int
    total: int


@dataclass(frozen=True)
class Completeness:
    """What the SERVER returned, read off the envelope's own scalars — never inferred from how
    much of it this view happens to show. `unknown` when the payload declares nothing, which is
    honest: most single-record payloads have no completeness to declare."""

    state: str  # "complete" | "capped" | "unknown"
    total: int | None = None
    returned: int | None = None


def _dumps(value: Any) -> str:
    return json.dumps(value, default=str)


def _int(obj: dict, key: str) -> int | None:
    v = obj.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _lists(obj: dict) -> list[list]:
    return [v for v in obj.values() if isinstance(v, list)]


def completeness(obj: Any) -> Completeness:
    """Read, in declaration order of strength: the `total`/`returned` pair the search envelope
    states outright; `row_count` against the rows actually present (ES|QL); a lone `total`
    against the payload's ONE list; and finally a bare `truncated` flag.

    Structural throughout — a list is identified by being the only list, never by its name."""
    if not isinstance(obj, dict):
        return Completeness("unknown")
    total, returned = _int(obj, "total"), _int(obj, "returned")
    if total is not None and returned is not None:
        return Completeness("capped" if total > returned else "complete", total, returned)
    row_count = _int(obj, "row_count")
    if row_count is not None and isinstance(obj.get("values"), list):
        n = len(obj["values"])
        return Completeness("capped" if row_count > n else "complete", row_count, n)
    if total is not None and len(lists := _lists(obj)) == 1:
        n = len(lists[0])
        return Completeness("capped" if total > n else "complete", total, n)
    if isinstance(obj.get("truncated"), bool):
        return Completeness("capped" if obj["truncated"] else "complete")
    return Completeness("unknown")


# --------------------------------------------------------------------------------------- #
# The span of a capped payload's returned docs (#830) — kept because a cap is ONE slice and
# the envelope never says which. Computed over the FULL returned list this module holds, not
# over whatever survived the byte budget.
# --------------------------------------------------------------------------------------- #

_TIME_KEYS = ("@timestamp", "timestamp")


def _record_time(rec: Any) -> str | None:
    if not isinstance(rec, dict):
        return None
    src = rec["_source"] if isinstance(rec.get("_source"), dict) else rec
    for key in _TIME_KEYS:
        if isinstance((v := src.get(key)), str) and v:
            return v
    return None


def _time_sort_key(ts: str) -> tuple[int, Any]:
    """A chronological sort key for one `@timestamp` string, falling open to string order.

    Plain string order breaks the moment two stamps in the same second carry different
    fractional-second precision: `"...11:59:00Z"` sorts AFTER `"...11:59:00.500Z"` because
    `.` (0x2E) is below `Z` (0x5A) in ASCII, even though 00Z is the earlier instant — inverting
    the reported start/end. Parsed timestamps sort first (chronologically); anything unparseable
    sorts after, by its raw string, rather than raising on a field this function was never handed
    a schema for.
    """
    try:
        return (0, datetime.fromisoformat(ts.replace("Z", "+00:00")))
    except ValueError:
        return (1, ts)


def returned_span(records: list) -> tuple[str, str] | None:
    """The time range the returned docs actually cover.

    A capped payload is a *slice*, and which slice depends on the adapter's sort — for the SIEM's
    `query` verb that is `@timestamp`, newest-first unless the call asked for `sort: "asc"`, so a
    window bracketing an alert hands back the window's newest N by default and the alert's own
    events can sit entirely outside them. The envelope reports `total` and `returned` but never
    *which* docs these are, so a lead that asked for ±15m around a pivot and got the last six
    minutes has no way to tell. Stating the span costs nothing and is a fact about the payload,
    not advice about what to do next.
    """
    stamps = [t for rec in records if (t := _record_time(rec)) is not None]
    if not stamps:
        return None
    stamps.sort(key=_time_sort_key)
    return (stamps[0], stamps[-1])


def _returned_records(obj: Any, comp: Completeness) -> list:
    """The docs the server returned, identified by COUNT: the list whose length is `returned`.
    Falls back to the longest list. Structural on purpose — naming it would rebuild the
    whitelist this module exists to delete."""
    if not isinstance(obj, dict) or not (lists := _lists(obj)):
        return obj if isinstance(obj, list) else []
    if comp.returned is not None:
        matching = [v for v in lists if len(v) == comp.returned]
        if len(matching) == 1:
            return matching[0]
    return max(lists, key=len)


# --------------------------------------------------------------------------------------- #
# The walk.
# --------------------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Node:
    """One bulk region: a list, or a string long enough to be bulk in its own right."""

    path: tuple[str, ...]
    kind: str
    value: Any

    @property
    def size(self) -> int:
        return len(_dumps(self.value))

    @property
    def label(self) -> str:
        return ".".join(self.path)


def _bulk_nodes(obj: Any, prefix: tuple[str, ...] = ()) -> list[_Node]:
    """Bulk reachable through dicts. Deliberately does NOT descend into a list: a list is bulk
    as a whole, and whatever nests inside its elements is handled when those elements are kept
    (`_clip_leaves`) or is gone with the elements that were not."""
    if isinstance(obj, list):
        return [_Node(prefix, "list", obj)]
    if not isinstance(obj, dict):
        return []
    nodes: list[_Node] = []
    for key, value in obj.items():
        path = (*prefix, str(key))
        if isinstance(value, list):
            nodes.append(_Node(path, "list", value))
        elif isinstance(value, str) and len(value) > LEAF_MAX_CHARS:
            nodes.append(_Node(path, "string", value))
        elif isinstance(value, dict):
            nodes.extend(_bulk_nodes(value, path))
    return nodes


def _replace(obj: Any, path: tuple[str, ...], value: Any) -> Any:
    if not path:
        return value
    head, rest = path[0], path[1:]
    return {k: (_replace(v, rest, value) if k == head else v) for k, v in obj.items()}


def _list_marker(kept: int, total: int) -> str:
    return (
        f"{ELISION_PREFIX} {total - kept} of {total} elements — dropped from THIS VIEW only; "
        f"the payload on disk has all {total}>>"
    )


def _string_marker(kept: int, total: int) -> str:
    return f"{ELISION_PREFIX} {total - kept} of {total} chars>>"


def _clip_string(text: str, room: int) -> tuple[str, bool]:
    if len(text) <= room:
        return text, False
    keep = max(room - len(_string_marker(0, len(text))), 0)
    return text[:keep] + _string_marker(keep, len(text)), True


def _clip_leaves(value: Any, path: str, out: list[Elision]) -> Any:
    """Long string leaves inside a KEPT element. The element keeps every key it had; only the
    bulky value is cut, and it says so where it was cut."""
    if isinstance(value, str):
        clipped, did = _clip_string(value, LEAF_MAX_CHARS)
        if did:
            out.append(Elision(path, "string", LEAF_MAX_CHARS, len(value)))
        return clipped
    if isinstance(value, dict):
        return {k: _clip_leaves(v, f"{path}.{k}", out) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip_leaves(v, f"{path}[{i}]", out) for i, v in enumerate(value)]
    return value


def _fit_list(node: _Node, share: int, out: list[Elision]) -> Any:
    reserve = len(_dumps(_list_marker(0, len(node.value)))) + 2
    kept: list[Any] = []
    leaves: list[Elision] = []
    used = 2
    for idx, element in enumerate(node.value):
        clipped = _clip_leaves(element, f"{node.label}[{idx}]", leaves)
        cost = len(_dumps(clipped)) + 1
        if used + cost + reserve > share:
            break
        kept.append(clipped)
        used += cost
    out.extend(leaves[: len(kept) * 8])
    if len(kept) == len(node.value):
        return kept
    out.append(Elision(node.label, "list", len(kept), len(node.value)))
    return [*kept, _list_marker(len(kept), len(node.value))]


def _fit_string(node: _Node, share: int, out: list[Elision]) -> Any:
    clipped, did = _clip_string(node.value, max(share - 2, 0))
    if did:
        out.append(Elision(node.label, "string", len(clipped), len(node.value)))
    return clipped


def _fit_fields(obj: dict, budget: int, out: list[Elision]) -> Any:
    """A wide flat object of short scalars: no list, no long string, nothing structural to cut.
    Keep whole key/value pairs until the budget is spent and say how many were dropped — the one
    case where a payload is bulky purely by having many fields."""
    kept: dict[str, Any] = {}
    used = 2
    for key, value in obj.items():
        cost = len(_dumps({key: value}))
        if used + cost > budget - 120:
            break
        kept[str(key)] = value
        used += cost
    out.append(Elision("", "fields", len(kept), len(obj)))
    kept[f"{ELISION_PREFIX}>>"] = _list_marker(len(kept), len(obj)).replace("elements", "fields")
    return kept


def walk(obj: Any, budget: int) -> tuple[Any, list[Elision]]:
    """The payload reduced to fit `budget` bytes, and the record of what that cost.

    Water-filling, ascending: every scalar is kept (that is the metadata every envelope carries),
    then the remaining budget is spent across bulk regions SMALLEST FIRST, each taking an equal
    share of what is left and rolling its unspent remainder forward. A 5-entry `columns` simply
    fits and survives whole beside an elided `values`; the inverse — `row_count: 1` with 1,657
    columns, which occurs in the corpus when a lead probes schema by pulling one wide row — falls
    out with the same arithmetic and no rule about which key is schema. A per-key rule ("never cut
    columns") is right for one of those and wrong for the other; a budget is right for both
    without being told which it is looking at.
    """
    if len(_dumps(obj)) <= budget:
        return obj, []
    elisions: list[Elision] = []
    nodes = sorted(_bulk_nodes(obj), key=lambda n: n.size)
    if not nodes:
        if isinstance(obj, dict):
            return _fit_fields(obj, budget, elisions), elisions
        return obj, elisions
    result = obj
    for node in nodes:
        result = _replace(result, node.path, [] if node.kind == "list" else "")
    remaining = max(budget - len(_dumps(result)), 0)
    left = len(nodes)
    for node in nodes:
        share = remaining // left
        fitted = (
            _fit_list(node, share, elisions) if node.kind == "list"
            else _fit_string(node, share, elisions)
        )
        result = _replace(result, node.path, fitted)
        remaining = max(remaining - len(_dumps(fitted)), 0)
        left -= 1
    return result, elisions


# --------------------------------------------------------------------------------------- #
# The view.
# --------------------------------------------------------------------------------------- #

def _prose(comp: Completeness, elisions: list[Elision], size: int, span) -> list[str]:
    """Four cases, four statements. What the SERVER did and what THIS VIEW did are separate
    sentences and never borrow each other's wording: a lead that cannot tell "the server capped
    this" from "your view is bounded" will either hunt for rows that are on disk all along, or
    report a total it never saw."""
    lines: list[str] = []
    if comp.state == "capped" and comp.total is not None and comp.returned is not None:
        lines.append(
            f"[record_query] {comp.total} total matches (EXACT, from the envelope). The SERVER "
            f"returned {comp.returned} of them — a returned-doc cap, upstream of this view. "
            f"COUNTS come from `total` (to count a subset, re-query with the narrowing filter "
            f"and read its `total`); NEVER count the returned docs — their number is the cap."
        )
        if span is not None:
            lines.append(
                f"[record_query] those {comp.returned} docs span {span[0]} … {span[1]} — ONE "
                f"slice of the {comp.total}, not a spread across your window. The other "
                f"{comp.total - comp.returned} lie outside that span and no `limit` reaches "
                f"them: narrow the window onto the pivot you care about, or compute the answer "
                f"server-side with an aggregating query."
            )
    elif comp.state == "complete":
        lines.append(
            f"[record_query] {size} bytes. The SERVER returned everything it had — nothing was "
            f"capped upstream, and the payload's own counts are exact."
        )
    else:
        lines.append(f"[record_query] {size} bytes.")
    if elisions:
        lines.append(
            f"[record_query] this VIEW is bounded and does not show all of it. Each region it "
            f"dropped is marked `{ELISION_PREFIX} …>>` exactly where it was dropped — those "
            f"elements are absent from THIS TEXT ONLY and are present in full on disk. Read "
            f"counts off the payload's own fields, or compute them over the file."
        )
    return lines


def _footer(payload_rel: str | None, run_dir: Path) -> list[str]:
    if not payload_rel:
        return []
    abs_payload = run_dir / payload_rel
    return [
        f"[record_query] full payload: {abs_payload}",
        "→ compute every value over the full payload on disk; the reducers read STDIN — pipe "
        "the file in, don't pass it as an operand, e.g.:\n"
        f"  cat {abs_payload} | defender-sql 'SELECT count(*) FROM data'",
    ]


def render(
    text: str, payload_rel: str | None, run_dir: Path, *, ceiling: int | None = None
) -> str:
    """The model-visible view of one captured payload.

    Under the ceiling the payload is returned VERBATIM — no prose, no samples, no reformatting.
    That is 94% of the recorded corpus, and it is the whole of the fix for the 41 of 62 elastic
    payloads that were complete, entirely visible, and told not to count themselves.
    """
    cap = passthrough_max_bytes() if ceiling is None else ceiling
    if len(text) <= cap:
        return text
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        body, did = _clip_string(text, cap)
        elisions = [Elision("", "text", len(body), len(text))] if did else []
        comp, span = Completeness("unknown"), None
    else:
        walked, elisions = walk(obj, cap)
        body = _dumps(walked)
        comp = completeness(obj)
        span = returned_span(_returned_records(obj, comp)) if comp.state == "capped" else None
        if len(body) > cap:
            # The budget is honoured structurally in every shape the adapters produce; this is
            # the floor under shapes they do not (an object whose own KEYS overflow the cap).
            body, _ = _clip_string(body, cap)
            elisions = [*elisions, Elision("", "text", cap, len(_dumps(obj)))]
    return "\n".join([*_prose(comp, elisions, len(text), span), body, *_footer(payload_rel, run_dir)])
