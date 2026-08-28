#!/usr/bin/env python3
"""What a captured query payload looks like by the time a lead reads it.

THE RULE: a payload small enough to reason from arrives **whole and uncommented**; one too large
arrives **structurally reduced, with every reduction marked where it happened**. Size decides,
and nothing else does — in particular NOT the payload's key names. A whitelist of bulk-array
names cannot work here: the systems are bespoke and each names its list after its contents
(`values`, `entries`, `packages`, `hosts`, `tickets`, `keys`, …), an open range no list keeps up
with. Every identification below is structural — by count, by size, by type — never by name.

Two facts, kept apart. `Completeness` is what the SERVER did, read off the envelope's own scalars
(`total`/`returned`/`truncated`/`row_count`) — which survive any reduction for free, since the
metadata/bulk split is universal: scalars are metadata, arrays are bulk. `Elision` is what THIS
VIEW did. Conflating them is how a lead comes to believe rows are missing from the world when
they are merely absent from its context, and how a complete payload gets told not to count
itself. Under the ceiling a payload arrives verbatim and says nothing: `elisions == []` IS the
proof of completeness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._clock import parse_iso_utc
from defender._env import env_int

#: The in-context ceiling for ONE captured payload. 8 KB because in the recorded corpus only SIEM
#: payloads exceed it — identity profiles, host records, tickets, package and key listings pass
#: whole BY RULE rather than by luck — while a larger ceiling lets a 33 KB result into gather's
#: context to be re-read every turn.
#:
#: NOT the cap on reading an authored file — `runtime/tools.py` holds that one separately, and
#: applies THIS ceiling to reads under `gather_raw/` so an on-disk read cannot defeat the bound
#: the capture chose.
PASSTHROUGH_MAX_BYTES_DEFAULT = 8192


def passthrough_max_bytes() -> int:
    return env_int("DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES", PASSTHROUGH_MAX_BYTES_DEFAULT)


#: A string value longer than this is bulk in its own right and clips, marked, AT THE LEAF.
#: Deliberately NOT a cap on the serialized record: clipping `json.dumps(record)` drops whole
#: trailing FIELDS, so a "field-shape sample" loses part of the field shape. A record keeps all
#: its keys; only a bulky value is cut.
LEAF_MAX_CHARS = 600

#: The shortest value prefix worth keeping beside a marker. Below this a clip states nothing
#: about the value it replaced, and `_clip_string` refuses rather than emit a mangled marker.
_MIN_CLIP_PREFIX = 8

#: Every reduction carries this, in the scope where it happened. A silently shortened array is
#: valid JSON that parses clean and counts wrong, so the marker is deliberately not JSON-shaped
#: and cannot be read as data.
ELISION_PREFIX = "<<ELIDED"


@dataclass(frozen=True)
class Elision:
    """One region this VIEW dropped. Never a statement about the payload on disk, which is
    always whole: `kept`/`total` are counts of elements (a list) or characters (a string)."""

    path: str
    kind: str  # "list" | "string" | "fields" | "cells" | "text"
    kept: int
    total: int


@dataclass(frozen=True)
class Completeness:
    """What the SERVER returned, read off the envelope's own scalars — never inferred from how
    much of it this view happens to show. `unknown` when the payload declares nothing; most
    single-record payloads have no completeness to declare."""

    state: str  # "complete" | "capped" | "unknown"
    total: int | None = None
    returned: int | None = None


#: `json.dumps`' DEFAULT separators are `", "` and `": "` — TWO bytes each, not one. Every cost in
#: the walk must charge that; charging 1 overshoots the ceiling, falls to `render`'s floor, and
#: cuts the document mid-token into text `json.loads` rejects. The ruler stays `json.dumps`'
#: default because that is what the CAPTURE writes with (`query_tool._record`).
_SEP = 2


def _dumps(value: Any) -> str:
    """`ensure_ascii` STAYS ON, and it is load-bearing.

    Everything here is compared in BYTES but measured with `len()`, which counts codepoints.
    Those agree only because `json.dumps` escapes non-ASCII to `\\uXXXX`, making every string
    this module measures — and every `text` reaching `render`, both callers building it the same
    way — pure ASCII. Turn `ensure_ascii` off and the ruler under-reads by up to 3x on CJK: an
    8,000-character payload measuring 8,000 and weighing 24,000 passes the 8 KB ceiling whole."""
    return json.dumps(value, default=str)


def _int(obj: dict, key: str) -> int | None:
    v = obj.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _lists(obj: dict) -> list[list]:
    return [v for v in obj.values() if isinstance(v, list)]


def _rows_for(obj: dict, declared: int) -> list | None:
    """The list a declared row/doc count is ABOUT, by COUNT and then by size — never by name.
    Keyed on a name (say the ES|QL `values`), a payload declaring `row_count` beside a
    differently-named list loses its completeness reading and falls through to `unknown`."""
    if not (lists := _lists(obj)):
        return None
    matching = [v for v in lists if len(v) == declared]
    if len(matching) == 1:
        return matching[0]
    return max(lists, key=len)


def completeness(obj: Any) -> Completeness:
    """Read, in declaration order of strength: the `total`/`returned` pair the search envelope
    states outright; a `row_count` that EXCEEDS the rows actually present; a lone `total`
    against the payload's ONE list; and finally a bare `truncated` flag.

    Structural throughout — a list is identified by being the only list, never by its name."""
    if not isinstance(obj, dict):
        return Completeness("unknown")
    total, returned = _int(obj, "total"), _int(obj, "returned")
    if total is not None and returned is not None:
        return Completeness("capped" if total > returned else "complete", total, returned)
    row_count = _int(obj, "row_count")
    # ONE DIRECTION ONLY. `row_count` ABOVE the rows present is a real declaration of a cap.
    # EQUAL declares nothing: `elastic_adapter.esql_payload` computes `"row_count": len(values)`
    # from the very array `_rows_for` measures, so reading equality as `complete` asserts
    # "nothing was capped upstream" over a row count that may BE ES's 1000-row cap or the
    # query's `LIMIT`. Equal falls through to `unknown` — no prose rather than false prose. A
    # genuine ES|QL server total needs response headers, which `docker_exec_curl` does not
    # capture today.
    if (
        row_count is not None
        and (rows := _rows_for(obj, row_count)) is not None
        and row_count > len(rows)
    ):
        return Completeness("capped", row_count, len(rows))
    if total is not None and len(lists := _lists(obj)) == 1:
        n = len(lists[0])
        return Completeness("capped" if total > n else "complete", total, n)
    if isinstance(obj.get("truncated"), bool):
        return Completeness("capped" if obj["truncated"] else "complete")
    return Completeness("unknown")


# The span of a capped payload's returned docs — a cap is ONE slice and the envelope never says
# which. Computed over the FULL returned list, not over whatever survived the byte budget.

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

    Plain string order inverts the reported start/end when two stamps in the same second carry
    different fractional-second precision: `"...11:59:00Z"` sorts AFTER `"...11:59:00.500Z"`
    because `.` (0x2E) is below `Z` (0x5A). Unparseable stamps sort last, by raw string, rather
    than raising on a field this function was never handed a schema for.

    `_clock.parse_iso_utc` rather than a bare `fromisoformat`, and the difference is a crash:
    `fromisoformat` returns NAIVE for a stamp with no offset and AWARE for a `Z` stamp, and
    `sort` comparing the two raises `TypeError` out of `render` and the lead loses the whole
    payload. The fallback `timestamp` key is exactly where a bespoke adapter omits the offset;
    the shared helper reads naive AS UTC.
    """
    parsed = parse_iso_utc(ts)
    return (1, ts) if parsed is None else (0, parsed)


def returned_span(records: list) -> tuple[str, str] | None:
    """The time range the returned docs actually cover.

    A capped payload is a *slice*, and which slice depends on the adapter's sort — the SIEM's
    `query` verb sorts `@timestamp` newest-first unless asked for `sort: "asc"`, so a window
    bracketing an alert hands back the window's newest N and the alert's own events can sit
    entirely outside them. The envelope never says *which* docs it returned; the span does.
    """
    stamps = [t for rec in records if (t := _record_time(rec)) is not None]
    if not stamps:
        return None
    stamps.sort(key=_time_sort_key)
    return (stamps[0], stamps[-1])


def _returned_records(obj: Any, comp: Completeness) -> list:
    """The docs the server returned, identified by COUNT: the list whose length is `returned`.
    Falls back to the longest list. Structural on purpose — see the module docstring."""
    if not isinstance(obj, dict):
        return obj if isinstance(obj, list) else []
    rows = _rows_for(obj, comp.returned if comp.returned is not None else -1)
    return rows if rows is not None else []


# The walk.

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
    """Bulk reachable through dicts. Deliberately does NOT descend into a list: a list is bulk as
    a whole, and what nests inside its elements is handled by `_clip_leaves` when those elements
    are kept, or is gone with the elements that were not."""
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


def _list_marker(kept: int, total: int, noun: str = "elements") -> str:
    """The marker for a region cut by COUNT. `noun` names what was counted — elements of a
    list, fields of a record, cells of a positional row — because a lead reading "elements"
    over a row whose count is intact reads it as "rows were dropped"."""
    return (
        f"{ELISION_PREFIX} {total - kept} of {total} {noun} — dropped from THIS VIEW only; "
        f"the payload on disk has all {total}>>"
    )


def _string_marker(kept: int, total: int) -> str:
    return f"{ELISION_PREFIX} {total - kept} of {total} chars>>"


def _clip_string(text: str, room: int) -> tuple[str, bool]:
    """Clip to at most `room` CHARACTERS, marked. A clipper that returns more than its room is a
    budget that does not hold."""
    if len(text) <= room:
        return text, False
    marker = _string_marker(0, len(text))
    keep = room - len(marker)
    if keep < _MIN_CLIP_PREFIX or room >= len(text):
        # A clip has to leave BOTH a legible prefix and a whole marker, or it is not a clip. The
        # marker runs ~25 chars, so at the small caps `_fit_one` squeezes to, clamping would cut
        # the MARKER itself. Refuse, and let the caller drop whole FIELDS instead.
        return text, False
    return text[:keep] + _string_marker(keep, len(text)), True


def _clip_serialized(text: str, room: int) -> tuple[str, bool]:
    """Clip so the string's JSON SERIALIZATION fits `room` bytes — a different ruler from
    `_clip_string`, because of escaping. `LEAF_MAX_CHARS` is a CHARACTER budget by intent; a
    share of the walk's byte budget is not. `json.dumps` spends 2 bytes on a newline and 6 on a
    non-ASCII codepoint, so a newline-dense value clipped to 1,949 characters serializes to
    3,931 bytes. Binary search on the prefix, measured with the same `_dumps` as everything."""
    if len(_dumps(text)) <= room:
        return text, False
    probe = _string_marker(0, len(text))  # the widest the marker can get: `total - 0` digits
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(_dumps(text[:mid] + probe)) <= room:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo] + _string_marker(lo, len(text)), True


def _clip_leaves(value: Any, path: str, out: list[Elision], leaf_cap: int = LEAF_MAX_CHARS) -> Any:
    """Long string leaves inside a KEPT element. The element keeps every key it had; only the
    bulky value is cut, and it says so where it was cut.

    `leaf_cap` is normally `LEAF_MAX_CHARS`. `_fit_one` lowers it when a single element is
    itself wider than the whole share."""
    if isinstance(value, str):
        clipped, did = _clip_string(value, leaf_cap)
        if did:
            out.append(Elision(path, "string", leaf_cap, len(value)))
        return clipped
    if isinstance(value, dict):
        return {k: _clip_leaves(v, f"{path}.{k}", out, leaf_cap) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip_leaves(v, f"{path}[{i}]", out, leaf_cap) for i, v in enumerate(value)]
    return value


#: Leaf caps `_fit_one` walks down when ONE element does not fit the share, before it gives up
#: on values and starts dropping fields. The last is deliberately tiny: a 12-character value
#: still shows the lead that the field is an ISO stamp rather than an integer, which is the
#: whole reason elements are shown instead of a key list.
_SQUEEZE_CAPS = (300, 120, 40, 12)


def _fit_one(element: Any, room: int, path: str, out: list[Elision]) -> Any | None:
    """ONE element squeezed into `room`, for the case where not even the first fits whole. A
    single alert document can serialize larger than the whole ceiling; without this the lead
    receives `hits: ["<<ELIDED 20 of 20 elements>>"]` — no field name at all, on exactly the
    payload it most needs one from to write a narrowing filter.

    Field shape is preserved ahead of value shape: clip the string leaves harder and harder
    first, and only when even that will not fit start dropping the element's own members —
    `_fit_fields` for a record, `_fit_cells` for a positional row. Both halves are needed
    because an element is whatever the payload made it: a dict for search hits, a bare array for
    an ES|QL row. `None` when the element cannot be represented at all, leaving the marker to
    speak alone."""
    squeezed = element
    for cap in _SQUEEZE_CAPS:
        leaves: list[Elision] = []
        squeezed = _clip_leaves(element, path, leaves, cap)
        if len(_dumps(squeezed)) <= room:
            out.extend(leaves)
            return squeezed
    # `squeezed` is the tightest cap's candidate, already built by the last pass above.
    if room > 0:
        if isinstance(element, dict):
            return _fit_fields(squeezed, room, out, path=path)
        if isinstance(element, list):
            return _fit_cells(squeezed, room, out, path=path)
    return None


def _fit_list(node: _Node, share: int, out: list[Elision]) -> Any:
    reserve = len(_dumps(_list_marker(0, len(node.value)))) + 2
    kept: list[Any] = []
    used = 2
    for idx, element in enumerate(node.value):
        # Per ELEMENT, not per list: leaf elisions are committed (`out.extend`) only once the
        # element they belong to is kept, or the record of the element that BROKE the loop — a
        # region absent from the view entirely — leaks in.
        leaves: list[Elision] = []
        clipped = _clip_leaves(element, f"{node.label}[{idx}]", leaves)
        cost = len(_dumps(clipped)) + _SEP
        if used + cost + reserve > share:
            break
        kept.append(clipped)
        out.extend(leaves)
        used += cost
    if not kept and node.value:
        # Not one element fit — see `_fit_one`. Squeeze the first rather than show none: a list
        # rendered as a bare marker carries no field name at all.
        squeezed = _fit_one(node.value[0], max(share - reserve - 2, 0), f"{node.label}[0]", out)
        if squeezed is not None:
            kept = [squeezed]
    if len(kept) == len(node.value):
        # Checked AFTER the salvage, which can complete the list: a one-row payload whose single
        # element was squeezed has lost no ELEMENT, and marking a drop of zero breaks the rule
        # that a marker means a real cut. The squeeze's own cost is marked INSIDE the element.
        return kept
    out.append(Elision(node.label, "list", len(kept), len(node.value)))
    return [*kept, _list_marker(len(kept), len(node.value))]


def _fit_string(node: _Node, share: int, out: list[Elision]) -> Any:
    clipped, did = _clip_serialized(node.value, max(share - _SEP, 0))
    if did:
        out.append(Elision(node.label, "string", len(clipped), len(node.value)))
    return clipped


def _fit_fields(obj: dict, budget: int, out: list[Elision], *, path: str = "") -> Any:
    """A wide flat object of short scalars — bulky purely by having many fields, with nothing
    structural to cut. Keep whole key/value pairs until the budget is spent, then say how many
    were dropped."""
    marker_key = f"{ELISION_PREFIX}>>"
    marker = _list_marker(0, len(obj), "fields")
    reserve = len(_dumps({marker_key: marker})) + _SEP  # measured, not guessed
    kept: dict[str, Any] = {}
    used = 2
    for key, value in obj.items():
        # `_dumps({k: v})` is `{` + the pair + `}`, so the pair PLUS its `", "` is that length.
        cost = len(_dumps({str(key): value}))
        if used + cost + reserve > budget:
            break
        kept[str(key)] = value
        used += cost
    if len(kept) == len(obj):
        return kept
    out.append(Elision(path, "fields", len(kept), len(obj)))
    kept[marker_key] = _list_marker(len(kept), len(obj), "fields")
    return kept


def _fit_cells(row: list, budget: int, out: list[Elision], *, path: str = "") -> Any:
    """A wide positional ROW — the list-shaped mirror of `_fit_fields`, needed because an ES|QL
    row arrives as a bare array and would otherwise fall to `_fit_one`'s `return None`.

    Cells are kept from the FRONT, which is what makes a cut row still readable: cell `i` binds
    to `columns[i]`, so `columns[:len(kept)]` names precisely the survivors. That falls out of
    not reordering; nothing here has to know it.
    """
    marker = _list_marker(0, len(row), "cells")
    reserve = len(_dumps(marker)) + _SEP
    kept: list[Any] = []
    used = 2
    for cell in row:
        cost = len(_dumps(cell)) + _SEP
        if used + cost + reserve > budget:
            break
        kept.append(cell)
        used += cost
    if len(kept) == len(row):
        return kept
    out.append(Elision(path, "cells", len(kept), len(row)))
    return [*kept, _list_marker(len(kept), len(row), "cells")]


def walk(obj: Any, budget: int) -> tuple[Any, list[Elision]]:
    """The payload reduced to fit `budget` bytes, and the record of what that cost.

    Water-filling, ascending: every scalar is kept (the metadata every envelope carries), then
    the remaining budget is spent across bulk regions SMALLEST FIRST, each taking an equal share
    of what is left and rolling its unspent remainder forward. A 5-entry `columns` survives whole
    beside an elided `values`; the inverse — one wide row against many columns — falls out of the
    same arithmetic. A per-key rule ("never cut `columns`") is right for one and wrong for the
    other; a budget is right for both without being told which it sees.
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
    remaining = budget - len(_dumps(result))
    if remaining <= 0:
        # The SCALARS alone overflow, so `_fit_fields` must run here too and not only for
        # payloads with no bulk node — a wide flat object carrying ONE long string HAS a bulk
        # node, and skipping this keeps all its fields and blows the budget. Mark each emptied
        # region in place first (an emptied `[]` is a silently shortened array), then spend
        # what is left on the fields.
        for node in nodes:
            total = len(node.value)
            marker = (
                [_list_marker(0, total)] if node.kind == "list" else _string_marker(0, total)
            )
            result = _replace(result, node.path, marker)
            elisions.append(Elision(node.label, node.kind, 0, total))
        if isinstance(result, dict):
            return _fit_fields(result, budget, elisions), elisions
        return result, elisions
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


# The view.

def _prose(comp: Completeness, elisions: list[Elision], size: int, span) -> list[str]:
    """Four cases, four statements. What the SERVER did and what THIS VIEW did are separate
    sentences and never borrow each other's wording: a lead that cannot tell them apart will
    either hunt for rows that are on disk all along, or report a total it never saw."""
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
    elif comp.state == "capped":
        # A `truncated: true` envelope declaring no `total`/`returned` IS a server cap, which the
        # branch above has no numbers to state. Without this arm the elision line below would
        # tell the lead the rows it cannot see "are present in full on disk" — false: never sent.
        lines.append(
            f"[record_query] {size} bytes. The SERVER capped this result (`truncated`) and did "
            f"NOT say how many matched — this is a slice of unknown size, on disk as well as "
            f"here. NEVER count these docs; re-query with a narrowing filter that reports a "
            f"total, or compute the answer server-side with an aggregating query."
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


def _footer(payload_rel: str | None, run_dir: Path, comp: Completeness) -> list[str]:
    if payload_rel is None:
        return []
    abs_payload = run_dir / payload_rel
    if comp.state == "capped":
        # The file holds the SERVER'S SLICE, not the world, so no `SELECT count(*)` example
        # here: it hands back the cap — the number the prose above says never to count.
        return [
            f"[record_query] returned slice on disk: {abs_payload}",
            "→ read FIELD SHAPE and values off this file; its row count is the server's cap, "
            "not a count of matches. COUNTS come from a query envelope's `total` — re-query "
            "with the narrowing filter and read that. The reducers read STDIN — pipe the file "
            "in, don't pass it as an operand, e.g.:\n"
            f"  cat {abs_payload} | head -40",
        ]
    if comp.state == "unknown":
        # `unknown` means the envelope declared no completeness fact this module can read —
        # EVERY ES|QL payload, since `row_count` is `len(values)` (see `completeness`). Falling
        # through to the `complete` arm below would name the file "full payload" and advertise
        # `SELECT count(*) FROM data`, restating the false "nothing was capped upstream" the
        # prose deliberately does not state. Let a count be a count OF THIS FILE, not an answer.
        return [
            f"[record_query] payload on disk: {abs_payload}",
            "→ nothing in this payload declares a total, so whether the system capped it is "
            "UNKNOWN: a count over this file counts the rows the FILE holds, not the rows that "
            "matched. Read field shape and values off it; to claim a total, re-query with an "
            "aggregating query that reports one. The reducers read STDIN — pipe the file in, "
            "don't pass it as an operand, e.g.:\n"
            f"  cat {abs_payload} | defender-sql 'DESCRIBE data'",
        ]
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
    That is ~94% of the recorded corpus.
    """
    cap = passthrough_max_bytes() if ceiling is None else ceiling
    if len(text) <= cap:
        return text
    try:
        obj = json.loads(text)
    except ValueError:  # JSONDecodeError is a ValueError — one clause, not two spellings of it
        # `len(text) > cap` is already established, so this always clips.
        body, _ = _clip_string(text, cap)
        elisions = [Elision("", "text", len(body), len(text))]
        comp, span = Completeness("unknown"), None
    else:
        walked, elisions = walk(obj, cap)
        body = _dumps(walked)
        comp = completeness(obj)
        span = returned_span(_returned_records(obj, comp)) if comp.state == "capped" else None
        if len(body) > cap:
            # The floor under shapes the structural walk cannot fit. Emits the clipped document
            # as a JSON STRING rather than a raw byte cut of the serialization, which would land
            # mid-token and no longer parse.
            clipped, _ = _clip_serialized(body, cap)
            body = _dumps(clipped)
            elisions = [*elisions, Elision("", "text", len(clipped), len(_dumps(obj)))]
    return "\n".join(
        [*_prose(comp, elisions, len(text), span), body, *_footer(payload_rel, run_dir, comp)]
    )
