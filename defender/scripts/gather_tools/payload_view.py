#!/usr/bin/env python3
"""What a captured query payload looks like by the time a lead reads it.

A payload small enough to reason from arrives whole and uncommented; a larger one arrives
structurally reduced, with every reduction marked where it happened. Only size decides — never
key names, since each bespoke system names its bulk list after its contents (`values`,
`entries`, `hosts`, …). Every identification here is by count, size or type.

`Completeness` is what the server did, read off the envelope's scalars (`total`, `returned`,
`truncated`, `row_count`), which survive any reduction since scalars are metadata and arrays are
bulk. `Elision` is what this view did. Keeping them apart stops a lead from believing rows are
missing from the world when they are only missing from its context. Under the ceiling nothing
is said: `elisions == []` means the view is complete.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from defender._clock import parse_iso_utc
from defender._env import env_int
from defender._model import model
from defender._text import as_int

#: The in-context ceiling for one captured payload. At 8 KB only SIEM payloads exceed it in the
#: recorded corpus; larger would let 33 KB results into gather's context, re-read every turn.
#: `runtime/tools.py` applies this ceiling to reads under `gather_raw/` too, so reading the file
#: cannot bypass it.
PASSTHROUGH_MAX_BYTES_DEFAULT = 8192


def passthrough_max_bytes() -> int:
    return env_int("DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES", PASSTHROUGH_MAX_BYTES_DEFAULT)


#: A longer string value is bulk and is clipped, marked, at the leaf — not by clipping the
#: serialized record, which would drop trailing fields.
LEAF_MAX_CHARS = 600

#: The shortest value prefix worth keeping beside a marker; below it `_clip_string` refuses.
_MIN_CLIP_PREFIX = 8

#: Every reduction carries this, where it happened. Not JSON-shaped, so a shortened array cannot
#: be mistaken for complete data.
ELISION_PREFIX = "<<ELIDED"


@model(frozen=True)
class Elision:
    """One region this view dropped (the payload on disk is always whole). `kept`/`total`
    count elements for a list, characters for a string."""

    path: str
    kind: str  # "list" | "string" | "fields" | "cells" | "text"
    kept: int
    total: int


@model(frozen=True)
class Completeness:
    """What the server returned, read off the envelope's scalars — never inferred from this
    view. `unknown` when the payload declares nothing, as most single records do."""

    state: str  # "complete" | "capped" | "unknown"
    total: int | None = None
    returned: int | None = None


#: `json.dumps`' default separators are two bytes each; undercharging overshoots the ceiling
#: and falls to `render`'s floor. Default separators because the capture writes with them.
_SEP = 2


def _dumps(value: Any) -> str:
    """`ensure_ascii` must stay on: sizes are measured with `len()` (codepoints) but compared
    as bytes, which agree only because escaping makes every string ASCII. Without it CJK text
    would under-measure up to 3x and pass the ceiling whole."""
    return json.dumps(value, default=str)


def _int(obj: dict, key: str) -> int | None:
    return as_int(obj.get(key))


def _lists(obj: dict) -> list[list]:
    return [v for v in obj.values() if isinstance(v, list)]


def _rows_for(obj: dict, declared: int) -> list | None:
    """The list a declared row/doc count is about: the one of that length, else the longest."""
    if not (lists := _lists(obj)):
        return None
    matching = [v for v in lists if len(v) == declared]
    if len(matching) == 1:
        return matching[0]
    return max(lists, key=len)


def completeness(obj: Any) -> Completeness:
    """Read in order of strength: the `total`/`returned` pair; a `row_count` exceeding the rows
    present; a lone `total` against the payload's only list; a bare `truncated` flag."""
    if not isinstance(obj, dict):
        return Completeness("unknown")
    total, returned = _int(obj, "total"), _int(obj, "returned")
    if total is not None and returned is not None:
        return Completeness("capped" if total > returned else "complete", total, returned)
    row_count = _int(obj, "row_count")
    # One direction only: `row_count` above the rows present declares a cap, but equality
    # declares nothing (`esql_payload` sets `row_count = len(values)`, which may itself be ES's
    # 1000-row cap or a `LIMIT`), so it stays `unknown`. A real ES|QL total needs response
    # headers, which `docker_exec_curl` does not capture.
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


# The span of a capped payload's returned docs (the envelope never says which slice), computed
# over the full returned list.

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
    """A chronological sort key for a timestamp string, unparseable ones last by raw string.

    String order is wrong across fractional-second precisions (`.` sorts below `Z`).
    `_clock.parse_iso_utc` reads naive stamps as UTC; a bare `fromisoformat` would mix naive and
    aware values and raise `TypeError` out of `render`.
    """
    parsed = parse_iso_utc(ts)
    return (1, ts) if parsed is None else (0, parsed)


def returned_span(records: list) -> tuple[str, str] | None:
    """The time range the returned docs actually cover.

    A capped payload is one slice whose position depends on the adapter's sort (the SIEM
    defaults to newest-first), so an alert's own events can lie outside it. The envelope never
    says which slice; the span does.
    """
    stamps = [t for rec in records if (t := _record_time(rec)) is not None]
    if not stamps:
        return None
    stamps.sort(key=_time_sort_key)
    return (stamps[0], stamps[-1])


def _returned_records(obj: Any, comp: Completeness) -> list:
    """The docs the server returned: the list whose length is `returned`, else the longest.
    Identified by count, never by key name."""
    if not isinstance(obj, dict):
        return obj if isinstance(obj, list) else []
    rows = _rows_for(obj, comp.returned if comp.returned is not None else -1)
    return rows if rows is not None else []


# The walk.

@model(frozen=True)
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
    """Bulk reachable through dicts. Does not descend into lists: a list is bulk as a whole,
    and `_clip_leaves` handles what is inside the elements that are kept."""
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
    """The marker for a region cut by count. `noun` names what was counted, so a lead does not
    read dropped fields or cells as dropped rows."""
    return (
        f"{ELISION_PREFIX} {total - kept} of {total} {noun} — dropped from THIS VIEW only; "
        f"the payload on disk has all {total}>>"
    )


def _string_marker(kept: int, total: int) -> str:
    return f"{ELISION_PREFIX} {total - kept} of {total} chars>>"


def _clip_string(text: str, room: int) -> tuple[str, bool]:
    """Clip to at most `room` characters, marked."""
    if len(text) <= room:
        return text, False
    marker = _string_marker(0, len(text))
    keep = room - len(marker)
    if keep < _MIN_CLIP_PREFIX or room >= len(text):
        # A clip must leave a legible prefix and a whole marker (~25 chars); otherwise refuse
        # and let the caller drop whole fields.
        return text, False
    return text[:keep] + _string_marker(keep, len(text)), True


def _clip_serialized(text: str, room: int) -> tuple[str, bool]:
    """Clip so the string's JSON serialization fits `room` bytes. Unlike `_clip_string`'s
    character budget, escaping matters here (a newline costs 2 bytes, non-ASCII 6), so this
    binary-searches the prefix length with `_dumps`."""
    if len(_dumps(text)) <= room:
        return text, False
    probe = _string_marker(0, len(text))  # the widest the marker can get
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(_dumps(text[:mid] + probe)) <= room:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo] + _string_marker(lo, len(text)), True


def _clip_leaves(value: Any, path: str, out: list[Elision], leaf_cap: int = LEAF_MAX_CHARS) -> Any:
    """Clip long string leaves inside a kept element, marking each cut; every key is kept.
    `_fit_one` lowers `leaf_cap` when one element is wider than its share."""
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


#: Leaf caps `_fit_one` tries before dropping fields. Even 12 characters shows whether a value
#: is an ISO stamp or an integer.
_SQUEEZE_CAPS = (300, 120, 40, 12)


def _fit_one(element: Any, room: int, path: str, out: list[Elision]) -> Any | None:
    """One element squeezed into `room` when not even the first fits whole. Without it a large
    alert document would render as a bare marker with no field names, exactly when the lead
    needs them to write a narrowing filter.

    Field shape is kept ahead of value shape: clip leaves progressively harder, then drop
    members (`_fit_fields` for a record, `_fit_cells` for an ES|QL row). `None` when the
    element cannot be represented at all."""
    squeezed = element
    for cap in _SQUEEZE_CAPS:
        leaves: list[Elision] = []
        squeezed = _clip_leaves(element, path, leaves, cap)
        if len(_dumps(squeezed)) <= room:
            out.extend(leaves)
            return squeezed
    # `squeezed` is the tightest cap's candidate from the last pass.
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
        # Leaf elisions are committed only once their element is kept.
        leaves: list[Elision] = []
        clipped = _clip_leaves(element, f"{node.label}[{idx}]", leaves)
        cost = len(_dumps(clipped)) + _SEP
        if used + cost + reserve > share:
            break
        kept.append(clipped)
        out.extend(leaves)
        used += cost
    if not kept and node.value:
        # Nothing fit: squeeze the first so the view still shows field names.
        squeezed = _fit_one(node.value[0], max(share - reserve - 2, 0), f"{node.label}[0]", out)
        if squeezed is not None:
            kept = [squeezed]
    if len(kept) == len(node.value):
        # After the salvage: a squeezed single-element list lost no element, so no list
        # marker (the squeeze is marked inside the element).
        return kept
    out.append(Elision(node.label, "list", len(kept), len(node.value)))
    return [*kept, _list_marker(len(kept), len(node.value))]


def _fit_string(node: _Node, share: int, out: list[Elision]) -> Any:
    clipped, did = _clip_serialized(node.value, max(share - _SEP, 0))
    if did:
        out.append(Elision(node.label, "string", len(clipped), len(node.value)))
    return clipped


def _fit_fields(obj: dict, budget: int, out: list[Elision], *, path: str = "") -> Any:
    """A wide flat object of short scalars: keep whole key/value pairs until the budget is
    spent, then mark how many were dropped."""
    marker_key = f"{ELISION_PREFIX}>>"
    marker = _list_marker(0, len(obj), "fields")
    reserve = len(_dumps({marker_key: marker})) + _SEP  # measured, not guessed
    kept: dict[str, Any] = {}
    used = 2
    for key, value in obj.items():
        # `{` + pair + `}` costs the same as the pair plus its separator.
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
    """A wide positional row (an ES|QL row is a bare array) — the list counterpart of
    `_fit_fields`. Cells are kept from the front, so `columns[:len(kept)]` names the survivors.
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

    Water-filling: every scalar is kept, then the remaining budget is spread over bulk regions
    smallest first, each taking an equal share of what is left and passing on its remainder. So
    a small `columns` survives beside an elided `values`, and the reverse case works too,
    without any per-key rule.
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
        # The scalars alone overflow, so fall back to `_fit_fields` even though bulk nodes
        # exist. Mark each emptied region first — a bare `[]` would look like real data.
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
    """The prose lines. What the server did and what this view did are separate sentences, so
    a lead neither hunts for rows that are on disk nor reports a total it never saw."""
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
        # `truncated: true` with no counts is still a server cap; without this arm the elision
        # line would wrongly claim the missing rows are on disk.
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
        # The file holds the server's slice, so no `count(*)` example: it would return the cap.
        return [
            f"[record_query] returned slice on disk: {abs_payload}",
            "→ read FIELD SHAPE and values off this file; its row count is the server's cap, "
            "not a count of matches. COUNTS come from a query envelope's `total` — re-query "
            "with the narrowing filter and read that. The reducers read STDIN — pipe the file "
            "in, don't pass it as an operand, e.g.:\n"
            f"  cat {abs_payload} | head -40",
        ]
    if comp.state == "unknown":
        # No declared completeness (every ES|QL payload): don't call it the full payload or
        # suggest `count(*)` as if nothing was capped.
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
    """The model-visible view of one captured payload. Under the ceiling (~94% of the recorded
    corpus) it is returned verbatim."""
    cap = passthrough_max_bytes() if ceiling is None else ceiling
    if len(text) <= cap:
        return text
    try:
        obj = json.loads(text)
    except ValueError:  # includes JSONDecodeError
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
            # Floor for shapes the walk cannot fit: emit the clipped document as a JSON string,
            # since a raw byte cut would not parse.
            clipped, _ = _clip_serialized(body, cap)
            body = _dumps(clipped)
            elisions = [*elisions, Elision("", "text", len(clipped), len(_dumps(obj)))]
    return "\n".join(
        [*_prose(comp, elisions, len(text), span), body, *_footer(payload_rel, run_dir, comp)]
    )
