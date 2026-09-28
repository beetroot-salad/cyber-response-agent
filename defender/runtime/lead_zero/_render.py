"""Lead-0: turning captured documents into the section the model reads.

Elision and ordering, and saying a thing was unavailable without asserting an absence the
backend never confirmed.
"""
from __future__ import annotations

from typing import Any

from ._spec import ELIDED, MESSAGE_CHAR_BUDGET, UNAVAILABLE
from ._capture import _sanitize


def _elide(value: Any, lead_id: str, seq: int) -> str:
    """Bound one rendered leaf, with a pointer to the payload that holds it whole.

    `seq` is the queries-table seq of the returning call, not the document's position. A
    negative `seq` means no row was written, and the note says so instead of naming a payload
    that was never persisted."""
    if not isinstance(value, str) or len(value) <= MESSAGE_CHAR_BUDGET:
        return value if isinstance(value, str) else str(value)
    where = (
        f", full text at gather_raw/{lead_id}/{seq}.json"  # lint-run-records: ok — a message naming the record for the model or operator, not a path
        if seq >= 0 else ", and the call that returned it persisted no payload"
    )
    return f"{value[:MESSAGE_CHAR_BUDGET]}\n{ELIDED} {len(value)} chars{where})"


def _flatten_doc(doc: dict) -> dict[str, Any]:
    """A document's leaves, keyed by their dotted ECS path.

    `_source` arrives nested, and the correlation lead must name the queryable field each
    entity came from, which a rendered dict repr does not give it."""
    out: dict[str, Any] = {}

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, dict) and node:
            for k, v in node.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                walk(v, key)
        elif isinstance(node, list) and any(isinstance(x, dict) for x in node):
            # Arrays of objects (e.g. `kibana.alert.ancestors`) are indexed so same-named
            # leaves stay distinct; arrays of scalars stay whole.
            for i, item in enumerate(node):
                walk(item, f"{prefix}.{i}" if prefix else str(i))
        elif prefix:
            out[prefix] = node

    walk(doc, "")
    return out


def _render_doc(doc: dict, lead_id: str, seq: int) -> str:
    flat = _flatten_doc(doc)
    lines = []
    ts = flat.get("@timestamp")
    if ts:
        lines.append(f"- @timestamp: {_sanitize(ts)}")
    for key in sorted(flat):
        if key in ("@timestamp", "message"):
            continue
        # Null leaves are dropped: `host.name: None` would invite the lead to bind
        # `host.name:"None"`, which matches nothing and reads as a real zero.
        if flat[key] is None:
            continue
        # Keys are attacker-influenced too, so they are sanitized. Every leaf is elided, since
        # a command line or stored query is as unbounded as a message.
        lines.append(f"  {_sanitize(key)}: {_sanitize(_elide(flat[key], lead_id, seq))}")
    if flat.get("message") is not None:
        lines.append(f"  message: {_sanitize(_elide(flat['message'], lead_id, seq))}")
    return "\n".join(lines)


def _sort_chrono(docs: list[tuple[dict, int]]) -> list[tuple[dict, int]]:
    """Sort `(doc, seq)` entries chronologically by the document's `@timestamp`."""
    def key(entry: tuple[dict, int]) -> str:
        return str(entry[0].get("@timestamp") or "")
    return sorted(docs, key=key)


def _unavailable(reason: str) -> str:
    """An unavailability note. The reason is sanitized because it may be an exception repr
    carrying attacker-influenced text."""

    return f"{UNAVAILABLE} {_sanitize(reason)})"
