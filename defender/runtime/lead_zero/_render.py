"""Harness-executed lead-0.

Before MAIN's first ORIENT turn, the runtime resolves the alert's ancestor documents (item 1)
and dispatches one tightly-bounded correlation gather lead (item 3), both writing into the
run's leads/queries tables under the reserved ids ``l-000``/``l-00c`` so the learning loop and
the review gate cite them like any model-dispatched lead.

This module owns every backend call, run-dir write and dispatch those two items add;
``orient.py`` stays a pure text-assembler that calls ``resolve_lead_zero`` and formats the
returned block as one more ORIENT section.

Turning captured documents into the section the model reads.

Split out of `lead_zero.py` at 1215 lines. Everything here is elision and ordering: what
to show, in what order, and how to say a thing was not available without asserting an
absence the backend never confirmed.
"""
from __future__ import annotations

from typing import Any

from ._spec import ELIDED, MESSAGE_CHAR_BUDGET, UNAVAILABLE
from ._capture import _sanitize


def _elide(value: Any, lead_id: str, seq: int) -> str:
    """Bound ONE rendered leaf, with a pointer to the payload that holds it whole.

    `seq` is the QUERIES-TABLE seq of the call that returned the document (`_last_row_seq`),
    never the document's position in the block — those are different numbers. A negative `seq`
    means the call wrote no row at all (screened, or the table write failed), and the note then
    says so rather than naming a payload that was never persisted."""
    if not isinstance(value, str) or len(value) <= MESSAGE_CHAR_BUDGET:
        return value if isinstance(value, str) else str(value)
    where = (
        f", full text at gather_raw/{lead_id}/{seq}.json"
        if seq >= 0 else ", and the call that returned it persisted no payload"
    )
    return f"{value[:MESSAGE_CHAR_BUDGET]}\n{ELIDED} {len(value)} chars{where})"


def _flatten_doc(doc: dict) -> dict[str, Any]:
    """A document's leaves, keyed by their DOTTED ECS path.

    The adapter hands `_source` back UNMODIFIED, and real ECS `_source` is NESTED
    (`{"host": {"name": …}}`, with per-source namespaces two or three levels deeper) while the
    alerting namespace arrives as flat dotted keys. Rendering the top level alone prints a
    nested document as one line per top-level object holding a PYTHON DICT REPR — `host:
    {'name': 'ws-1'}` — which is not a field name anything can be queried on. This block is
    the correlation lead's whole entity evidence and it is asked to name the field each entity
    came from, so a repr is not good enough."""
    out: dict[str, Any] = {}

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, dict) and node:
            for k, v in node.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                walk(v, key)
        elif isinstance(node, list) and any(isinstance(x, dict) for x in node):
            # An ARRAY OF OBJECTS is the same defect one level down, and not exotic: every
            # Kibana alert document carries `kibana.alert.ancestors`, and on the group-id path
            # the documents this block renders ARE alert documents. Indexed (`…ancestors.0.id`)
            # so two elements' same-named leaves stay distinguishable; an array of SCALARS
            # stays whole, since `['a', 'b']` already reads as the multi-valued field it is.
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
        # A null leaf is DROPPED, not rendered: `_sanitize(None)` is the literal string
        # `"None"`, and this block is what the correlation lead picks its axes off —
        # `host.name: None` reads as a bindable value and invites `host.name:"None"`, a
        # predicate that matches nothing and reports as a real zero. An absent field and a null
        # one are the same thing to the index anyway.
        if flat[key] is None:
            continue
        # The field NAME as well as its value: an attacker-influenced document whose KEY
        # carries a `<run-…-…>`-shaped delimiter would otherwise end the untrusted frame early.
        #
        # EVERY leaf is elided, not just `message`: flattening makes every leaf of every
        # namespace its own line, and a captured command line or a rule's stored query is
        # exactly as unbounded as a message.
        lines.append(f"  {_sanitize(key)}: {_sanitize(_elide(flat[key], lead_id, seq))}")
    if flat.get("message") is not None:
        lines.append(f"  message: {_sanitize(_elide(flat['message'], lead_id, seq))}")
    return "\n".join(lines)


def _sort_chrono(docs: list[tuple[dict, int]]) -> list[tuple[dict, int]]:
    """Chronological by each document's own `@timestamp`. Each entry is `(doc, seq)` — the
    queries-table seq of the call that returned it, which the elision pointer names."""
    def key(entry: tuple[dict, int]) -> str:
        return str(entry[0].get("@timestamp") or "")
    return sorted(docs, key=key)


def _unavailable(reason: str) -> str:
    """The reason is SANITIZED: `_unavailable(f"{e!r}")` interpolates the repr of an exception
    whose message can carry attacker-influenced text, and the note lands INSIDE the untrusted
    frame with everything else."""
    return f"{UNAVAILABLE} {_sanitize(reason)})"
