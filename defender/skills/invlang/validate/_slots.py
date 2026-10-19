"""Open and unresolved vertex-slot vocabulary."""
from __future__ import annotations


from typing import Any








#: The whole-cell open marker, shared by the predicates below and their readers.
OPEN_MARKER = "??"




def is_unresolved(value: Any) -> bool:
    """Does the whole cell say "not settled yet": `??`, or a `{...}` candidate set.

    SKILL.md's progression is `??` → `{a, b}` → concrete, so a candidate set (even `{internal}`)
    is still open. Anchored to the whole value so an attribute that merely contains braces
    does not block a benign close. A value starting with `{` is open if it ends with `}` or has
    an unclosed brace — a dropped `}` (`{internal, dmz`) must not read as concrete — while
    `{ cd /x && ls; } >out` stays concrete.
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if v == OPEN_MARKER:
        return True
    return v.startswith("{") and (v.endswith("}") or v.count("{") > v.count("}"))




def is_ident_open(value: Any) -> bool:
    """Does this `ident` cell still carry an open question, whole-cell or embedded.

    Identifiers are routinely named in part (`bash[pid=??]`, `dev-ws-??`), which `is_unresolved`
    would call settled, breaking lesson retrieval in both directions. The substring test is
    safe here, unlike for attributes, because `??` inside a chosen name is the marker, not
    data; and it feeds retrieval only (`_check_benign_open_slots` passes `include_ident=False`).

    A superset of `is_unresolved`, so a candidate set (`{dev-ws-1, dev-ws-2}`) also reads open.
    """
    return is_unresolved(value) or (isinstance(value, str) and OPEN_MARKER in value)




def class_slots(classification: str) -> list[str]:
    """A class cell's slots: the slash-tuple, minus an optional leading `<type>:` prefix.

    Split only at brace depth 0, so a whole-triple candidate set
    (`{monitoring-agent/internal/known-corp, ip-only/internet/novel}`) is one unresolved slot
    while `role/{internal, dmz}/prov` is three. The `compute:` prefix is stripped because models
    write it, and it would hide a candidate set behind it.

    Public so `runtime/lessons_engine/lessons_frontier.py` splits cells the way `has_open_slot` does.
    """
    c = classification.strip()
    head, sep, rest = c.partition(":")
    if sep and "{" not in head and "/" not in head:
        c = rest.strip()
    slots: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in c:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        elif ch == "/" and depth == 0:
            slots.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    slots.append("".join(cur))
    return [s.strip() for s in slots]




def is_open_slot(slot: str) -> bool:
    """Is this one already-split class slot unresolved.

    Public for `runtime/lessons_engine/lessons_frontier.py`, which holds split slots and must not
    re-split them through `has_open_slot`. An unclosed `{` counts as open (a dropped `}` must not
    read as concrete); a stray `}` hides nothing.
    """
    return is_unresolved(slot) or slot.count("{") > slot.count("}")




def has_open_slot(classification: Any) -> bool:
    if not isinstance(classification, str):
        return False
    return any(is_open_slot(slot) for slot in class_slots(classification))
