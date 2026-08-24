"""A world's difference applied to a state system's response.

The six systems that are not the event stream have no query engine to hand the work to, so
their difference is applied to the payload after the call. What matters is the KEY it is
authored under.

**Per entity, not per response.** A patch decided once for `canary-1` lands in every payload
`canary-1` appears in — its own `get-host` record and its row inside a fifty-host `list-hosts`
alike. Authored per response instead, those are two independent decisions that can disagree,
and the world then contradicts itself across queries: the host has an owner when asked about
directly and none when listed. That is #845's constraint — *the overlay is authored once and
applied by code, or siblings contradict across queries* — and it is the same principle staging
buys for free on the event side, where one corpus answers every query over it.

MATCHING IS BY VALUE, and deliberately carries no per-system knowledge. An entity is patched
wherever an object names it, whatever field it happens to be named in — `host`, `name`,
`hostname`, `ci_name`, the seven systems do not agree and this seam does not need them to.
The cost is a false positive: an object that mentions `canary-1` for an unrelated reason is
patched too. Round one accepts that and records it — every application lands in the ledger, so
an over-broad patch is visible rather than silent, which is the trade the alternative (a
per-system rule for where entities live) does not obviously beat.
"""

from __future__ import annotations

import copy
from typing import Any


def _named(obj: dict) -> set:
    """The entity names this object could identify: its own STRING values, never a recursive
    read.

    A nested object naming the entity is that object's business, and the walk reaches it
    separately. Without that bound a patch for one host would land on every ancestor container
    that happens to hold it, which is the whole payload.

    Collected ONCE per node rather than rescanned per entity. Asked the other way round — "does
    this object name entity E?", for each E — the same field scan runs once per patch, so a
    world with thirty patched entities reads every string in the payload thirty times on every
    served call. The set is half of what makes the per-node cost independent of the patch
    table's size; PROBING the table with it rather than scanning the table is the other half,
    and `apply_patches` owes it the same way round.
    """
    return {v for v in obj.values() if isinstance(v, str)}


def _hits(node: dict, patches: dict[str, dict]) -> list[dict]:
    """The patches this node's own names select, in the table's order.

    PROBED with the node's names — `len(names)` dict lookups — rather than sweeping the table
    for each node, which is `len(patches)` membership tests per node and puts the patch table's
    size back into the per-node cost `_named`'s set was collected to remove. The multi-hit case
    falls back to the table's own order so a node two entities both name resolves the same way
    every run; a set's iteration order would not.
    """
    matched = _named(node) & patches.keys()
    if not matched:
        return []
    if len(matched) == 1:
        return [patches[next(iter(matched))]]
    return [patches[entity] for entity in patches if entity in matched]


def _rebuilt_list(node: list, walk: Any) -> list:
    """`node` with every element walked — the SAME object back when none of them moved.

    The deferral the dict arm makes, made here too. Building the replacement list first and
    comparing afterwards paid one list of N pointers (plus N zip tuples) per list node on the
    commonest case by far: a payload naming none of the patched entities, which the caller then
    discards whole.
    """
    items: list | None = None
    for i, item in enumerate(node):
        walked = walk(item)
        if walked is not item:
            if items is None:
                items = list(node)
            items[i] = walked
    return node if items is None else items


def apply_patches(payload: Any, patches: dict[str, dict]) -> tuple[Any, int]:
    """`payload` with every matching entity patched; returns `(payload, applications)`.

    The count is what lets the caller distinguish "this world changed nothing here" from "this
    world does not touch this system" — two different facts that would otherwise both read as
    an untouched response.

    Rebuilt rather than mutated in place, because the base payload is the FAMILY's recording:
    mutating it would edit one sibling's world into the shared row every other sibling replays.

    STRUCTURE-SHARED where nothing matched: an untouched subtree is handed back as the SAME
    object, and no dict OR LIST is allocated for it either — the copy is made on the first
    child that moved or the first hit, so the copying really is proportional to what the
    world changed rather than merely the object that comes back. Rebuilding unconditionally made the
    commonest case — a payload naming none of the patched entities, which the caller then
    discards whole — the most expensive one, at one dict and one set per node of the tree.

    THE PATCH IS COPIED IN, never referenced in. The overlay is authored once and lives for the
    whole run, so writing its own objects into a served payload hands the caller a mutable
    handle on the world itself: one `payload["hosts"][0]["tags"].append(...)` downstream and
    every later call — and every sibling sharing the applier — serves the edited overlay. That
    is the same "author once, apply mechanically" rule read from the other side.
    """
    if not patches:
        return payload, 0
    applied = 0

    def walk(node: Any) -> Any:
        nonlocal applied
        if isinstance(node, list):
            return _rebuilt_list(node, walk)
        if not isinstance(node, dict):
            return node
        out: dict | None = None
        for k, v in node.items():
            walked = walk(v)
            if walked is not v and out is None:
                out = dict(node)
            if out is not None:
                out[k] = walked
        hits = _hits(node, patches)
        if hits:
            out = dict(node) if out is None else out
            for patch in hits:
                out.update(copy.deepcopy(patch))
            applied += len(hits)
        return node if out is None else out

    return walk(payload), applied
