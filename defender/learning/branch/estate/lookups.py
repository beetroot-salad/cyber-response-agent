"""A world's difference applied to a state system's response.

The six systems that are not the event stream have no query engine to hand the work to, so
their difference is applied to the payload after the call.

Patches are keyed per entity, not per response. A patch for `canary-1` lands in every payload
that entity appears in — its own `get-host` record and its row in a `list-hosts` alike —
so the world cannot contradict itself across queries.

Matching is by value, with no per-system knowledge: an entity is patched wherever an object
names it, in whatever field (`host`, `name`, `hostname`, `ci_name`). The cost is false positives
(an object mentioning `canary-1` for an unrelated reason is patched too); every application
lands in the ledger, so an over-broad patch is visible.
"""

from __future__ import annotations

import copy
from typing import Any


def _named(obj: dict) -> set:
    """The entity names this object could identify: its own string values, not nested ones.

    Nested objects are reached separately by the walk; recursing here would patch every
    ancestor container. Collected once per node so per-node cost does not scale with the
    number of patched entities.
    """
    return {v for v in obj.values() if isinstance(v, str)}


def _hits(node: dict, patches: dict[str, dict]) -> list[dict]:
    """The patches this node's own names select, in the table's order.

    Probes the table with the node's names rather than sweeping the table per node. With
    several hits, the table's order (not a set's) keeps resolution deterministic.
    """
    matched = _named(node) & patches.keys()
    if not matched:
        return []
    if len(matched) == 1:
        return [patches[next(iter(matched))]]
    return [patches[entity] for entity in patches if entity in matched]


def _rebuilt_list(node: list, walk: Any) -> list:
    """`node` with every element walked — the same object back when none of them moved.

    The copy is deferred until the first changed element, so the common no-match case
    allocates nothing.
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

    The count lets the caller tell "this world changed nothing here" from "this world does not
    touch this system".

    `applications` counts content changes, not entity-name hits: a patch that writes only values
    the node already held (or an empty patch) does not count. The ledger `source`, the
    world-rejection gate and `judge/family.py`'s `doctored_answer_served` all rely on this.

    Rebuilt, never mutated: the base payload is the family's shared recording, so mutating it
    would leak one sibling's world into every other sibling's replay. Untouched subtrees are
    returned as the same objects, with no allocation, so copying is proportional to what
    changed.

    Patches are deep-copied in, never referenced: the overlay lives for the whole run, and a
    caller mutating a served payload would otherwise edit the world for every later call.
    """
    if not patches:
        return payload, 0
    counter = [0]
    return _walk_patched(payload, patches, counter), counter[0]


def _apply_hits(node: dict, out: dict | None, hits: list[dict], counter: list[int]) -> dict:
    """`node` (or its already-child-rebuilt `out`) with every hit merged in.

    Module-level with a list counter rather than a closure with `nonlocal`, because mccabe
    counts a closure's branches against its enclosing function and this keeps `_walk_patched`
    under the complexity gate.
    """
    working = dict(node) if out is None else dict(out)
    for patch in hits:
        merged = dict(working)
        merged.update(copy.deepcopy(patch))
        # Counted per patch: each entity counts only if it actually changes content.
        if merged != working:
            counter[0] += 1
        working = merged
    return working


def _walk_patched(node: Any, patches: dict[str, dict], counter: list[int]) -> Any:
    """`node` with every matching entity patched, `counter[0]` incremented per content change."""
    if isinstance(node, list):
        return _rebuilt_list(node, lambda item: _walk_patched(item, patches, counter))
    if not isinstance(node, dict):
        return node
    out: dict | None = None
    for k, v in node.items():
        walked = _walk_patched(v, patches, counter)
        if walked is not v and out is None:
            out = dict(node)
        if out is not None:
            out[k] = walked
    hits = _hits(node, patches)
    if hits:
        out = _apply_hits(node, out, hits, counter)
    return node if out is None else out
