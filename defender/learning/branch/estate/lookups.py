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
    served call. The set makes the per-node cost independent of the patch table's size.
    """
    return {v for v in obj.values() if isinstance(v, str)}


def apply_patches(payload: Any, patches: dict[str, dict]) -> tuple[Any, int]:
    """`payload` with every matching entity patched; returns `(payload, applications)`.

    The count is what lets the caller distinguish "this world changed nothing here" from "this
    world does not touch this system" — two different facts that would otherwise both read as
    an untouched response.

    Rebuilt rather than mutated in place, because the base payload is the FAMILY's recording:
    mutating it would edit one sibling's world into the shared row every other sibling replays.

    STRUCTURE-SHARED where nothing matched: an untouched subtree is handed back as the SAME
    object, never written into, so the non-mutation guarantee holds while the copying stays
    proportional to what the world actually changed. Rebuilding unconditionally made the
    commonest case — a payload naming none of the patched entities, which the caller then
    discards whole — the most expensive one.
    """
    if not patches:
        return payload, 0
    applied = 0

    def walk(node: Any) -> Any:
        nonlocal applied
        if isinstance(node, list):
            items = [walk(item) for item in node]
            return node if all(new is old for new, old in zip(items, node, strict=True)) else items
        if not isinstance(node, dict):
            return node
        out = {k: walk(v) for k, v in node.items()}
        named = _named(node)
        hits = [patch for entity, patch in patches.items() if entity in named]
        for patch in hits:
            out.update(patch)
        applied += len(hits)
        if hits or any(out[k] is not v for k, v in node.items()):
            return out
        return node

    return walk(payload), applied
