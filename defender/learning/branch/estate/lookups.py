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


def _names(obj: dict, entity: str) -> bool:
    """Does this object identify `entity`?

    A STRING comparison over the object's own values, never a recursive one: a nested object
    naming the entity is that object's business, and the walk reaches it separately. Without
    that bound a patch for one host would land on every ancestor container that happens to hold
    it, which is the whole payload.
    """
    return any(v == entity for v in obj.values() if isinstance(v, str))


def apply_patches(payload: Any, patches: dict[str, dict]) -> tuple[Any, int]:
    """`payload` with every matching entity patched; returns `(payload, applications)`.

    The count is what lets the caller distinguish "this world changed nothing here" from "this
    world does not touch this system" — two different facts that would otherwise both read as
    an untouched response.

    Rebuilt rather than mutated in place, because the base payload is the FAMILY's recording:
    mutating it would edit one sibling's world into the shared row every other sibling replays.
    """
    if not patches:
        return payload, 0
    applied = 0

    def walk(node: Any) -> Any:
        nonlocal applied
        if isinstance(node, list):
            return [walk(item) for item in node]
        if not isinstance(node, dict):
            return node
        out = {k: walk(v) for k, v in node.items()}
        for entity, patch in patches.items():
            if _names(node, entity):
                out.update(patch)
                applied += 1
        return out

    return walk(payload), applied
