"""The world's difference, applied to a real response.

Two hooks, not one, because the seven systems do not divide evenly:

- **`prepare`** — retarget a call at this world's staged corpus, BEFORE it runs. Only systems
  with a per-vendor stager implement it, and today that is the event stream alone. This is the
  strong path: the corpus is staged and the query engine does its own filtering, aggregation
  and sorting, so a result is correct by construction rather than composed.
- **`apply`** — patch a response AFTER it runs. Generic, every system. The path for the six
  state systems, where there is no engine to hand the work to.

The vendor knowledge lives one directory down in `stagers/`, which is carved out of the
shippable-surface gate for exactly that reason; this module stays agnostic, and the gate is
what keeps it so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..ledger import PASSTHROUGH, PATCHED, STAGED
from .lookups import apply_patches
from .stagers.dispatch import STAGERS


def _touches(world: Any, system: str) -> bool:
    """Does this world declare `system`? ONE spelling, because two would drift.

    `touches` is what decides, and it decides COST as much as semantics: a system no world
    declares is never staged, never patched, and never costs a model call — and a difference
    observed there is corrupt by construction rather than something to explain. Which makes
    the wrong answer here the silent one: a world whose `touches` reads as empty routes every
    response to `passthrough`, and the run measures nothing while every ledger row stays honest.

    A BARE STRING IS ONE NAME, not a set of characters. `"ticket" in "ticketing"` is true, so a
    world handed a plain string rather than a sequence would stage and patch every system whose
    name is a substring of what it declared — and `world` is untyped at this seam, so nothing
    upstream refuses the shape.
    """
    declared = getattr(world, "touches", ())
    if isinstance(declared, str):
        declared = (declared,)
    return system in declared


@dataclass
class WorldApplier:
    """Stage where a system can be staged, patch where it cannot, and record which.

    The empty patch table is the SIGNATURE's default rather than a coalesce in the body: a
    world with no lookup overlay is the honest empty case, not a missing argument to repair.
    That also keeps the type — `{system: {entity: patch}}` — checked at the seam that decides
    whether a world's difference is applied at all, which `Any` turned off.
    """

    patches: dict[str, dict] = field(default_factory=dict)

    def _staging_world(self, system: str, world: Any) -> str | None:
        """This world's id for `system`, or `None` when `system` is not staged for it."""
        if system not in STAGERS or not _touches(world, system):
            return None
        return world.world_id

    def prepare(self, system: str, verb: str, params: dict, world: Any) -> dict:
        stager = STAGERS.get(system)
        if stager is None:
            return params
        return stager.redirect(verb, params, self._staging_world(system, world))

    def apply(
        self, system: str, verb: str, params: dict, payload: Any, world: Any,  # noqa: ARG002
    ) -> tuple[str, Any]:
        """What this world does to a response that has already run.

        A staged system needs nothing done here — the difference is already IN the documents
        the engine read, which is the whole point of staging — so it reports `STAGED` and hands
        the payload back untouched. Reporting rather than staying silent is what keeps "the
        world changed this" distinguishable from "the applier never ran".

        Everything else is patched by entity. A system this world does not touch has no patches
        to find, so it costs nothing and reports `PASSTHROUGH`; a touched system whose patches
        match nothing in THIS payload reports `PASSTHROUGH` too, and truthfully — the world
        changed nothing here.

        The order is `touches` FIRST, then staged-ness — two independent booleans, asked as
        two. Routing through `_staging_world`'s nullable id instead folded a third state in:
        a world whose `world_id` is falsy answers `None` for a system it genuinely stages, and
        the call then fell through to the patch path and recorded `patched`/`passthrough` for a
        staged response — a wrong row in the one table built to make wrong rows visible.
        """
        if not _touches(world, system):
            return PASSTHROUGH, payload
        if system in STAGERS:
            return STAGED, payload
        patched, applied = apply_patches(payload, self.patches.get(system, {}))
        return (PATCHED, patched) if applied else (PASSTHROUGH, payload)
