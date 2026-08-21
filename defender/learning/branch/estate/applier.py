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

from typing import Any

from ..ledger import PASSTHROUGH, PATCHED, STAGED
from .lookups import apply_patches
from .stagers.dispatch import STAGERS


class WorldApplier:
    """Stage where a system can be staged, patch where it cannot, and record which."""

    def __init__(self, patches: Any = None):
        # lint-default: ok — DI seam owning its default (no patches is the honest empty table,
        # and PR 1's whole lookup overlay)
        self.patches = patches if patches is not None else {}

    def _staging_world(self, system: str, world: Any) -> str | None:
        """This world's id for `system`, or `None` when `system` is not staged for it.

        `touches` is what decides, and it decides COST as much as semantics: a system no world
        declares is never staged, never patched, and never costs a model call — and a
        difference observed there is corrupt by construction rather than something to explain.
        """
        if system not in STAGERS:
            return None
        if system not in getattr(world, "touches", ()):
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
        """
        if self._staging_world(system, world) is not None:
            return STAGED, payload
        if system not in getattr(world, "touches", ()):
            return PASSTHROUGH, payload
        patched, applied = apply_patches(payload, self.patches.get(system, {}))
        return (PATCHED, patched) if applied else (PASSTHROUGH, payload)
