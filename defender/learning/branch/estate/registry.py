"""The verb registry a branched run queries through.

Every query executes against the REAL adapter and the world's difference is applied on top of
what comes back. Nothing here composes a query result: for the event stream the corpus is
staged before the query runs and the engine does its own filtering and aggregation, and for the
six state systems an entity patch authored once is applied wherever that entity appears. The
governing rule is **author once, apply mechanically** — a result composed per call is the
mid-run authoring that made the retired oracle fatal (#791).

Subclassing `ModuleVerbRegistry` is REQUIRED, not stylistic. `driver.build_agent_core` refuses
anything failing `isinstance(verbs, VerbRegistry)`, and `VerbRegistry.decide` compares
`verb_class_of(fn)` against the grant — so the served callables have to carry the real adapter
bodies' decoration, which is what `functools.wraps` preserves. Coverage of all seven systems is
then STRUCTURAL: there is no served verb that is not a wrapped one, rather than an enumeration
someone maintains and gets wrong.
"""

from __future__ import annotations

import functools
import json
from typing import Any

from defender.runtime.verbs import ModuleVerbRegistry

from ..ledger import BASE, Ledger, ServedCall
from .applier import WorldApplier


class EstateError(Exception):
    """A world that cannot be served honestly."""


def _payload_text(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, default=str)


class WorldRegistry(ModuleVerbRegistry):
    """A `ModuleVerbRegistry` whose verbs run for real and then answer to the world."""

    def __init__(self, adapters_dir, grant, *, world: Any, ledger: Ledger, applier: Any = None):
        super().__init__(adapters_dir, grant)
        world_id = getattr(world, "world_id", None)
        if not isinstance(world_id, str) or not world_id:
            # `None` is the FAMILY tier's key, so no world may answer to it. A world that did
            # would write its own applied payload into the shared slot `base_payload` reads,
            # and every sibling would then replay one world's difference AS THE ESTATE — while
            # each sibling's own row honestly reported `passthrough`, because from its side
            # nothing was applied. Silent scenario INJECTION, the inverse of the deletion this
            # ledger was built to catch, and invisible in exactly the record that should show it.
            raise EstateError(
                f"a world needs a non-empty string id, got {world_id!r} — `None` is how the "
                "family tier spells 'the shared base', and a world claiming it would overwrite "
                "the recording its siblings replay")
        self.world = world
        self.ledger = ledger
        # lint-default: ok — DI seam owning its default (the stage-or-patch applier; with no
        # patches and a world touching nothing it is the identity, which is exactly what a
        # base world wants)
        self.applier = applier if applier is not None else WorldApplier()

    def verbs(self, system: str):
        """Every verb this system declares, wrapped so no body reaches the caller unwrapped.

        The wrapping is what makes the safety property structural rather than conventional:
        `decide()` resolves through here, and so does the query tool's own second lookup
        (`query_tool.py`'s `registry.verbs(system)[verb]`), so both routes to a callable are
        this one.
        """
        real = super().verbs(system)
        return {name: self._served(system, name, fn) for name, fn in real.items()}

    def _served(self, system: str, verb: str, fn: Any) -> Any:
        applier, ledger, world = self.applier, self.ledger, self.world

        @functools.wraps(fn)
        def served(ctx: Any, **params: Any) -> Any:
            prepared = applier.prepare(system, verb, params, world)
            payload = _base_payload(fn, ctx, prepared, system, verb, ledger)
            decision, out = applier.apply(system, verb, prepared, payload, world)
            # The decision is validated by `Ledger.record`, which OWNS that vocabulary — and it
            # raises before `out` is returned, so an applier that names no honest decision
            # cannot serve. Re-checking it here would put the same rule in two places, and the
            # copy that drifts is the one that stops refusing.
            ledger.record(ServedCall(
                system=system, verb=verb, params=dict(prepared),
                payload_text=_payload_text(out), source=decision,
                world_id=world.world_id,
            ))
            return out

        return served


def _base_payload(fn: Any, ctx: Any, params: dict, system: str, verb: str, ledger: Ledger) -> Any:
    """This key's base answer: the family's recording if one exists, else the live adapter.

    Recorded ONCE PER FAMILY rather than once per world. The estate is live, so two siblings
    calling it minutes apart would get different data and the pair's invariance — the whole
    reason a sibling is worth running — would be a fiction. A hit here issues no adapter call
    at all.
    """
    recorded = ledger.base_payload(system, verb, params)
    if recorded is not None:
        return json.loads(recorded)
    payload = fn(ctx, **params)
    ledger.record(ServedCall(
        system=system, verb=verb, params=dict(params),
        payload_text=_payload_text(payload), source=BASE, world_id=None,
    ))
    return payload
