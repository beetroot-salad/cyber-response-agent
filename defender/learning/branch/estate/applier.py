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

from collections.abc import Mapping
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


def unappliable(world: Any, patches: Mapping) -> list[str]:
    """The systems in `patches` whose overlay this world could never apply.

    TWO ways an entity patch is dropped in silence, and `apply` below is where both happen, so
    they are named together here and refused where the world is built.

    A system the world does not DECLARE never reaches the patch path at all — `apply` asks
    `touches` first — so the row reads `passthrough`, truthfully, which is what makes it
    invisible.

    A STAGED system never reaches it either, and that one is worse: `apply` reports `STAGED`
    and hands the payload back untouched, because on the event stream a world's difference is
    supposed to be IN the documents the engine read. A patch table naming it is an authoring
    slip that reads as the strongest possible confirmation — a row saying the world was applied
    to a response the world never touched.
    """
    return sorted(s for s in patches if not _touches(world, s) or s in STAGERS)


def unnameable(world: Any) -> list[str]:
    """Why each staged system this world declares could not name a view for it, if any.

    A stager derives its view name from the world id, and an id it cannot carry costs the
    sibling that system's WHOLE evidence class — every call refused, while the base world keeps
    all of it. Asked once, here, because the answer is a property of the id rather than of a
    call, and the alternative is discovering it per served row.

    Only the systems the world DECLARES: a stager whose system this world never touches is
    never asked to name anything for it, so refusing on its rule would refuse a world that is
    perfectly serveable.
    """
    reasons = []
    for system, stager in STAGERS.items():
        if not _touches(world, system):
            continue
        try:
            stager.check_world_id(getattr(world, "world_id", None))
        except Exception as bad_name:  # noqa: BLE001 — the stager owns its own refusal class
            reasons.append(f"{system}: {bad_name}")
    return reasons


@dataclass
class WorldApplier:
    """Stage where a system can be staged, patch where it cannot, and record which.

    The empty patch table is the SIGNATURE's default rather than a coalesce in the body: a
    world with no lookup overlay is the honest empty case, not a missing argument to repair.
    That also keeps the type — `{system: {entity: patch}}` — checked at the seam that decides
    whether a world's difference is applied at all, which `Any` turned off.
    """

    patches: dict[str, dict] = field(default_factory=dict)

    def _staging_world(self, world: Any, system: str) -> str | None:
        """This world's TOKEN for `system`, or `None` when `system` is not staged for it.

        THE WORLD FIRST, and the order is not cosmetic. Four sites compare a world token — the
        stager's view name, the ledger's row key and filename, the serve point's confinement
        declaration, and this one — and all four ask the WORLD for it. Written `(system, world)`
        this frame read as a question about the system that happened to take a world, and it was
        the only one of the four whose first argument was not the thing being identified.

        `world_id` is the composed token (`<episode>.<label>`), never the short manifest label:
        the alias, the ledger file and the row key must each carry the episode, or two episodes'
        world `b` are one world wherever their names meet.
        """
        if system not in STAGERS or not _touches(world, system):
            return None
        return world.world_id

    def patch_table(self, world: Any) -> Mapping[str, dict]:
        """The entity patches to apply for `world` — ITS OWN overlay, when it carries one.

        The overlay is the world's difference, authored once in the manifest and parsed once by
        `_family.parse_overlay`; an applier constructed with a patch table beside it is a second
        copy of the same thing, and the copy that drifts is the one that stops patching. So a
        world carrying an overlay answers for itself, and the constructor field remains for the
        callers that hand a bare world object and its table separately (the estate seam's own
        tests, and any programmatic world assembled without a manifest).

        Read per call rather than folded in at construction because `WorldApplier()` is built
        with NO arguments on the sibling path — the world arrives at `prepare`/`apply`, not at
        `__init__`, and an applier that had to be told the patches up front could not be the
        default the registry constructs for itself.
        """
        patches = getattr(getattr(world, "overlay", None), "patches", None)
        return patches if isinstance(patches, Mapping) else self.patches

    @staticmethod
    def _overlay(world: Any) -> Any:
        """This world's declared difference, for the stager to narrow its retarget by.

        THE SAME READ `patch_table` MAKES, one field over, and it is what wires the stager's
        own `declares` to the only caller that can supply it. Without it a touching world
        retargeted EVERY corpus its calls addressed — including patterns staging never created
        a view for — and a retarget to a name nothing created answers with zero hits in
        silence while the ledger row still reads `staged`.

        A world object carrying no overlay answers `None`, which is "this caller has not been
        told what the world stages" rather than "it stages nothing"; the stager's own docstring
        holds that distinction and keeps its pre-existing behaviour there.
        """
        return getattr(world, "overlay", None)

    def prepare(self, system: str, verb: str, params: dict, world: Any, ctx: Any = None) -> dict:
        """This call, pointed at the world's corpus if the system has one.

        `ctx` rides through because a stager may need the RUN's own config to know where a call
        addresses its corpus. A call that omits its index parameter is not indexless — it is
        naming the run's configured default — and a frame that cannot see that would have to
        refuse a shipped template outright, dropping a whole evidence class from the sibling
        while the base keeps it. That is a base-vs-sibling difference belonging to the harness
        rather than the world, which is the one kind this seam must never manufacture.
        """
        stager = STAGERS.get(system)
        if stager is None:
            return params
        return stager.redirect(verb, params, self._staging_world(world, system), ctx,
                               overlay=self._overlay(world))

    def restore(
        self, system: str, verb: str, payload: Any, asked: dict | None, prepared: dict,
        ctx: Any = None,
    ) -> Any:
        """This response with the world's own corpus identity taken back out.

        THE MIRROR OF `prepare`, and the seam calls them as a pair. `prepare` moves a call onto
        the world's staged corpus; the identity it substituted then comes back echoed in the
        response, so a staged payload differs from its base in a field the world never touched.
        Undone here, the two payloads differ by exactly what the world staged and nothing else,
        which is what makes ΔO over the event stream mean anything.

        `asked is None` is a call staging did not move, so there is nothing to take back — the
        same condition `ServedCall.asked_params` records under, asked once and answered the
        same way in both places.

        Vendor-free, like the rest of this module: WHICH field echoes a corpus identity is the
        stager's knowledge and stays one directory down.
        """
        stager = STAGERS.get(system)
        if stager is None or asked is None:
            return payload
        return stager.restore(verb, payload, asked, prepared, ctx)

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
        stager = STAGERS.get(system)
        if stager is not None:
            # STAGED names what happened to THIS CALL, not what is true of the system. A verb
            # the stager never retargets — a liveness probe reaches no corpus to stage — had a
            # world's difference applied to it in name only, which is a wrong row in the one
            # table built to make wrong rows visible. The stager owns that question because
            # only it knows which of its verbs address a corpus.
            #
            # STILL `stages(verb)` AND NOT `stager.decision`, and the reason is which params
            # this frame holds. `apply` is handed the PREPARED call — the seam calls
            # `apply(system, verb, prepared, …)` — so a stager asked to re-derive its own answer
            # here would read the VIEW name as the call's base pattern, find it in no overlay,
            # and report `passthrough` for every genuinely staged call. The row is therefore
            # still `staged` for a call `redirect` passed through untouched because the world's
            # overlay does not declare its corpus; closing that needs the ASKED params threaded
            # to this frame (the serve point already computes `asked = params if prepared !=
            # params`), which is a change to this seam's contract rather than to its body.
            return (STAGED if stager.stages(verb) else PASSTHROUGH), payload
        patched, applied = apply_patches(payload, self.patch_table(world).get(system, {}))
        return (PATCHED, patched) if applied else (PASSTHROUGH, payload)
