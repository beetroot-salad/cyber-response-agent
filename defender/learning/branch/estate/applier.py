"""The world's difference, applied to a real response.

Two hooks, because the seven systems do not divide evenly:

- **`prepare`** — retarget a call at this world's staged corpus before it runs. Only systems
  with a per-vendor stager implement it (today, the event stream). The query engine does its own
  filtering, aggregation and sorting, so a result is correct by construction.
- **`apply`** — patch a response after it runs. Generic; the path for the six state systems.

Vendor knowledge lives in `stagers/`, which is carved out of the shippable-surface gate; the
gate keeps this module vendor-agnostic.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import field
from typing import Any

from defender._model import model
from defender.runtime import case_ticket

from ..ledger import PASSTHROUGH, PATCHED, STAGED
from .lookups import apply_patches
from .stagers.dispatch import STAGERS


def _touches(world: Any, system: str) -> bool:
    """Does this world declare `system`?

    A wrong "no" is silent: every response routes to `passthrough` and the run measures nothing
    while the ledger stays honest.

    A bare string is one name, not a set of characters (`"ticket" in "ticketing"` is true), and
    `world` is untyped here, so nothing upstream refuses that shape.
    """
    declared = getattr(world, "touches", ())
    if isinstance(declared, str):
        declared = (declared,)
    return system in declared


def unappliable(world: Any, patches: Mapping) -> list[str]:
    """The systems in `patches` whose overlay this world could never apply.

    Two silent drops in `apply`, refused where the world is built. A system the world does not
    declare never reaches the patch path and reads `passthrough`. A staged system reports
    `STAGED` and returns the payload untouched (its difference belongs in the documents), so a
    patch naming it would read as confirmation of a change that never happened.
    """
    return sorted(s for s in patches if not _touches(world, s) or s in STAGERS)


#: The one state system whose responses pass a second screen after the patch.
_TICKET_SYSTEM = "ticket"


def unservable(patches: Mapping, mapping: Any | None) -> list[str]:
    """The `ticket` patches whose difference the read screen would empty before the sibling
    ever saw it.

    An unreleased ticket serves no comments, and that screen runs after the patch on every
    ticket response. A patch writing `comments` without moving the ticket to the released status
    authors a difference no query can reach. The fix is to set `status: <released>` in the
    patch.

    The released status is the operator mapping's (`case_ticket.release_predicate`), taken from
    the record's `ticket_mapping` handed in as `mapping` (#1107) — never from the file; a mapping
    that cannot say what it is (or no mapping at all) refuses every such patch, since nothing
    could be served."""
    table = patches.get(_TICKET_SYSTEM)
    if not isinstance(table, Mapping):
        return []
    with_comments = {
        entity: patch for entity, patch in table.items()
        if isinstance(patch, Mapping) and "comments" in patch
    }
    if not with_comments:
        return []
    if mapping is None:
        return [f"{_TICKET_SYSTEM}/{entity}: patches `comments`, but no tenant record "
                "was handed in to say which status releases them" for entity in with_comments]
    try:
        released = case_ticket.release_predicate(mapping).released_status
    except case_ticket.CaseTicketError as e:
        return [f"{_TICKET_SYSTEM}/{entity}: patches `comments`, but the case-history mapping "
                f"cannot say which status releases them ({e})" for entity in with_comments]
    return [
        f"{_TICKET_SYSTEM}/{entity}: patches `comments` on a case it does not also move to "
        f"the released status ({released!r}) — an unreleased case serves no comments (#767), "
        "so the sibling could never observe this difference"
        for entity, patch in with_comments.items() if patch.get("status") != released
    ]


def unnameable(world: Any) -> list[str]:
    """Why each staged system this world declares could not name a view for it, if any.

    A stager derives its view name from the world id; an id it cannot carry refuses every call
    on that system. Only declared systems are checked, since an undeclared stager never names
    anything for this world.
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


@model
class WorldApplier:
    """Stage where a system can be staged, patch where it cannot, and record which.

    An empty patch table is the honest default for a world with no lookup overlay.
    """

    patches: dict[str, dict] = field(default_factory=dict)

    def _staging_world(self, world: Any, system: str) -> str | None:
        """This world's token for `system`, or `None` when `system` is not staged for it.

        `world_id` is the composed token (`<episode>.<label>`), never the short label: the
        alias, ledger file and row key must carry the episode or two episodes' world `b` collide.
        """
        if system not in STAGERS or not _touches(world, system):
            return None
        return world.world_id

    def patch_table(self, world: Any) -> Mapping[str, dict]:
        """The entity patches to apply for `world` — its own overlay, when it carries one.

        The overlay is authored once in the manifest; a patch table passed to the constructor
        beside it would be a second copy that can drift. The constructor field serves only
        callers with a bare world and a separate table (tests, programmatic worlds).

        Read per call because the sibling path constructs `WorldApplier()` with no arguments;
        the world only arrives at `prepare`/`apply`.
        """
        patches = getattr(getattr(world, "overlay", None), "patches", None)
        return patches if isinstance(patches, Mapping) else self.patches

    @staticmethod
    def _overlay(world: Any) -> Any:
        """This world's declared difference, for the stager to narrow its retarget by.

        Without it a touching world would retarget every corpus its calls address, including
        patterns with no staged view, which silently return zero hits while the row reads
        `staged`. `None` means "not told what the world stages", not "stages nothing".
        """
        return getattr(world, "overlay", None)

    def prepare(self, system: str, verb: str, params: dict, world: Any, ctx: Any = None) -> dict:
        """This call, pointed at the world's corpus if the system has one.

        `ctx` lets the stager read the run's config: a call omitting its index addresses the
        configured default, and refusing it would drop an evidence class from the sibling only.
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

        The mirror of `prepare`: the substituted identity is echoed in the response, and
        removing it leaves the staged and base payloads differing only by what the world staged.
        `asked is None` means staging did not move the call, so there is nothing to undo.
        Which field echoes the identity is the stager's knowledge.
        """
        stager = STAGERS.get(system)
        if stager is None or asked is None:
            return payload
        return stager.restore(verb, payload, asked, prepared, ctx)

    def apply(
        self, system: str, verb: str, params: dict, payload: Any, world: Any,  # noqa: ARG002
        asked: dict | None = None,
    ) -> tuple[str, Any]:
        """What this world does to a response that has already run.

        A staged system's difference is already in the documents, so the payload comes back
        untouched, reported `STAGED` (or `PASSTHROUGH` if the call was not moved) — reporting
        keeps "the world changed this" distinct from "the applier never ran".

        Other systems are patched by entity. An untouched system, or patches matching nothing
        in this payload, report `PASSTHROUGH`.

        `asked` is the serve point's `moved`: the params as asked when staging moved the call,
        else `None`.

        `touches` is asked first, then staged-ness, as two separate checks: routing through
        `_staging_world`'s nullable id would send a staged system with a falsy `world_id` down
        the patch path and record the wrong decision.
        """
        if not _touches(world, system):
            return PASSTHROUGH, payload
        if system in STAGERS:
            # Whether the call was moved is a fact handed in, not re-derived. `stages(verb)`
            # would be wrong: `redirect` also passes through a call whose corpus the overlay
            # does not declare, and labelling that `staged` would be "silent scenario deletion
            # wearing an honest label". Re-deriving through the stager would need the overlay
            # and the run's config, and a copy without the config would disagree with `redirect`.
            return (STAGED if asked is not None else PASSTHROUGH), payload
        patched, applied = apply_patches(payload, self.patch_table(world).get(system, {}))
        return (PATCHED, patched) if applied else (PASSTHROUGH, payload)
