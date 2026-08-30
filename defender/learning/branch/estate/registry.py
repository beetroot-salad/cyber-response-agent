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
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from defender.runtime.verbs import ModuleVerbRegistry
from defender.runtime.verb_grant import VerbGrant
from defender.scripts.adapters.confinement import (
    VIEW_NAMESPACE,
    ConfinementFault,
    is_world_view,
)
from defender.scripts.adapters.faults import USAGE_EXIT_CODE

from ..ledger import BASE, FAULT, REFUSED, Ledger, LedgerError, ServedCall, payload_text
from . import applier as applier_module
from .applier import WorldApplier
from .stagers.dispatch import STAGERS


class EstateError(Exception):
    """A world that cannot be served honestly."""


def validate_world_touches(derived: Any, grant: VerbGrant) -> tuple[str, ...]:
    """Validate the systems a world's difference touches against its serving grant.

    THE DERIVED SET, not an authored field (D2). `World.touches` retires as something a manifest
    spells: the systems a world touches are read off its overlay by `_family.touches_of` on every
    read, because a stored set is a second place for the answer to live and the copy that drifts
    is the one that stops staging. What stays is this check — a derived name can still be a name
    this ROLE may not query, and an overlay keyed on a system outside the grant would apply no
    difference while every ledger row read honestly.

    A declaration is authoring input, not an advisory label: it decides whether staging or
    patches run at all. An unknown name therefore cannot be allowed to degrade to the honest
    `passthrough` decision every real adapter makes for it. The grant is the authoritative
    roster because a system outside it cannot be queried by this role even if an adapter file
    happens to exist.

    Kept as one helper for both the manifest boundary and this registry boundary. The launcher
    can then refuse before priming an immutable episode, while programmatic callers cannot
    bypass the check by constructing a world directly — and both ask the same question of the
    same value, since neither of them authors it any more.

    Typed `Any` rather than `Iterable[str]`, deliberately: what arrives is unvalidated authoring
    input, and the shapes refused below (a bare string, a non-sequence, a non-string name) are
    exactly the ones an annotation would have promised away without checking.
    """
    declared = derived
    if not isinstance(declared, (str, list, tuple, set, frozenset)):
        raise EstateError(
            f"a world's `touches` must be a sequence of system names (or one name), got "
            f"{declared!r} — an unreadable `touches` routes every response to `passthrough` "
            "and the run then measures nothing with every row still reading honestly")

    names = (declared,) if isinstance(declared, str) else tuple(declared)
    malformed = [name for name in names if not isinstance(name, str) or not name]
    if malformed:
        raise EstateError(
            f"a world's `touches` contains invalid system name(s) {malformed!r} — every name "
            "must be a non-empty string from the serving role's grant")

    unknown = sorted(set(names) - grant.systems)
    if unknown:
        raise EstateError(
            f"a world's `touches` names unknown or unavailable system(s) {unknown}; systems "
            f"served to role {grant.role!r} are {sorted(grant.systems)} — an unknown name "
            "would apply no difference and record only `passthrough` rows")
    return names


@dataclass(frozen=True)
class ServingWorld:
    """A world as the serving path needs it: a token, the systems it touches, its difference.

    The three fields every serving site reads off `ResumeWorld`, with none of the manifest half
    a call cannot use — so a caller serving ONE call (the review's replay, a probe, this
    module's own serve point) does not have to materialise an episode directory and a `Family`
    to ask a question about an index name.

    `touches` is passed rather than re-derived because a caller may legitimately serve a world
    that touches LESS than its overlay would imply — the control world in a triplet is exactly
    that: an empty overlay and an empty set, which is the world the isolation refusal has to
    cover, since its applier returns every call untouched and threads no world label at all.
    """

    world_id: str
    touches: tuple[str, ...]
    overlay: Any


def world_for(*, token: str, touches: Iterable[str], overlay: Any) -> ServingWorld:
    """Build a serving world from the three things a served call needs to know.

    THE TOKEN, never the short manifest label. `world_id` reaches the stager's view name, the
    ledger's row key and the confinement declaration below unfiltered, and each of those has to
    carry the episode or two episodes' world `b` collide in one alias, one filename and one row.

    The overlay is PARSED when it arrives as a document, by the manifest's own parser, so a
    world assembled here and a world loaded from `family.yaml` carry the same object and the
    applier has one shape to read. `{}` is the base world's own overlay and is legal — the empty
    difference is a world, not a missing argument.
    """
    # Imported HERE rather than at module scope: the manifest module reads the corpus patterns
    # off this package's own stager (`_family._configured_patterns`), so a top-level import
    # would close a cycle between the two halves of the branch — and the estate must stay
    # importable by a run that never loads a manifest at all.
    from defender.runtime.branch._family import Overlay, parse_overlay

    parsed = overlay if isinstance(overlay, Overlay) else parse_overlay(overlay)
    return ServingWorld(world_id=token, touches=tuple(touches), overlay=parsed)


def refuse_a_foreign_world_view(world: Any, system: str, verb: str, params: Mapping) -> None:
    """Refuse a call that names ANOTHER world's staged view, before anything runs (FORK-6).

    Inside one episode the siblings share a cluster, and each stages its own private corpus
    under the view namespace. A world naming a SIBLING's view by hand reads that sibling's
    injected documents and the effect of its exclusions — the one cross-world channel the whole
    per-world-view scheme exists to close.

    **ABOVE PER-WORLD STAGING, and that placement is what the executed probe forced.** A world
    that DOES stage this system has its foreign name rewritten by the stager — `FROM wv-c-…`
    comes back as `wv-a-wv-c-…`, a view of nothing — so a check written into the stager passes
    its own test while the live hole stays open: the world that can actually make the read is
    the CONTROL, which stages nothing, whose applier hands the parameters straight back and
    threads no world label onto the context. Every episode with a control has exactly one such
    sibling by construction. Asked here, above the applier, the control is covered by the same
    line as its staging siblings.

    **AND NOT IN THE OUTBOUND HTTP GUARD**, which is where a target-fidelity check would
    otherwise live. `guard_outbound` is handed the URL, and the index is in the URL for the
    param-indexed arm (`/wv-a-logs-/_search`) and inside the request BODY for the query-language
    arm (`/_query`) — so the guard can only see half the traffic, and the half it cannot see is
    the one the probe drove through to the transport unrefused.

    Both query languages are read through the STAGER's own source reader, because which of a
    verb's parameters addresses a corpus is vendor knowledge and has one home. `ctx` is not
    passed: an omitted index resolves to the run's configured default, which is a configured
    pattern and cannot be a foreign view — so the config read is pure cost here, and skipping it
    keeps this frame total. A body this seam cannot parse is left to `prepare`, which parses it
    again and raises the stager's own refusal for the world that stages; for a world that does
    not, it is a call that names no view and there is nothing here to answer.
    """
    stager = STAGERS.get(system)
    reader = getattr(stager, "source_pattern", None) if stager is not None else None
    if stager is None or reader is None:
        return
    try:
        source = reader(verb, dict(params), None)
    except Exception:  # noqa: BLE001 — see docstring: an unparseable body is `prepare`'s answer
        # NOT UNCONDITIONALLY, though, and this is the half the docstring's "left to `prepare`"
        # argument does not cover. `prepare` answers for a world that STAGES this system; a
        # world that stages nothing gets its params handed straight back, and `esql` carries no
        # index confinement at all — so an expression the reader refuses to reduce to one source
        # (`FROM logs-*, wv-<other>-logs-`, which is exactly how a multi-source read spells a
        # foreign view beside a legal one) reached the transport unrefused for the one world the
        # guard's own docstring names as the one that can make the read. Nothing here parses the
        # expression a second time: an unreducible call that MENTIONS the namespace at all is
        # refused, and one that does not is the ordinary unparseable body `prepare` answers for.
        if _names_the_namespace(params):
            raise ConfinementFault(
                "the call names the staged view namespace inside an index expression this seam "
                "cannot reduce to a single corpus — refused before the call was issued, because "
                "a multi-source read is how a foreign view rides alongside a legal one") from None
        return
    if not isinstance(source, str) or not source.startswith(f"{VIEW_NAMESPACE}-"):
        return
    # THE WORLD'S OWN VIEW STAYS ADMISSIBLE, so the refusal is a boundary rather than a channel
    # that answers nothing — and only for a system this world actually stages, since a world
    # that stages nothing has no view of its own for any name to be.
    if system in getattr(world, "touches", ()) and is_world_view(
            source, stager.configured_patterns(), world.world_id):
        return
    raise ConfinementFault(
        f"index expression {source!r} names a staged corpus this world does not read — "
        "refused before the call was issued")


def _names_the_namespace(params: Mapping) -> bool:
    """Does any parameter value mention the staged view namespace at all?

    A LAST LINE, not a parser. It is asked only where the vendor reader has already refused to
    reduce the call to one corpus, and it answers the one question that still matters there:
    could this call be addressing a staged view? No legitimate model-authored query names the
    namespace — the whole scheme exists so the model never learns it — so a mention is either
    the world's own view spelled by hand or a sibling's, and both are refusals at this seam.
    """
    prefix = f"{VIEW_NAMESPACE}-"
    return any(prefix in value for value in params.values() if isinstance(value, str))


@dataclass(frozen=True)
class Served:
    """One call's whole passage through the serve point, as the order produced it.

    The RECORD rather than just the answer, because the two callers need different parts of it
    and neither may re-derive its own: `serve_one`'s simple callers want `out`, and the registry
    wants `prepared`, `moved` and `decision` for the ledger rows it writes around the same
    passage. Handing back only `out` is what left the registry re-spelling the order inline to
    get at the rest.
    """

    #: The params as the caller asked them, before any retarget.
    asked: dict
    #: The params the adapter was actually called with.
    prepared: dict
    #: `asked`, but ONLY when staging moved the call — the same condition the ledger records
    #: `asked_params` under, and the one `restore` un-echoes on.
    moved: dict | None
    #: What came back, with the world's corpus identity taken back out.
    payload: Any
    #: The ledger's word for what this world did to the call.
    decision: str
    #: What the caller gets.
    out: Any


def serve_one(world: Any, system: str, verb: str, params: Mapping, *, adapters: Any = None,
              applier: Any = None, ctx: Any = None, run: Any = None) -> Served:
    """Serve ONE call for `world` — the serve point, above staging. THE order, spelled once.

    The narrow waist every branched read passes: refuse first, then let the world's applier
    point the call at its own corpus, then run it, then take the world's corpus identity back
    out of what came back, then ask the world what it did to it. `WorldRegistry._served` is this
    frame with the ledger's four row-writing arms around it, and it CALLS this one — which is
    the whole point. Spelled twice, the fuzz suite that proves the ordering proved it of a frame
    production never ran, and a fix to either copy left the other one unmoved.

    THE REFUSAL IS FIRST AND OUTSIDE EVERYTHING. It runs before `prepare`, so no stager gets to
    rewrite a foreign name into a harmless one; and before the adapter is called at all, so a
    refused cross-world read leaves no call on the wire and no row claiming one was made.

    `restore` is the mirror of `prepare` and is called on the same condition the ledger records
    `asked_params` under — the call staging moved is the call whose echoed corpus identity has
    to come back out.

    `run` IS THE ONE THING THE TWO CALLERS DO DIFFERENTLY, so it is the one thing that is a
    seam. A plain caller has an adapter layer and wants the call made; the registry has a FAMILY
    TIER in front of the adapter — `_base_payload`, which answers a key the capture already
    holds without issuing a call at all — and a restore that has to happen inside that miss. It
    is handed `(prepared, moved)` and owes back the restored payload, so everything on either
    side of it stays here, in one order, for both.
    """
    refuse_a_foreign_world_view(world, system, verb, params)
    applier = (  # lint-default: ok — DI seam owning its default, the same one `WorldRegistry` resolves at construction  # noqa: E501
        applier if applier is not None else WorldApplier())
    asked = dict(params)
    prepared = applier.prepare(system, verb, dict(asked), world, ctx)
    moved = asked if prepared != asked else None
    if run is None:
        if adapters is None:
            raise EstateError(
                "serve_one needs either an adapter layer or a `run` seam — with neither there "
                "is nothing to make the call, and a frame that returned the prepared params as "
                "if they were an answer would be a served response with no call behind it")
        payload = applier.restore(
            system, verb, adapters(system, verb, **prepared), moved, prepared, ctx)
    else:
        payload = run(prepared, moved)
    # `moved`, not `asked`: the row must say whether staging MOVED this call, which is
    # the same fact `restore` un-echoes on and the ledger records `asked_params` under.
    decision, out = applier.apply(system, verb, prepared, payload, world, moved)
    return Served(asked=asked, prepared=prepared, moved=moved, payload=payload,
                  decision=decision, out=out)


class WorldRegistry(ModuleVerbRegistry):
    """A `ModuleVerbRegistry` whose verbs run for real and then answer to the world."""

    def __init__(self, adapters_dir, grant, *, world: Any, ledger: Ledger, as_of: datetime,
                 applier: Any = None):
        super().__init__(adapters_dir, grant)
        # THE CLOCK FIRST, and read ONCE here rather than per call. A `TypeError` or an
        # `AttributeError` raised deep inside `served` is not an `AdapterFault`, so the query
        # tool files it as `DEFAULT_FAULT_EXIT` — which is 2, which is in
        # `circuit_breaker.INFRA_EXIT_CODES`: two of those trip the breaker for the system and
        # five abort the run, IN THE SIBLING AND NOT IN ITS BASE. That is the "the estate was up
        # for one and down for the other" contamination the whole base/sibling design exists to
        # exclude, and it would arrive from the field added to prevent a different one.
        #
        # `utcoffset() == timedelta(0)`, not `tzinfo is not None`: an aware datetime in any
        # other zone passes the weaker test and then formats a trailing `Z` that lies by its
        # offset. Every payload stamped from it is wrong by the same amount, consistently, which
        # is precisely the kind of wrong nothing downstream can see.
        if not isinstance(as_of, datetime):
            raise EstateError(
                f"a world needs the moment it is being served as of, got {as_of!r} — without it "
                "every timestamp a sibling mints is the afternoon it executed rather than the "
                "branch point it resumed into, and the episode cannot be replayed")
        if as_of.tzinfo is None or as_of.utcoffset() != timedelta(0):
            raise EstateError(
                f"as_of must be an aware UTC datetime, got {as_of!r} (offset "
                f"{as_of.utcoffset()!r}) — a naive or offset moment formats a `Z` that lies by "
                "that offset")
        self.as_of = as_of
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
        # Unknown names route every real response to `passthrough`, so a misspelt difference
        # vanishes while the ledger remains internally honest. The CLI calls this before
        # priming; this call is the non-bypassable boundary for programmatic worlds.
        declared = validate_world_touches(getattr(world, "touches", ()), grant)
        # AND NAMEABLE, which `str` and non-empty do not cover. A staged system derives its
        # per-world corpus name from this id, so one a stager cannot carry does not fail a
        # query, it fails EVERY query on that system — the sibling records a `refused` row per
        # call and loses the whole event stream while the base keeps it. Read here, where the
        # world arrives, for the same reason `touches` is: the answer is a property of the id,
        # not of a call, and per-call is where it reads as a sibling that simply asked nothing.
        unnameable = applier_module.unnameable(world)
        if unnameable:
            raise EstateError(
                f"world {world_id!r} declares a staged system whose view it cannot be named "
                f"in ({unnameable}) — the id reaches the corpus name unfiltered, so every "
                "staged call would be refused and the sibling would measure nothing")
        self.world = world
        self.ledger = ledger
        self.applier = (  # lint-default: ok — DI seam owning its default (the stage-or-patch applier; with no patches and a world touching nothing it is the identity, which is exactly what a base world wants)  # noqa: E501
            applier if applier is not None else WorldApplier())
        # A PATCH THE APPLIER COULD NEVER APPLY IS AN AUTHORING SLIP, and `unappliable` owns
        # both ways to write one — a system the world does not declare, and a STAGED system,
        # whose difference is supposed to live in the documents the engine read rather than in
        # a patch table. Either way the overlay is dropped in silence, so it is refused where
        # both halves of a world are in hand rather than left to read as a world that changed
        # nothing (or, for the staged half, as one that changed everything).
        #
        # A `Mapping` rather than a `dict`, because an applier is a DI seam and a read-only
        # mapping is a reasonable thing to hand one; `isinstance(..., dict)` skipped the whole
        # check for it without a word.
        # THE EFFECTIVE TABLE, which is the world's own overlay wherever it carries one — the
        # applier reads the patches off the world at `apply` time (D2: one authored copy), so a
        # constructor field is only what is applied for a world assembled without a manifest.
        # Asking the constructor field here would check a table this world will never be served
        # from and skip the one it will.
        table = getattr(self.applier, "patch_table", None)
        patches = table(world) if callable(table) else getattr(self.applier, "patches", None)
        if isinstance(patches, Mapping):
            unappliable = applier_module.unappliable(world, patches)
            if unappliable:
                raise EstateError(
                    f"world {world_id!r} carries patches for {unappliable}, which its applier "
                    f"can never apply — `touches` is {declared!r} and a staged system is served "
                    "from its corpus rather than patched, so the overlay would be silently "
                    "dropped while every row still read honestly")
        self._wrapped: dict[str, dict[str, Any]] = {}

    def verbs(self, system: str):
        """Every verb this system declares, wrapped so no body reaches the caller unwrapped.

        The wrapping is what makes the safety property structural rather than conventional:
        `decide()` resolves through here, and so does the query tool's own second lookup
        (`query_tool.py`'s `registry.verbs(system)[verb]`), so both routes to a callable are
        this one.

        WRAPPED ONCE PER SYSTEM. Both of those routes run on every `query` tool call, and
        `_tool_list_verbs` runs `decide()` once per verb on top of its own lookup — so building
        a fresh closure set per call is N wrappers per lookup and N(N+1) per `list_verbs`, all
        but one of them born and discarded in the same statement. The memo is sound because
        `served` reads its collaborators off `self` at CALL time rather than closing over them
        here: a cached wrapper cannot go stale against an applier or ledger replaced later.
        `super().verbs` still raises `KeyError` for an unknown system, which
        `_list_verbs_declared` depends on, because the miss is what populates the entry.

        A COPY comes back, not the memo itself — `ModuleVerbRegistry.verbs` ends `return
        dict(verbs)` and callers may treat that freedom as theirs. Handing out the live memo
        would let one caller's edit reach every later lookup, including `decide`'s.
        """
        if system not in self._wrapped:
            real = super().verbs(system)
            self._wrapped[system] = {
                name: self._served(system, name, fn) for name, fn in real.items()
            }
        return dict(self._wrapped[system])

    def _served(self, system: str, verb: str, fn: Any) -> Any:
        @functools.wraps(fn)
        def served(ctx: Any, **params: Any) -> Any:
            applier, ledger, world = self.applier, self.ledger, self.world
            # UNCONDITIONAL, and that is the whole point — unlike the `world_id` declaration
            # below, which fires only where staging MOVED the call. The two conditions look
            # alike and are not: a declaration widens what a call may reach (`confine_index`
            # admits a world's views by declaration, so setting it on an untouched call would
            # admit that world's views for a read that was never retargeted), while a clock
            # admits nothing and narrows nothing. And the adapter that makes an episode
            # unreplayable by stamping the wall clock into its payload is host-state, which has
            # no stager and is never staged — so a clock scoped to staged calls would miss
            # every call it exists for. Both go through `_carrying`, which holds the GUARD and
            # leaves the CONDITION here, where it is visible beside the other one.
            #
            # Rebound BEFORE `applier.prepare`, so the stager and `restore` see the same moment
            # the adapter body will. Cannot raise — `_carrying`'s guards are total and `as_of`
            # was validated at construction — which matters because this line sits OUTSIDE the
            # refusal handler below.
            ctx = _carrying(ctx, as_of=self.as_of)
            # WHAT THE RUN ARM REACHED, for the two recording arms below. The order itself is
            # `serve_one`'s; the only thing this frame needs back out of it before it finishes
            # is how far the call got, because the two rows a failure writes are different rows
            # (see each handler). Empty until `run` is entered, which is exactly the boundary
            # between them.
            reached: dict[str, Any] = {}

            def run(prepared: dict, moved: dict | None) -> Any:
                """The FAMILY TIER in front of the adapter, and the restore inside its miss."""
                reached.update(prepared=prepared, moved=moved)
                payload, reached["base_text"] = _base_payload(
                    fn, _carrying(ctx, world_id=world.world_id) if moved is not None else ctx,
                    prepared, system, verb, ledger, moved,
                    # BEFORE the base row is written, so the FAMILY's shared recording carries
                    # no world's identity. That row is replayed by every sibling, and it is
                    # made by whichever world called first — so a staged recording would hand
                    # every other sibling the first one's view name as if it were the estate's.
                    lambda served_payload: applier.restore(
                        system, verb, served_payload, moved, prepared, ctx),
                )
                return payload

            try:
                # THE ORDER, THROUGH THE FRAME THAT OWNS IT. The refusal, the retarget, the
                # call, the restore and the decision are `serve_one`'s — this frame supplies
                # only the family tier (`run`) and the ledger rows around it. Spelled inline
                # here, as it was, the 240-case isolation fuzz drove the OTHER copy: it proved
                # the refusal came first in a frame no sibling process ever entered.
                #
                # `applier` is a DI seam: one that retargets IN PLACE and returns the same
                # object leaves `prepared is params`, so `moved` is `None` for a call staging
                # DID move — and three things then silently switch off at once (the `world_id`
                # the adapter's confinement needs to admit this world's own view, `restore`'s
                # un-echo of the staged identity, and the `asked_params` column
                # `correlation_key` pairs on), with every row still reading honestly. The copy
                # `serve_one` hands `prepare` is what keeps that comparison meaningful.
                passage = serve_one(world, system, verb, params,
                                    applier=applier, ctx=ctx, run=run)
            except LedgerError:
                # The table's own refusal, already accounted for. Recording a second row for it
                # would answer "the ledger would not write this" with another write.
                raise
            except Exception as failure:
                if "prepared" not in reached:
                    # BEFORE THE CALL WAS MADE: the isolation refusal, or the retarget itself.
                    # A refusal is EVIDENCE, and an unrecorded one is indistinguishable from the
                    # sibling never asking. Recorded against the params as ASKED — the retarget
                    # is exactly what failed, so there is no prepared form to name — then
                    # re-raised so the query tool still turns it into the fault row the model
                    # reads.
                    #
                    # WHICH class, though, is the exit code's answer and not this frame's.
                    # `prepare` reads the run's config to resolve a default index, so an
                    # ENVIRONMENT fault (a missing config file, a missing key) surfaces here too
                    # — and filing that as `refused` splits one outage along the base/sibling
                    # axis: the base world returns from `redirect` before ever reading the
                    # config, takes the identical fault out of the adapter body below, and
                    # records `fault`. One outage, two decision classes, divided by exactly the
                    # thing the table exists to measure. `refused` is the capability answer,
                    # which is the one the stager marks usage.
                    _record_beside(ledger, ServedCall(
                        system=system, verb=verb, params=dict(params),
                        payload_text=str(failure),
                        source=(
                            REFUSED if getattr(failure, "exit_code", None) == USAGE_EXIT_CODE
                            else FAULT
                        ),
                        world_id=world.world_id,
                    ))
                    raise
                # AN ESTATE FAULT IS A RESPONSE. `QueryCapture` catches whatever the body raises
                # and hands the model a fault row, so the defender HAS seen an answer here — and
                # a seam that wrote nothing would leave exactly the state this table exists to
                # make visible, "a served response with no row". Recorded against the params as
                # RUN, because the retarget succeeded and it is the prepared call that faulted;
                # `asked_params` rides along for the same reason it does below, so a staged
                # fault can still find its opposite number. Re-raised untouched.
                _record_beside(ledger, ServedCall(
                    system=system, verb=verb, params=dict(reached["prepared"]),
                    payload_text=str(failure) or type(failure).__name__, source=FAULT,
                    world_id=world.world_id,
                    asked_params=reached["moved"],
                ))
                raise
            prepared, asked, out = passage.prepared, passage.moved, passage.out
            payload, decision, base_text = (
                passage.payload, passage.decision, reached["base_text"])
            # `out is payload` on every decision that changes nothing (STAGED, PASSTHROUGH), and
            # the base text is then the served text — the same bytes `payload_text` would
            # produce, since it is deterministic and already ran over this object. Re-dumping a
            # multi-hundred-KB result to rediscover that is the single most expensive thing the
            # seam did per call.
            #
            # The decision is validated by `Ledger.record`, which OWNS that vocabulary — and it
            # raises before `out` is returned, so an applier that names no honest decision
            # cannot serve. Re-checking it here would put the same rule in two places, and the
            # copy that drifts is the one that stops refusing.
            ledger.record(ServedCall(
                system=system, verb=verb, params=dict(prepared),
                payload_text=base_text if out is payload else payload_text(out),
                source=decision, world_id=world.world_id,
                # Only when staging moved it. This is what lets a sibling's row find its
                # opposite number: the prepared forms differ BY CONSTRUCTION on a staged
                # system, so a comparison keyed on them alone pairs nothing.
                asked_params=asked,
            ))
            return out

        return served


def _record_beside(ledger: Ledger, call: ServedCall) -> None:
    """Record `call` without letting the write displace the exception already in flight.

    Both callers are handlers recording WHY something failed and then re-raising it. A bare
    `ledger.record(...)` there is a second exception source in front of the `raise`: if the
    append fails — a read-only state root, a full disk, the ledger path replaced by a directory
    — that `OSError` propagates INSTEAD, and the original refusal never leaves this frame.

    Which is worse than losing a row, because the two exceptions are not interchangeable. A
    `StagingError` carries `USAGE_EXIT_CODE`, deliberately outside `circuit_breaker`'s
    `INFRA_EXIT_CODES`; the `OSError` that replaced it is unrecognised, so `query_tool` files it
    as `DEFAULT_FAULT_EXIT` — an infra code. Two of those trip the breaker for the system and
    five abort the run, in the SIBLING and not in its base, which is exactly the "the estate was
    up for one and down for the other" contamination the usage class was invented to prevent.

    So the write failure is reported to stderr and dropped. That leaves the state the ledger
    exists to make visible — a served response with no row — but it leaves it for a call that is
    ALREADY failing and already reaching the model as a fault, rather than manufacturing a
    second, differently-classed failure to announce it.
    """
    try:
        ledger.record(call)
    except Exception as write_failed:  # noqa: BLE001 — see docstring: never displace the raise
        print(f"[estate] could not record the {call.source} row for {call.system}.{call.verb} "
              f"({write_failed!r}); the call's own failure is what propagates", file=sys.stderr)


def _carrying(ctx: Any, **values: Any) -> Any:
    """`ctx` with `values` set on the fields it declares, or `ctx` untouched.

    ONE GUARD, TWO CALLERS, and the two conditions stay at the call sites where they belong.
    `served` sets `as_of` on EVERY call and `world_id` only where staging moved one; folding
    those conditions in here is what would let one silently acquire the other's scope — a
    declaration widens what a call may reach (`confine_index` admits a world's views by
    declaration, so setting it on an untouched call would admit that world's views for a read
    that was never retargeted), while a clock admits nothing and narrows nothing. Written as two
    functions, though, the GUARD was written twice, and a guard fixed in one copy and not the
    other is the invisible half of that.

    A ctx THAT CANNOT CARRY A FIELD IS HANDED BACK UNTOUCHED rather than repaired. That is a
    test stub, not a run: the real seam builds `VerbContext`. `replace` raises `TypeError` both
    on a non-dataclass and on a dataclass that simply has no such field, and a `TypeError` deep
    inside `served` is not an `AdapterFault` — the query tool files it as exit 2, an INFRA code
    the circuit breaker reads as the estate being down for this sibling and up for its base,
    which is the base-vs-sibling contamination this whole module exists to exclude.

    `fields(ctx)` rather than `type(ctx).__dataclass_fields__`, and the difference is not
    stylistic. `__dataclass_fields__` also holds the `ClassVar` and `InitVar` PSEUDO-fields
    that `fields()` filters out, so a stub declaring `as_of: ClassVar[datetime]` passed the
    membership test and reached `replace`, which raises `TypeError: __init__() got an
    unexpected keyword argument`. `f.init` rides with it for the third shape: `replace` raises
    `ValueError` on an `init=False` field. Either one is the exact `TypeError`-deep-inside-
    `served` this guard exists to prevent, and the `as_of` call site sits OUTSIDE the refusal
    handler — so it would escape with no ledger row at all. The tuple `fields()` builds per
    call is the price of the guard actually guarding.
    """
    if not is_dataclass(ctx) or isinstance(ctx, type):
        return ctx
    declared = {f.name for f in fields(ctx) if f.init}
    settable = {name: value for name, value in values.items() if name in declared}
    return replace(ctx, **settable) if settable else ctx


def _base_payload(  # noqa: PLR0913 — one call's whole identity: what runs it, where, as what
    fn: Any, ctx: Any, params: dict, system: str, verb: str, ledger: Ledger,
    asked: dict | None = None, restore: Any = None,
) -> tuple[Any, str]:
    """This key's base answer and its canonical text: the family's recording, else the adapter.

    THE HIT IS THE FAMILY'S; THE MISS IS THIS WORLD'S. A hit issues no adapter call at all, and
    for a key the source run captured that is a guarantee: the base file was primed before any
    sibling forked, so every sibling replays the same bytes. A MISS is a key the capture never
    held — one a sibling invented, which it will, because a sibling is continuing an
    investigation — and the `base` row written below goes into THIS world's own file, which no
    sibling reads. So two worlds asking one invented question each read the estate live and may
    differ; that residual is what `Ledger`'s own docstring sizes, and this frame is where it is
    incurred. (Before the tier split this row went into a shared table and a sibling could pick
    it up; "recorded once per family" was true of it then and is not now.)

    The TEXT comes back beside the tree because the caller needs it for the served row and it
    is already in hand on both arms — recomputed there, a memo hit paid a `loads` plus a `dumps`
    to rediscover the string it was handed.

    THE LIVE ARM ROUND-TRIPS TOO, so both arms hand back the same shape. `payload_text` writes
    with `default=str`, so a value JSON has no spelling for — a `datetime`, a `Decimal`, a
    tuple — survives as itself for the world that issued the live call and comes back
    stringified (or as a list) for every world that replays the recording. That is a difference
    between siblings created by nothing but call order, and it reaches the decision: an entity
    patch matches on string values, so the same query can report `passthrough` for the world
    that ran first and `patched` for the next. The family tier exists to make the pair's answers
    identical; normalising once here is what makes them so.
    """
    recorded = ledger.base_payload(system, verb, params)
    if recorded is not None:
        # lint-parse: ok — the payload half IS the adapter's own untyped answer, and the seam
        # that could narrow it is the adapter, not this one: a base row is whatever the verb
        # returned, and there is no shape seven systems share. `Any` is the honest declaration
        # rather than a promise the runtime never made; the narrow half (the text) is typed.
        return json.loads(recorded), recorded
    served = fn(ctx, **params)
    # RESTORED BEFORE THE TEXT IS TAKEN, so the recording and the replay are the same bytes and
    # neither carries the identity of the world that happened to run first. The live arm and
    # the memo arm then hand back payloads that differ by what the world staged and nothing
    # else — which is the whole of what a base-versus-sibling comparison is reading.
    text = payload_text(served if restore is None else restore(served))
    ledger.record(ServedCall(
        system=system, verb=verb, params=dict(params),
        payload_text=text, source=BASE, world_id=None,
        # THE FAMILY TIER PAIRS TOO, and on a staged system it is the only tier that can be
        # compared unmemoized: the base key is taken AFTER `prepare`, so two siblings record
        # two base rows under two staged spellings of one question. Without the asked form
        # `correlation_key` falls back to `params` and `keys(A) ∩ keys(B)` is empty — the same
        # silent-on-the-event-stream failure the world row carries `asked_params` to prevent,
        # left in the tier beside it. `None` on every unstaged call, so the column stays absent
        # wherever nothing was rewritten.
        asked_params=asked,
    ))
    # lint-parse: ok — same seam, same reason as the replay arm above: the payload is the
    # adapter's own untyped answer and there is no shape seven systems share.
    return json.loads(text), text
