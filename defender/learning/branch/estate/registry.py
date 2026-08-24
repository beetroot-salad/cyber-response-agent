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
from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
from typing import Any

from defender.runtime.verbs import ModuleVerbRegistry
from defender.scripts.adapters.faults import USAGE_EXIT_CODE

from ..ledger import BASE, FAULT, REFUSED, Ledger, LedgerError, ServedCall
from . import applier as applier_module
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
        declared = getattr(world, "touches", ())
        if not isinstance(declared, (str, list, tuple, set, frozenset)):
            # READ ONCE, HERE, LOUDLY. `_touches` coerces a bare string and answers `False` for
            # everything else it cannot read — and a world whose `touches` reads as empty routes
            # every response to `passthrough`, so the run measures nothing while every ledger
            # row stays honest. That is the silent failure this seam is built around, and the
            # only place to catch it is where the world arrives: `_touches` runs per call, deep
            # inside `served`, where a `TypeError` is not an `AdapterFault` and the query tool
            # files it as exit 2 — an INFRA code the circuit breaker counts as the estate being
            # down for this sibling and up for its base.
            raise EstateError(
                f"a world's `touches` must be a sequence of system names (or one name), got "
                f"{declared!r} — an unreadable `touches` routes every response to `passthrough` "
                "and the run then measures nothing with every row still reading honestly")
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
        patches = getattr(self.applier, "patches", None)
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
            try:
                prepared = applier.prepare(system, verb, params, world, ctx)
            except Exception as refusal:
                # A refusal is EVIDENCE, and an unrecorded one is indistinguishable from the
                # sibling never asking. Recorded against the params as ASKED — the retarget is
                # exactly what failed, so there is no prepared form to name — then re-raised
                # so the query tool still turns it into the fault row the model reads.
                #
                # WHICH class, though, is the exit code's answer and not this frame's. `prepare`
                # reads the run's config to resolve a default index, so an ENVIRONMENT fault
                # (a missing config file, a missing key) surfaces here too — and filing that as
                # `refused` splits one outage along the base/sibling axis: the base world
                # returns from `redirect` before ever reading the config, takes the identical
                # fault out of the adapter body below, and records `fault`. One outage, two
                # decision classes, divided by exactly the thing the table exists to measure.
                # `refused` is the capability answer, which is the one the stager marks usage.
                _record_beside(ledger, ServedCall(
                    system=system, verb=verb, params=dict(params),
                    payload_text=str(refusal),
                    source=(
                        REFUSED if getattr(refusal, "exit_code", None) == USAGE_EXIT_CODE
                        else FAULT
                    ),
                    world_id=world.world_id,
                ))
                raise
            asked = dict(params) if prepared != params else None
            try:
                payload, base_text = _base_payload(
                    fn, _declaring(ctx, world.world_id) if asked is not None else ctx,
                    prepared, system, verb, ledger, asked,
                    # BEFORE the base row is written, so the FAMILY's shared recording carries
                    # no world's identity. That row is replayed by every sibling, and it is
                    # made by whichever world called first — so a staged recording would hand
                    # every other sibling the first one's view name as if it were the estate's.
                    lambda served: applier.restore(
                        system, verb, served, asked, prepared, ctx),
                )
                decision, out = applier.apply(system, verb, prepared, payload, world)
            except LedgerError:
                # The table's own refusal, already accounted for. Recording a second row for it
                # would answer "the ledger would not write this" with another write.
                raise
            except Exception as fault:
                # AN ESTATE FAULT IS A RESPONSE. `QueryCapture` catches whatever the body raises
                # and hands the model a fault row, so the defender HAS seen an answer here — and
                # a seam that wrote nothing would leave exactly the state this table exists to
                # make visible, "a served response with no row". Recorded against the params as
                # RUN, because the retarget succeeded and it is the prepared call that faulted;
                # `asked_params` rides along for the same reason it does below, so a staged
                # fault can still find its opposite number. Re-raised untouched.
                _record_beside(ledger, ServedCall(
                    system=system, verb=verb, params=dict(prepared),
                    payload_text=str(fault) or type(fault).__name__, source=FAULT,
                    world_id=world.world_id,
                    asked_params=asked,
                ))
                raise
            # `out is payload` on every decision that changes nothing (STAGED, PASSTHROUGH), and
            # the base text is then the served text — the same bytes `_payload_text` would
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
                payload_text=base_text if out is payload else _payload_text(out),
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


def _declaring(ctx: Any, world_id: str) -> Any:
    """`ctx`, carrying the world whose views this call may read.

    THE RETARGET AND THE DECLARATION ARE ONE ACT, so they are done in one place. A staged call
    addresses a view named OUTSIDE every configured pattern — deliberately, because a view the
    base pattern still reaches is a view the base run and every unstaged sibling read too — and
    `confine_index` therefore cannot admit it by reach. It admits it by declaration instead, and
    the only frame that knows which world is being served is this one.

    PER WORLD, never a blanket exemption: the ctx names A, so A's views resolve and B's are
    still refused. And only where staging MOVED the call — an untouched call addresses the
    corpus itself and has nothing to declare, so the ordinary path is unchanged.

    A ctx that cannot CARRY the declaration is handed back untouched rather than repaired. That
    is a test stub, not a run: the real seam builds `VerbContext`, and the failure mode if one
    ever were not is a `ConfinementFault` naming the index — a refusal, which is the direction
    this whole module errs in. The field is checked as well as the dataclass-ness, because
    `replace` raises `TypeError` on a dataclass that simply has no `world_id` — and a `TypeError`
    here is not an `AdapterFault`, so the query tool files it as exit 2, an INFRA code the
    circuit breaker reads as the estate being down for this sibling and up for its base.
    """
    if not is_dataclass(ctx) or isinstance(ctx, type):
        return ctx
    if not any(f.name == "world_id" for f in fields(ctx)):
        return ctx
    return replace(ctx, world_id=world_id)


def _base_payload(  # noqa: PLR0913 — one call's whole identity: what runs it, where, as what
    fn: Any, ctx: Any, params: dict, system: str, verb: str, ledger: Ledger,
    asked: dict | None = None, restore: Any = None,
) -> tuple[Any, str]:
    """This key's base answer and its canonical text: the family's recording, else the adapter.

    Recorded ONCE PER FAMILY rather than once per world. The estate is live, so two siblings
    calling it minutes apart would get different data and the pair's invariance — the whole
    reason a sibling is worth running — would be a fiction. A hit here issues no adapter call
    at all.

    The TEXT comes back beside the tree because the caller needs it for the served row and it
    is already in hand on both arms — recomputed there, a memo hit paid a `loads` plus a `dumps`
    to rediscover the string it was handed.

    THE LIVE ARM ROUND-TRIPS TOO, so both arms hand back the same shape. `_payload_text` writes
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
    text = _payload_text(served if restore is None else restore(served))
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
