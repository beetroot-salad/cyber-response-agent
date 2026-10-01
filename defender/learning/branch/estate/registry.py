"""The verb registry a branched run queries through.

Every query executes against the real adapter and the world's difference is applied on top of
what comes back; nothing here composes a query result. The event stream's corpus is staged
before the query runs and the engine does its own filtering; the six state systems get an entity
patch authored once and applied wherever that entity appears. A result composed per call would
be mid-run authoring.

Subclassing `ModuleVerbRegistry` is required: `driver.build_agent_core` refuses anything failing
`isinstance(verbs, VerbRegistry)`, and `VerbRegistry.decide` compares `verb_class_of(fn)` against
the grant, so the served callables must carry the real adapter bodies' decoration
(`functools.wraps`). Every served verb is a wrapped one, so coverage of all seven systems is
structural.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import fields, is_dataclass, replace
from defender._model import model
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from defender.runtime.verbs import DENIED, TABLE_POINTER, ModuleVerbRegistry, VerbDecision
from defender.runtime.verb_grant import VerbGrant
from defender.scripts.adapters.confinement import (
    VIEW_NAMESPACE,
    ConfinementFault,
    is_world_view,
)
from defender.scripts.adapters.faults import USAGE_EXIT_CODE

from ..comparator import Verdict, canonical, mechanical
from ..ledger import BASE, FAULT, REFUSED, STAGED, Ledger, LedgerError, ServedCall, payload_text
from defender.scripts.gather_tools.record_query import ParamsTooDeep, _json_safe_params
from . import applier as applier_module
from .applier import WorldApplier
from .stagers.dispatch import STAGERS

_logger = logging.getLogger(__name__)


class EstateError(Exception):
    """A world that cannot be served honestly."""


def validate_world_touches(derived: Any, grant: VerbGrant) -> tuple[str, ...]:
    """Validate the systems a world's difference touches against its serving grant.

    The set is derived from the overlay (`_family.touches_of`), not authored, but a derived name
    can still be one this role may not query, and an overlay keyed on a system outside the grant
    would apply no difference while every ledger row read honestly as `passthrough`.

    Shared by the manifest boundary (so the launcher refuses before priming an episode) and the
    registry boundary (so programmatic callers cannot bypass it).

    Typed `Any` because the input is unvalidated: the shapes refused below (a bare string, a
    non-sequence, a non-string name) are what an `Iterable[str]` annotation would hide.
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


@model(frozen=True)
class ServingWorld:
    """A world as the serving path needs it: a token, the systems it touches, its difference.

    Lets a caller serving one call (a replay, a probe) skip materialising an episode directory
    and a `Family`. `touches` is passed rather than re-derived because a world may touch less
    than its overlay implies — the control world has an empty overlay and an empty set.
    """

    world_id: str
    touches: tuple[str, ...]
    overlay: Any


def world_for(*, token: str, touches: Iterable[str], overlay: Any) -> ServingWorld:
    """Build a serving world from the three things a served call needs to know.

    `token` must be the episode-qualified token, never the short manifest label: `world_id`
    reaches the stager's view name, the ledger's row key and the confinement declaration
    unfiltered, and two episodes' world `b` would otherwise collide in all three.

    A document overlay is parsed by the manifest's own parser so the applier sees one shape.
    `{}` (the base world's overlay) is legal.
    """
    # Local import: the manifest module reads corpus patterns off this package's stager, so a
    # top-level import would be a cycle, and the estate must import without the manifest.
    from defender.runtime.branch._family import Overlay, parse_overlay

    parsed = overlay if isinstance(overlay, Overlay) else parse_overlay(overlay)
    return ServingWorld(world_id=token, touches=tuple(touches), overlay=parsed)


def _configured_for(world: Any, ctx: Any, stager: Any) -> tuple[str, ...]:
    """The episode tenant's configured corpus patterns, for the own-view test.

    The manifest's recorded set first; otherwise the serving context's tenant config. With
    neither, no view is this world's own (fail-closed)."""
    recorded = tuple(getattr(getattr(world, "family", None), "configured_patterns", ()) or ())
    if recorded:
        return recorded
    settings_dir = getattr(ctx, "settings_dir", None)
    return tuple(stager.configured_patterns(settings_dir)) if settings_dir is not None else ()


def refuse_a_foreign_world_view(
    world: Any, system: str, verb: str, params: Mapping, ctx: Any = None,
) -> None:
    """Refuse a call that names another world's staged view, before anything runs.

    Siblings in an episode share a cluster, each staging a private corpus under the view
    namespace; a world naming a sibling's view by hand would read that sibling's injected
    documents and exclusions.

    This must sit above per-world staging. A staging world has a foreign name rewritten by its
    stager into a view of nothing, so a check inside the stager looks fine while the hole stays
    open: the world that can actually make the read is the control, which stages nothing, whose
    applier hands the parameters straight back and threads no world label onto the context.

    It cannot live in the outbound HTTP guard either: that guard sees only the URL, and the
    query-language arm (`/_query`) carries the index in the request body.

    The source is read through the stager's own reader (which parameter addresses a corpus is
    vendor knowledge). The reader gets no `ctx`: an omitted index resolves to a configured
    pattern, which cannot be a foreign view. An unparseable body is left to `prepare`, which
    raises the stager's refusal for a staging world.
    """
    stager = STAGERS.get(system)
    reader = getattr(stager, "source_pattern", None) if stager is not None else None
    if stager is None or reader is None:
        return
    try:
        source = reader(verb, dict(params), None)
    except Exception:  # noqa: BLE001 — an unparseable body is `prepare`'s answer, except as below
        # `prepare` only covers a world that stages this system; for one that stages nothing,
        # params pass straight through and `esql` carries no index confinement. A multi-source
        # expression (`FROM logs-*, wv-<other>-logs-`) that the reader refuses to reduce would
        # reach the transport, so any unreducible call mentioning the namespace is refused.
        if _names_the_namespace(params):
            raise ConfinementFault(
                "the call names the staged view namespace inside an index expression this seam "
                "cannot reduce to a single corpus — refused before the call was issued, because "
                "a multi-source read is how a foreign view rides alongside a legal one") from None
        return
    if not isinstance(source, str) or not source.startswith(f"{VIEW_NAMESPACE}-"):
        return
    # The world's own view stays admissible, but only for a system it actually stages.
    if system in getattr(world, "touches", ()) and is_world_view(
            source, _configured_for(world, ctx, stager), world.world_id):
        return
    raise ConfinementFault(
        f"index expression {source!r} names a staged corpus this world does not read — "
        "refused before the call was issued")


def _names_the_namespace(params: Mapping) -> bool:
    """Does any parameter value mention the staged view namespace at all?

    A last line, not a parser: asked only when the vendor reader could not reduce the call to
    one corpus. No legitimate model-authored query names the namespace, so any mention is
    refused.
    """
    prefix = f"{VIEW_NAMESPACE}-"
    return any(prefix in value for value in params.values() if isinstance(value, str))


@model(frozen=True)
class Served:
    """One call's whole passage through the serve point.

    `serve_one`'s simple callers want `out`; the registry also needs `prepared`, `moved` and
    `decision` for its ledger rows, and must not re-derive them.
    """

    #: The params as the caller asked them, before any retarget.
    asked: dict
    #: The params the adapter was actually called with.
    prepared: dict
    #: `asked`, but only when staging moved the call — the condition the ledger records
    #: `asked_params` under and `restore` un-echoes on.
    moved: dict | None
    #: What came back, with the world's corpus identity taken back out.
    payload: Any
    #: The ledger's word for what this world did to the call.
    decision: str
    #: What the caller gets.
    out: Any


def serve_one(world: Any, system: str, verb: str, params: Mapping, *, adapters: Any = None,
              applier: Any = None, ctx: Any = None, run: Any = None) -> Served:
    """Serve one call for `world`: the single definition of the serve order.

    Refuse, let the applier point the call at the world's corpus, run it, restore the corpus
    identity out of the result, then ask the world what it did. `WorldRegistry._served` calls
    this rather than re-spelling it, so the ordering tests exercise the production frame.

    The refusal runs before `prepare` (so no stager can rewrite a foreign name into a harmless
    one) and before the adapter (so a refused read leaves no call on the wire and no row).

    `run` is the one seam: the registry puts its family tier in front of the adapter (a
    recorded key issues no call) with the restore inside the miss. It takes `(prepared, moved)`
    and returns the restored payload.
    """
    refuse_a_foreign_world_view(world, system, verb, params, ctx)
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
    # `moved`, not `asked`: the row must say whether staging moved this call.
    decision, out = applier.apply(system, verb, prepared, payload, world, moved)
    return Served(asked=asked, prepared=prepared, moved=moved, payload=payload,
                  decision=decision, out=out)


class WorldRegistry(ModuleVerbRegistry):
    """A `ModuleVerbRegistry` whose verbs run for real and then answer to the world."""

    def __init__(self, roster, grant, *, world: Any, ledger: Ledger, as_of: datetime,  # noqa: PLR0913 — a world's whole serving identity plus its tenant
                 applier: Any = None, settings_dir: Path | None = None,
                 grant_home: str = TABLE_POINTER):
        # `settings_dir` is the episode tenant's folder, read for the ticket-comment check's
        # released status; `None` releases nothing, so a comment patch is refused.
        super().__init__(roster, grant, grant_home=grant_home)
        # Validate the clock here, once. A `TypeError` deep inside `served` is not an
        # `AdapterFault`, so the query tool files it as an infra exit code, which trips the
        # circuit breaker in the sibling but not its base — contaminating the comparison.
        #
        # `utcoffset() == timedelta(0)`, not `tzinfo is not None`: an aware non-UTC datetime
        # would format a trailing `Z` that is wrong by its offset.
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
            # `None` is the family tier's key. A world answering to it would write its applied
            # payload into the shared base slot, and every sibling would replay that difference
            # as the estate while its own rows honestly said `passthrough`.
            raise EstateError(
                f"a world needs a non-empty string id, got {world_id!r} — `None` is how the "
                "family tier spells 'the shared base', and a world claiming it would overwrite "
                "the recording its siblings replay")
        # Unknown names would route every response to `passthrough`; this is the
        # non-bypassable boundary for programmatic worlds (the CLI also checks before priming).
        declared = validate_world_touches(getattr(world, "touches", ()), grant)
        # The id must also be nameable: a staged system derives its per-world view name from
        # it, and an id the stager cannot carry fails every query on that system.
        unnameable = applier_module.unnameable(world)
        if unnameable:
            raise EstateError(
                f"world {world_id!r} declares a staged system whose view it cannot be named "
                f"in ({unnameable}) — the id reaches the corpus name unfiltered, so every "
                "staged call would be refused and the sibling would measure nothing")
        self.world = world
        self.ledger = ledger
        self.applier = (  # lint-default: ok — DI seam owning its default (with no patches and a world touching nothing it is the identity a base world wants)  # noqa: E501
            applier if applier is not None else WorldApplier())
        # A patch the applier can never apply (a system the world does not declare, or a
        # staged system, whose difference lives in its corpus) would be dropped silently, so
        # refuse it here. Check the effective table — the world's own overlay where it has one —
        # not the constructor field. `Mapping`, not `dict`: an applier may hand back a
        # read-only mapping.
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
            unservable = applier_module.unservable(patches, settings_dir)
            if unservable:
                raise EstateError(
                    f"world {world_id!r} carries a difference the read screen would empty "
                    f"before the sibling saw it: {'; '.join(unservable)}")
        self._wrapped: dict[str, dict[str, Any]] = {}

    def decide_call(self, system: str, verb: str, params: Mapping[str, Any]) -> VerbDecision:
        """The grant decision for a call, recorded as a `refused` row when it denies the call.

        A denied verb never reaches the serve seam, so without this it leaves no row and the
        sibling reads as never having asked (the mechanical grader's "no row on H"). It is filed
        like any other refusal, against the params as asked.

        An adapter that cannot load raises out of `decide` and is filed `fault`, matching what
        the base world records for the same failure, then re-raised untouched. Rows go through
        `_record_beside` so a failed write never replaces the decision or exception.

        A call no row could carry is refused first (`_refuse_unstorable`), so neither row is
        ever attempted for it.
        """
        _refuse_unstorable(system, verb, params)
        try:
            decision = super().decide_call(system, verb, params)
        except Exception as failure:
            _record_beside(self.ledger, ServedCall(
                system=system, verb=verb, params=dict(params),
                payload_text=f"{type(failure).__name__}: {failure}", source=FAULT,
                world_id=self.world.world_id,
            ))
            raise
        if decision.outcome == DENIED:
            _record_beside(self.ledger, ServedCall(
                system=system, verb=verb, params=dict(params),
                payload_text=decision.refusal or f"denied: {system}.{verb}", source=REFUSED,
                world_id=self.world.world_id,
            ))
        return decision

    def verbs(self, system: str):
        """Every verb this system declares, wrapped so no body reaches the caller unwrapped.

        Both `decide()` and the query tool's own lookup resolve through here, so every route to
        a callable is wrapped.

        Wrapped once per system: `list_verbs` would otherwise build N(N+1) closures. The memo is
        safe because `served` reads its collaborators off `self` at call time. `super().verbs`
        still raises `KeyError` for an unknown system, which `_list_verbs_declared` depends on.
        Returns a copy so one caller's edit cannot reach later lookups.
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
            _refuse_unstorable(system, verb, params)
            # The clock is set on every call, unlike `world_id`, which is set only where staging
            # moved the call: a `world_id` declaration widens what `confine_index` admits, while
            # a clock admits nothing. Host-state (never staged) is the adapter that stamps the
            # clock, so a clock scoped to staged calls would miss it.
            #
            # Set before `prepare` so the stager, `restore` and the adapter see one moment. This
            # line is outside the refusal handler; it cannot raise (`_carrying` is total and
            # `as_of` was validated at construction).
            ctx = _carrying(ctx, as_of=self.as_of)
            # How far the call got, so the failure handlers below know which row to write.
            # Empty until `run` is entered.
            reached: dict[str, Any] = {}

            def run(prepared: dict, moved: dict | None) -> Any:
                """The family tier in front of the adapter, and the restore inside its miss."""
                reached.update(prepared=prepared, moved=moved)
                payload, reached["base_text"] = _base_payload(
                    fn, _carrying(ctx, world_id=world.world_id) if moved is not None else ctx,
                    prepared, system, verb, ledger, moved,
                    # Restore before the base row is written: that row is replayed by every
                    # sibling, so it must carry no world's view name.
                    lambda served_payload: applier.restore(
                        system, verb, served_payload, moved, prepared, ctx),
                )
                return payload

            try:
                # `serve_one` owns the order; this frame adds the family tier and ledger rows.
                # It also hands `prepare` a copy, so an applier that retargets in place still
                # yields a `moved` (which drives the `world_id` declaration, `restore`'s
                # un-echo and the `asked_params` column).
                passage = serve_one(world, system, verb, params,
                                    applier=applier, ctx=ctx, run=run)
            except LedgerError:
                # The table's own refusal; recording another row for it would be another write.
                raise
            except Exception as failure:
                if "prepared" not in reached:
                    # Before the call was made: the isolation refusal or the retarget failed.
                    # Record it against the params as asked (an unrecorded refusal reads as
                    # never asking), then re-raise.
                    #
                    # The exit code picks the class: `prepare` reads config, so an environment
                    # fault surfaces here too, and the base world records the same outage as
                    # `fault`. Only a usage-class failure is `refused`.
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
                # An estate fault is a response: the query tool hands the model a fault row, so
                # this must write one too. Recorded against the params as run, with
                # `asked_params` so a staged fault can still be paired.
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
            # When nothing changed the payload, the base text is already the served text;
            # re-dumping a large result was the seam's most expensive per-call step.
            served_text = base_text if out is payload else payload_text(out)
            # One extra live read on a staged decision, at the plain ctx (a `world_id`-carrying
            # ctx would admit this world's staged views). The result goes on the staged row
            # itself: a separate witness row would be the first row under this correlation key
            # and shadow the served one under `episode._answers`' first-row-wins.
            differs_from_base: bool | None = None
            base_pattern_digest: str | None = None
            if decision == STAGED and asked is not None:
                differs_from_base, base_pattern_digest = _base_witness(fn, ctx, asked, served_text)
            # `Ledger.record` validates the decision and raises before `out` is returned.
            ledger.record(ServedCall(
                system=system, verb=verb, params=dict(prepared),
                payload_text=served_text,
                source=decision, world_id=world.world_id,
                # Only when staging moved it: prepared forms differ by construction on a staged
                # system, so pairing needs the asked form.
                asked_params=asked,
                differs_from_base=differs_from_base,
                base_pattern_digest=base_pattern_digest,
            ))
            return out

        return served


def _base_witness(
    fn: Any, ctx: Any, moved: dict, staged_text: str,
) -> tuple[bool | None, str | None]:
    """One live read of the un-rewritten base pattern, and how it compares to the staged text.

    `moved` is the world's question as asked, before the retarget; `ctx` must be the plain ctx
    (no `world_id`), so the read reaches the base pattern.

    Returns `(None, None)` when unmeasurable: `differs_from_base` means a comparison was made,
    and recording `False` would charge the world for an estate outage. The digest is `sha256` of
    the base text through `comparator.canonical`, the same canonicalisation the verdict uses.
    """
    # Everything, not just the read, is inside the try: `payload_text`, `canonical` and
    # `mechanical` can all raise, and an escape would fault the sibling's own served query.
    try:
        served = fn(ctx, **moved)
        base_text = payload_text(served)
        digest = hashlib.sha256(canonical(base_text).encode("utf-8")).hexdigest()
        verdict = mechanical(staged_text, base_text)
    except Exception:  # noqa: BLE001 — an unanswerable witness is unmeasured, not "no difference"
        return None, None
    return verdict not in (Verdict.SAME, Verdict.FORMATTING), digest


def _refuse_unstorable(system: str, verb: str, params: Mapping[str, Any]) -> None:
    """Refuse, as the table's own `LedgerError`, a call whose params no ledger row could carry.

    Both doors into the registry (`decide_call`, `served`) ask this before anything is decided,
    served or filed: past them every row is built from params already known to fit, so no
    refused or FAULT row is ever attempted and then dropped. `served` re-raises `LedgerError`
    untouched, where any other exception would be filed as a FAULT row."""
    try:
        _json_safe_params(params)
    except ParamsTooDeep as too_deep:
        raise LedgerError(f"{system}.{verb} was not served: {too_deep}") from too_deep


def _record_beside(ledger: Ledger, call: ServedCall) -> None:
    """Record `call` without letting the write displace the exception already in flight.

    Callers record why something failed and then re-raise. If the append itself fails (read-only
    root, full disk), that `OSError` would propagate instead; unlike a `StagingError`
    (`USAGE_EXIT_CODE`), it is filed as an infra code, tripping the circuit breaker in the
    sibling and not its base. So the write failure is logged and dropped: the call is already
    failing and reaching the model as a fault.
    """
    try:
        ledger.record(call)
    except Exception as write_failed:  # noqa: BLE001 — never displace the in-flight raise
        _logger.warning(f"could not record the {call.source} row for {call.system}.{call.verb} "
                        f"({write_failed!r}); the call's own failure is what propagates")


def _carrying(ctx: Any, **values: Any) -> Any:
    """`ctx` with `values` set on the fields it declares, or `ctx` untouched.

    The conditions for setting each field stay at the call sites; this holds only the guard.

    A ctx that cannot carry a field (a test stub; the real seam builds `VerbContext`) is
    returned untouched, because `replace` raising `TypeError` inside `served` would be filed as
    an infra fault. `fields()` rather than `__dataclass_fields__`, which also holds `ClassVar`
    and `InitVar` pseudo-fields; `f.init` excludes `init=False` fields, on which `replace`
    raises `ValueError`.
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

    A hit issues no adapter call; the base file was primed before any sibling forked, so every
    sibling replays the same bytes for a captured key. A miss (a key a sibling invented) goes
    live and its `base` row lands in this world's own file, which no sibling reads — so two
    worlds asking the same invented question may see different answers.

    Returns the text too because the caller needs it for the served row.

    The live arm also round-trips through JSON so both arms return the same shape:
    `payload_text` writes with `default=str`, and without this a `datetime` or tuple would
    differ between the world that ran live and those replaying, changing whether a string-
    matching entity patch applies.
    """
    recorded = ledger.base_payload(system, verb, params)
    if recorded is not None:
        # lint-parse: ok — the payload is the adapter's own untyped answer; there is no shape
        # the seven systems share, and the text half is typed.
        return json.loads(recorded), recorded
    served = fn(ctx, **params)
    # Restore before taking the text, so the recording carries no world's identity.
    text = payload_text(served if restore is None else restore(served))
    ledger.record(ServedCall(
        system=system, verb=verb, params=dict(params),
        payload_text=text, source=BASE, world_id=None,
        # The base key is taken after `prepare`, so on a staged system two siblings record
        # base rows under different staged spellings; the asked form lets `correlation_key`
        # pair them. `None` on unstaged calls.
        asked_params=asked,
    ))
    # lint-parse: ok — same reason as the replay arm: the adapter's untyped answer.
    return json.loads(text), text
