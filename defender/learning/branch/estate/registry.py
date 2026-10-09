"""The verb registry a branched run queries through (#1224: served by the world's live oracle).

Every investigator call reads its real base answer (the family's recording, else live) and,
in a world with facts, is served by one oracle turn whose submission passed the host checks and
a verifier (`estate.oracle`). Nothing reaches the investigator unverified, and every response
lands in the world ledger with the decision that produced it.

Subclassing `ModuleVerbRegistry` is required: `driver.build_agent_core` refuses anything failing
`isinstance(verbs, VerbRegistry)`, and `VerbRegistry.decide` compares `verb_class_of(fn)` against
the grant, so the served callables must carry the real adapter bodies' decoration
(`functools.wraps`). Every served verb is a wrapped one, so coverage of every system is
structural.
"""

from __future__ import annotations

import contextlib
import functools
import json
import logging
import threading
from collections.abc import Callable, Iterator, Mapping
from dataclasses import fields, is_dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from defender import _yaml
from defender._episode_paths import LAYOUT
from defender.runtime.branch import source_alert
from defender._io import read_jsonl_rows, read_text_utf8
from defender._query_rules import ParamsTooDeep, _json_safe_params
from defender.learning.core.config import oracle_settings_with
from defender.hooks.budget_enforcer import oracle_turn_closed, oracle_turn_opened
from defender.runtime.verbs import (
    CALL_DELIVERY,
    DENIED,
    TABLE_POINTER,
    ModuleVerbRegistry,
    VerbDecision,
)

from ..outcome import BUDGET, ORACLE_UNSERVABLE
from ..ledger import (
    FAULT,
    ORACLE,
    PASSTHROUGH,
    REAL_ERROR,
    REFUSED,
    Ledger,
    LedgerError,
    ServedCall,
    payload_text,
)
from .checks import RealData, canonical_json
from .limiter import RateLimiter
from .oracle import (
    DEFAULT_RESTART_AFTER,
    Oracle,
    OracleStore,
    OracleUnservable,
    QueryDoor,
    base_digest,
    request_key,
    start_process_box,
)

_logger = logging.getLogger(__name__)


class EstateError(Exception):
    """A world that cannot be served honestly."""


def serve_one(registry: WorldRegistry, system: str, verb: str, fn: Any, ctx: Any,
              params: Mapping[str, Any]) -> Any:
    """Serve one investigator call for `registry`'s world: the single definition of the serve
    order (#1224).

    The world's stored answer first (a repeated call is served byte for byte, no turn). Then
    the call's base answer: the family's recording, else this world's own live base store,
    else one live read (kept in that store, never in the world ledger, M16). A real error on
    that read passes through as itself (`real-error`, not cached, O4). A world with no facts is
    served its base (`passthrough`). Otherwise one oracle turn at a time (S11): the stored
    answer is looked up again under the turn, then the oracle serves, the host checks and the
    verifier pass it, and its rows, facts and answer are committed before the ledger row."""
    asked = dict(params)
    key = request_key(system, verb, asked)
    hit = registry.store.answers.get(key)
    if hit is not None:
        return registry._from_store(system, verb, asked, hit)
    base_text = registry._base(system, verb, fn, ctx, asked)
    if not registry.world_facts:
        return registry._deliver(ServedCall(
            system=system, verb=verb, params=asked, payload_text=base_text, source=PASSTHROUGH,
            world_id=registry.world.world_id))
    with registry._turn(ctx, pauses_clock=True):
        hit = registry.store.answers.get(key)
        if hit is not None:
            return registry._from_store(system, verb, asked, hit)
        base = json.loads(base_text)
        digest = base_digest(base_text)
        committed: dict[str, Any] = {}

        def commit(served: Any, claim: dict, verdict: dict, attempts: int, staged: Any) -> None:
            served_text = payload_text(served)
            decision = PASSTHROUGH if canonical_json(served) == canonical_json(base) else ORACLE
            answer = {"system": system, "verb": verb, "params": asked,
                      "served": json.loads(served_text), "decision": decision,
                      "base_digest": digest, "claim": claim, "verifier_verdict": verdict,
                      "attempts": attempts}
            registry.store.commit(forged=list(staged.forged.values()),
                                  facts=[{"entity": e, "field": f, "value": v}
                                         for (e, f), v in staged.facts.items()],
                                  answer=answer)
            committed["answer"] = answer

        registry.oracle.serve((system, verb, asked), base,
                              lambda: registry._real(system, base), commit)
        return registry._record_answer(system, verb, asked, committed["answer"])


class PrebranchChanged(Exception):
    """Pre-flight: a world's verified answer changes a call the source run made before the
    branch point (M01=A: that prefix is fixed, so the world cannot be served)."""


def calibrate_one(registry: WorldRegistry, ctx: Any, system: str, verb: str,
                  params: Mapping[str, Any], base: Any, *, fixed: bool) -> None:
    """Pre-flight's replay of one original call through `registry`'s world (#1224, Amendment 2
    change 1): one oracle turn and verifier pass against the call's base answer, under the same
    turn lock, checks and budget as a sibling's call. It only CALIBRATES: a verified attempt
    freezes its forged rows and recorded facts in the world's store, and no served answer is
    cached and no world-ledger row written (S1). The replay itself is one `preflight` row of
    the world's oracle-side ledger (N14).

    `fixed` marks a call the source run made before the branch point: a verified answer that
    differs from its base raises `PrebranchChanged` before anything is frozen. An unservable
    call raises `OracleUnservable` as it would in a sibling. `ctx` is pre-flight's own verb
    context; every oracle-side query of the turn runs in it, at the branch-point clock."""
    asked = dict(params)
    registry.store.log_query("preflight", system, verb, asked)

    def commit(served: Any, _claim: dict, _verdict: dict, _attempts: int, staged: Any) -> None:
        if fixed and canonical_json(served) != canonical_json(base):
            raise PrebranchChanged(
                f"the world's verified answer changes {system}.{verb}, a call the source run "
                "made before the branch point — that prefix is fixed (M01=A)")
        registry.store.commit(forged=list(staged.forged.values()),
                              facts=[{"entity": e, "field": f, "value": v}
                                     for (e, f), v in staged.facts.items()],
                              answer=None)

    with registry._turn(_carrying(ctx, as_of=registry.as_of), pauses_clock=False):
        registry.oracle.serve((system, verb, asked), base,
                              lambda: registry._real(system, base), commit)


class WorldRegistry(ModuleVerbRegistry):
    """A `ModuleVerbRegistry` whose verbs answer as the world's live oracle serves them."""

    def __init__(self, roster, grant, *, world: Any, ledger: Ledger, as_of: datetime,  # noqa: PLR0913 — a world's whole serving identity, its tenant and the oracle's coined knobs
                 tenant: Any = None, grant_home: str = TABLE_POINTER, oracle: Any = None,
                 verifier: Any = None, oracle_dir: Path | None = None,
                 retry_cap: int | None = None, turn_deadline: float | None = None,
                 budget: float | None = None, rate: float | None = None,
                 box: Callable[[], Any] | None = None, restart_after: int = DEFAULT_RESTART_AFTER,
                 limiter: RateLimiter | None = None):
        super().__init__(roster, grant, grant_home=grant_home)
        # Validate the clock here, once: every query this world issues, the oracle's own
        # included, carries it, so no oracle-side context is ever built without it (O-31).
        #
        # `utcoffset() == timedelta(0)`, not `tzinfo is not None`: an aware non-UTC datetime
        # would format a trailing `Z` that is wrong by its offset.
        if not isinstance(as_of, datetime):
            raise EstateError(
                f"a world needs the moment it is being served as of, got {as_of!r} — without it "
                "every read a sibling or its oracle makes is the afternoon it executed rather "
                "than the branch point it resumed into, and the episode cannot be replayed")
        if as_of.tzinfo is None or as_of.utcoffset() != timedelta(0):
            raise EstateError(
                f"as_of must be an aware UTC datetime, got {as_of!r} (offset "
                f"{as_of.utcoffset()!r}) — a naive or offset moment formats a `Z` that lies by "
                "that offset")
        self.as_of = as_of
        world_id = getattr(world, "world_id", None)
        if not isinstance(world_id, str) or not world_id:
            raise EstateError(
                f"a world needs a non-empty string id, got {world_id!r} — `None` is how the "
                "family tier spells 'the shared base', and a world claiming it would overwrite "
                "the recording its siblings replay")
        self.world = world
        self.ledger = ledger
        self.tenant = tenant
        self.world_facts = tuple(getattr(world, "facts", ()) or ())
        settings = oracle_settings_with(retry_cap=retry_cap, turn_deadline=turn_deadline,
                                        budget=budget, rate=rate)
        if oracle_dir is None:
            oracle_dir = _default_oracle_dir(world, ledger)
        self.store = OracleStore(Path(oracle_dir))
        self._turn_lock = threading.Lock()
        #: The context of the call whose turn holds the lock: every oracle-side query of that
        #: turn runs in it. Set and cleared only under the lock.
        self._turn_ctx: Any = None
        #: The family's base recording as `(system, verb, answer)`, parsed once: every host
        #: check reads it, and it does not change while the world is served.
        self._family_answers = [(r["system"], str(r.get("verb")), _parsed(r["payload_text"]))
                                for r in read_jsonl_rows(ledger.base_path)
                                if isinstance(r.get("system"), str)
                                and isinstance(r.get("payload_text"), str)]
        #: This world's real data, indexed once and grown as answers arrive (`_real`).
        self._real_data = RealData(
            answers=[(s, answer) for s, _verb, answer in self._family_answers])
        self._kept_seen = 0
        self._explored_seen = 0
        #: A host check abandoned by a passed deadline may still be reading on its own thread
        #: while the next attempt checks: the index grows under one lock.
        self._real_lock = threading.Lock()
        door = QueryDoor(
            decide=lambda system, verb: ModuleVerbRegistry.decide(self, system, verb),
            real_verbs=lambda system: ModuleVerbRegistry.verbs(self, system),
            # One limiter per process (S16): pre-flight hands every world the launcher's own,
            # held at the episode rate; a sibling builds its slice's here.
            limiter=limiter if limiter is not None else RateLimiter(settings.rate),
            store=self.store, context=self._oracle_context)
        self.oracle = Oracle(
            world=world, store=self.store, door=door,
            oracle_model=oracle if oracle is not None else _LazyModel(
                settings.model, settings.effort),
            verifier_model=verifier if verifier is not None else _LazyModel(
                settings.check_model, settings.check_effort),
            box_factory=box if box is not None else start_process_box,
            retry_cap=settings.retry_cap, turn_deadline=settings.turn_deadline,
            budget=settings.budget, restart_after=restart_after,
            family_examples=self._examples(), real_extra=self._alert())
        # A world whose sibling already went unservable stays so on resume: its failing call
        # is never retried (N13). Its record is the sibling's own (`run.py`), read here.
        recorded = _world_record(world)
        if recorded is not None:
            self.oracle.unservable = recorded
        self._wrapped: dict[str, dict[str, Any]] = {}

    # -- the grant door -------------------------------------------------------------------------

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
        a callable is wrapped. Wrapped once per system; `super().verbs` still raises `KeyError`
        for an unknown system. Returns a copy so one caller's edit cannot reach later lookups.
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
            _refuse_unstorable(system, verb, params)
            # The clock is set on every call: every read this world makes, the oracle's own
            # included, is bounded by the branch point (O6).
            ctx = _carrying(ctx, as_of=self.as_of)
            return serve_one(self, system, verb, fn, ctx, params)

        return served

    # -- the serve order's parts ------------------------------------------------------------

    def _base(self, system: str, verb: str, fn: Any, ctx: Any, params: dict) -> str:
        """The call's base answer text: the family's recording, else this world's own base
        store, else one live read kept in that store (never a world-ledger row, M16). A real
        error on the read is recorded `real-error` and passes through untouched."""
        recorded = self.ledger.base_payload(system, verb, params)
        if recorded is not None:
            return recorded
        kept = self.store.base.get(request_key(system, verb, params))
        if kept is not None:
            return kept
        try:
            answer = fn(ctx, **params)
        except Exception as failure:
            _record_beside(self.ledger, ServedCall(
                system=system, verb=verb, params=dict(params),
                payload_text=str(failure) or type(failure).__name__, source=REAL_ERROR,
                world_id=self.world.world_id))
            raise
        text = payload_text(answer)
        self.store.keep_base(system, verb, params, text)
        return text

    def _from_store(self, system: str, verb: str, params: dict, answer: dict) -> Any:
        return self._record_answer(system, verb, params, answer)

    def _record_answer(self, system: str, verb: str, params: dict, answer: dict) -> Any:
        """The stored answer, delivered to this call (`_deliver`)."""
        return self._deliver(ServedCall(
            system=system, verb=verb, params=params,
            payload_text=payload_text(answer.get("served")),
            source=answer.get("decision") or ORACLE, world_id=self.world.world_id,
            base_digest=answer.get("base_digest"), claim=answer.get("claim"),
            verifier_verdict=answer.get("verifier_verdict"), attempts=answer.get("attempts")))

    def _deliver(self, call: ServedCall) -> Any:
        """`call`'s payload, handed to the caller and recorded as served — unless its caller
        stopped waiting (the lead was ended mid-call): an undelivered call leaves no row (N12).
        The one writer of a delivered call's row, whatever served it."""
        delivery = CALL_DELIVERY.get()
        if delivery is None or not delivery.abandoned:
            self.ledger.record(call)
        return json.loads(call.payload_text)

    @contextlib.contextmanager
    def _turn(self, ctx: Any, *, pauses_clock: bool) -> Iterator[None]:
        """One oracle turn at a time in this world (S11), its oracle-side queries run in `ctx`,
        and — for an investigator's call (`pauses_clock`) — the investigator's clock paused for
        as long as the turn is held (S12-S15). Pre-flight's replay has no investigator clock."""
        run_dir = getattr(ctx, "run_dir", None) if pauses_clock else None
        with self._turn_lock:
            self._turn_ctx = ctx
            if run_dir is not None:
                oracle_turn_opened(Path(run_dir))
            try:
                yield
            finally:
                self._turn_ctx = None
                if run_dir is not None:
                    oracle_turn_closed(Path(run_dir))

    def _oracle_context(self) -> Any:
        """The context an oracle-side query runs in: that of the call whose turn is held,
        carrying the branch-point clock."""
        return _carrying(self._turn_ctx, as_of=self.as_of)

    def _real(self, system: str, base: Any) -> RealData:
        """This world's real data as the host checks read it: the family recording, every base
        answer kept and every answer the oracle or verifier read so far, this call's base and
        the source alert — one index, added to rather than rebuilt."""
        data = self._real_data
        with self._real_lock:
            kept = self.store.base_answers[self._kept_seen:]
            explored = self.oracle.explored[self._explored_seen:]
            self._kept_seen += len(kept)
            self._explored_seen += len(explored)
            for kept_system, text in kept:
                data.add(kept_system, _parsed(text))
            for explored_system, answer in explored:
                data.add(explored_system, answer)
            data.add(system, base)
            if not data.loose:
                data.add_loose(self.oracle.real_extra)
        return data

    def _examples(self) -> list[tuple[str, str, Any]]:
        """Example answers per system from the family's base recording, for the oracle's
        family block: answers only, never the params that asked them (another call's params
        must not enter this call's turn)."""
        out: list[tuple[str, str, Any]] = []
        per_system: dict[str, int] = {}
        for system, verb, answer in self._family_answers:
            if per_system.get(system, 0) >= _EXAMPLES_PER_SYSTEM:
                continue
            per_system[system] = per_system.get(system, 0) + 1
            out.append((system, verb, answer))
        return out

    def _alert(self) -> list[Any]:
        family = getattr(self.world, "family", None)
        source = getattr(family, "source_run_dir", None)
        if not source:
            return []
        alert = source_alert(Path(source))
        return [alert] if alert is not None else []

    def close(self) -> None:
        """Tear down the oracle's boxes (the sibling is ending)."""
        self.oracle.close()


class _LazyModel:
    """A role's production model, built from its knobs on first use, so a world that never
    takes a turn needs no provider key."""

    def __init__(self, name: str, effort: str) -> None:
        self.name, self.effort = name, effort
        self._built: Any = None

    @property
    def model(self) -> Any:
        return self._resolve().model

    @property
    def settings(self) -> Any:
        return self._resolve().settings

    def _resolve(self) -> Any:
        if self._built is None:
            from defender.runtime.providers import build_for_effort

            self._built = build_for_effort(self.name, self.effort)
        return self._built


def _default_oracle_dir(world: Any, ledger: Ledger) -> Path:
    """The world's oracle store: under its episode, by label, when the world names one; else
    beside the world's own ledger rows (a world served outside an episode)."""
    episode_dir, label = getattr(world, "episode_dir", None), getattr(world, "label", None)
    if episode_dir is not None and isinstance(label, str):
        return Path(episode_dir) / LAYOUT.oracle_dir(label)
    return Path(ledger.path).parent / LAYOUT.oracle_dir(str(world.world_id))


def _world_record(world: Any) -> OracleUnservable | None:
    episode_dir, label = getattr(world, "episode_dir", None), getattr(world, "label", None)
    if episode_dir is None or not isinstance(label, str):
        return None
    try:
        doc = _yaml.safe_load(read_text_utf8(Path(episode_dir) / LAYOUT.world_record(label)))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, Mapping) or doc.get("reason") not in (ORACLE_UNSERVABLE, BUDGET):
        return None
    raw_call = doc.get("call")
    call: Mapping[str, Any] = raw_call if isinstance(raw_call, Mapping) else {}
    raw_params = call.get("params")
    params: Mapping[str, Any] = raw_params if isinstance(raw_params, Mapping) else {}
    return OracleUnservable("budget" if doc["reason"] == BUDGET else "retries",
                            (str(call.get("system", "")), str(call.get("verb", "")),
                             dict(params)), "recorded before this process started")


def _parsed(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return text


_EXAMPLES_PER_SYSTEM = 2
#: The episode folder holding each world's oracle-side state (`oracle/<label>/`).


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
