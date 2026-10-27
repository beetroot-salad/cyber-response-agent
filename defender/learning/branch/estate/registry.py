"""The verb registry a branched run queries through (#1224: served by the world's live oracle)."""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import json
import logging
import threading
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import fields, is_dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from defender import _yaml
from defender.records._episode_paths import LAYOUT
from defender.records._run_id import uuid_id_fault
from defender.investigation.branch import source_alert
from defender.records._family import family_identities
from defender.records import Run
from defender._io import read_jsonl_rows, read_text_utf8
from defender.knowledge._query_rules import ParamsTooDeep, _json_safe_params
from defender.learning.core.config import OracleSettings
from defender.hooks.budget_enforcer import oracle_turn_closed, oracle_turn_opened
from defender.investigation.payload_view import payload_text_of
from defender.tenancy.case_ticket import read_posted_comments
from defender.systems.verbs import (
    CALL_DELIVERY,
    CALL_ID,
    DENIED,
    TABLE_POINTER,
    ModuleVerbRegistry,
    VerbDecision,
)

from defender.records.run_end import TRUNCATED_BY_SERVED_LEDGER, CallRecordWriteFailed

from ..outcome import BUDGET, ORACLE_UNSERVABLE
from ..ledger import (
    FAULT,
    ORACLE,
    PASSTHROUGH,
    REAL_ERROR,
    RECONSTRUCTED,
    REFUSED,
    Ledger,
    LedgerError,
    ServedCall,
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
    order (#1224, #1255 D3/D5/D6)."""
    asked = dict(params)
    key = request_key(system, verb, asked)
    hit = registry.store.answers.get(key)
    if hit is not None:
        return registry._from_store(system, verb, asked, hit)
    base_text, recorded = registry._base(system, verb, fn, ctx, asked)
    if recorded and not registry.world_facts:
        return registry._deliver(ServedCall(
            system=system, verb=verb, params=asked, payload_text=base_text, source=PASSTHROUGH,
            world_id=registry.world.world_id, call_id=CALL_ID.get()))
    with registry._turn(ctx, pauses_clock=True):
        hit = registry.store.answers.get(key)
        if hit is None:
            hit = _served_in_turn(registry, system, verb, asked, base_text,
                                  fixed=registry.fixes(key), live=not recorded)
    return registry._record_answer(system, verb, asked, hit)


def _served_in_turn(registry: WorldRegistry, system: str, verb: str, asked: dict,  # noqa: PLR0913 — the call, its base and the turn's two framings
                    base_text: str, *, fixed: bool, live: bool) -> dict:
    """One oracle turn's committed answer for the call (under the turn the caller holds).
    `fixed`: a recorded pre-branch call, whose changed submission is refused before it is
    checked. `live`: the base is a live read, framed for the oracle as the system now."""
    base = json.loads(base_text)
    digest = base_digest(base_text)
    committed: dict[str, Any] = {}

    def commit(served: Any, claim: dict, verdict: dict, attempts: int, staged: Any) -> None:
        changed = changes_base(served, base)
        decision = (PASSTHROUGH if not changed
                    else ORACLE if registry.world_facts else RECONSTRUCTED)
        answer = {"system": system, "verb": verb, "params": asked,
                  "served": json.loads(payload_text_of(served if changed else base)),
                  "decision": decision,
                  "base_digest": digest, "claim": claim, "verifier_verdict": verdict,
                  "attempts": attempts}
        registry.store.commit(forged=list(staged.forged.values()),
                              facts=[{"entity": e, "field": f, "value": v}
                                     for (e, f), v in staged.facts.items()],
                              answer=answer)
        committed["answer"] = answer

    def unchanged(served: Any) -> str | None:
        return PREBRANCH_REFUSAL if changes_base(served, base) else None

    registry.oracle.serve((system, verb, asked), base,
                          lambda: registry._real(system, base), commit,
                          fixed=fixed, live=live, gate=unchanged if fixed else None)
    return committed["answer"]


#: What the oracle is told when it submits a changed answer to a pre-branch call in a sibling.
PREBRANCH_REFUSAL = ("this call was made before the branch point; serve its base answer "
                     "unchanged (the investigator's inherited transcript already holds it, "
                     "M01=A)")


def changes_base(served: Any, base: Any) -> bool:
    """Whether `served` changes the call's base answer (canonical JSON): the one comparison
    M01=A's fixed prefix is judged by, at pre-flight (`calibrate_one`) and in a sibling
    (`serve_one`)."""
    return canonical_json(served) != canonical_json(base)


def prebranch_calls(source: Run, branch_message_id: int) -> frozenset[str]:
    """The request keys of the calls the source run made before the branch point — the fixed
    prefix of M01=A — derived once by each caller from the source run: pre-flight (each
    replayed call's `fixed`) and the sibling (`WorldRegistry(prebranch=)`). A call is pre-branch
    when the first capture of its key is under a lead the source run held at the branch point.
    A source with no session store cannot say which leads those were, so nothing is fixed."""
    from defender.learning.branch.ledger import request_key as ledger_key
    from defender.learning.lead_repository import load_queries_report
    from defender.investigation import branch

    run_dir = source.run_dir
    opened = branch.source_store_if_any(run_dir, source_run=source)
    if opened is None:
        return frozenset()
    with opened as store:
        session = branch.session_for_run(store, run_dir, source_run=source)
        leads = set(branch.leads_at(store, session, branch_message_id, run_dir, source_run=source))
    rows, _unreadable = load_queries_report(run_dir)
    seen: set[str] = set()
    fixed: set[str] = set()
    for row in rows:
        if row.is_sentinel or not row.system or not row.verb:
            continue
        key = ledger_key(row.system, row.verb, row.params)
        if key in seen:
            continue
        seen.add(key)
        if row.lead_id in leads:
            fixed.add(key)
    return frozenset(fixed)


class PrebranchChanged(Exception):
    """Pre-flight: a world's verified answer changes a call the source run made before the
    branch point (M01=A: that prefix is fixed, so the world cannot be served)."""


def calibrate_one(registry: WorldRegistry, ctx: Any, system: str, verb: str,  # noqa: PLR0913 — the call, its base and its two framings
                  params: Mapping[str, Any], base: Any, *, fixed: bool,
                  live: bool = False) -> None:
    """Pre-flight's replay of one original call through `registry`'s world (#1224, Amendment 2
    change 1): one oracle turn and verifier pass against the call's base answer, under the same
    turn lock, checks and budget as a sibling's call. It only CALIBRATES: a verified attempt
    freezes its forged rows and recorded facts in the world's store, and no served answer is
    cached and no world-ledger row written (S1). The replay itself is one `preflight` row of
    the world's oracle-side ledger (N14)."""
    asked = dict(params)
    registry.store.log_query("preflight", system, verb, asked)

    def commit(served: Any, _claim: dict, _verdict: dict, _attempts: int, staged: Any) -> None:
        if fixed and changes_base(served, base):
            raise PrebranchChanged(
                f"the world's verified answer changes {system}.{verb}, a call the source run "
                "made before the branch point — that prefix is fixed (M01=A)")
        registry.store.commit(forged=list(staged.forged.values()),
                              facts=[{"entity": e, "field": f, "value": v}
                                     for (e, f), v in staged.facts.items()],
                              answer=None)

    with registry._turn(_carrying(ctx, as_of=registry.as_of), pauses_clock=False):
        registry.oracle.serve((system, verb, asked), base,
                              lambda: registry._real(system, base), commit, fixed=fixed,
                              live=live)


@dataclasses.dataclass(frozen=True)
class OracleServing:
    """A world's oracle-side inputs, settled: the oracle and verifier models, the oracle's box
    factory and its knobs. Built once per world by `oracle_serving` at the boundary that starts
    serving it (the sibling's `run.main`, one world per process; the launcher's
    `cli.preflight_replay`, in each world's own thread) and handed inward whole, so no registry
    re-applies a default and no two worlds' event loops share a production model."""

    oracle: Any
    verifier: Any
    box: Callable[[], Any]
    settings: OracleSettings
    restart_after: int


def oracle_serving(settings: OracleSettings, *, oracle: Any = None, verifier: Any = None,
                   box: Callable[[], Any] | None = None,
                   restart_after: int = DEFAULT_RESTART_AFTER) -> OracleServing:
    """The world's oracle-side inputs with every seam left `None` filled by its production
    default: the role models built lazily from `settings` (a world that never takes a turn
    needs no provider key) and the production box. The one place those defaults live."""
    return OracleServing(
        oracle=oracle if oracle is not None else _LazyModel(settings.model, settings.effort),
        verifier=verifier if verifier is not None else _LazyModel(
            settings.check_model, settings.check_effort),
        box=box if box is not None else start_process_box,
        settings=settings, restart_after=restart_after)


class WorldRegistry(ModuleVerbRegistry):
    """A `ModuleVerbRegistry` whose verbs answer as the world's live oracle serves them."""

    def __init__(self, roster, grant, *, world: Any, ledger: Ledger, as_of: datetime,  # noqa: PLR0913 — a world's whole serving identity, its tenant and its settled oracle side
                 serving: OracleServing, oracle_dir: Path, limiter: RateLimiter,
                 tenant: Any = None, grant_home: str = TABLE_POINTER,
                 family_answers: Sequence[FamilyAnswer] | None = None,
                 prebranch: Collection[str] = frozenset(),
                 source_run: Run | None = None):
        """`serving` is the world's settled oracle side (`oracle_serving`), `oracle_dir` its
        oracle-side state (`default_oracle_dir`), `limiter` the process's one rate limiter
        (S16: pre-flight hands every world the launcher's, held at the episode rate; a
        sibling builds its slice's). `family_answers` is the family's base recording as
        `read_family_answers` parses it — pre-flight parses it once for every world; `None`
        parses `ledger.base_path` here. `prebranch` is the request keys of the source run's
        pre-branch calls (`prebranch_calls`), whose answers a sibling serves unchanged.
        `source_run_dir` is the source run's folder, as the opened source `Run` hands it out
        (#1105 PR 2: never the manifest's recorded path); its alert is the oracle's view of the
        case, and `None` serves none."""
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
        if (fault := uuid_id_fault(world_id, "world")) is not None:
            raise EstateError(fault)
        self.world = world
        self.ledger = ledger
        self.tenant = tenant
        self.world_facts = tuple(getattr(world, "facts", ()) or ())
        self.prebranch = frozenset(prebranch)
        #: The calls the source asked whose answer the recording lacks (#1255 D6, the primer's
        #: skip record): never fixed, served through the oracle at the fork time.
        self.unrecorded = ledger.unrecorded_keys()
        self._source_run = source_run
        self.store = OracleStore(Path(oracle_dir))
        self._turn_lock = threading.Lock()
        #: The context of the call whose turn holds the lock: every oracle-side query of that
        #: turn runs in it. Set and cleared only under the lock.
        self._turn_ctx: Any = None
        #: The family's base recording as `(system, verb, answer)`, parsed once: every host
        #: check reads it, and it does not change while the world is served.
        self._family_answers = list(family_answers if family_answers is not None
                                    else read_family_answers(ledger.base_path))
        #: This world's real data, indexed once and grown as answers arrive (`_real`).
        self._real_data = RealData(
            answers=[(s, answer) for s, _verb, answer in self._family_answers])
        self._kept_seen = 0
        self._explored_seen = 0
        #: The last base answer added to `_real_data` (held, so identity is a safe test).
        self._real_base: Any = None
        #: A host check abandoned by a passed deadline may still be reading on its own thread
        #: while the next attempt checks: the index grows under one lock.
        self._real_lock = threading.Lock()
        door = QueryDoor(
            decide=lambda system, verb: ModuleVerbRegistry.decide(self, system, verb),
            real_verbs=lambda system: ModuleVerbRegistry.verbs(self, system),
            limiter=limiter, store=self.store, context=self._oracle_context)
        settings = serving.settings
        self.oracle = Oracle(
            world=world, store=self.store, door=door,
            oracle_model=serving.oracle, verifier_model=serving.verifier,
            box_factory=serving.box,
            retry_cap=settings.retry_cap, turn_deadline=settings.turn_deadline,
            budget=settings.budget, restart_after=serving.restart_after,
            family_examples=self._examples(), real_extra=self._alert(),
            source_writes=self._source_writes())
        # A world whose sibling already went unservable stays so on resume: its failing call
        # is never retried (N13). Its record is the sibling's own (`run.py`), read here.
        recorded = _world_record(world)
        if recorded is not None:
            self.oracle.unservable = recorded
        self._wrapped: dict[str, dict[str, Any]] = {}

    def fixes(self, key: str) -> bool:
        """Whether the call keyed `key` is a fixed pre-branch answer (M01=A): one the source
        made before the branch point, unless the primer recorded it unanswered (#1255 D6)."""
        return key in self.prebranch and key not in self.unrecorded

    @property
    def call_run(self) -> str:
        """How this world's call ids name its run (`record_query.bind_call_ids`): the world
        token every served-ledger row of the world carries as `world_id`."""
        return str(self.world.world_id)

    def branch_identities(self) -> frozenset[str]:
        """The whole family this world belongs to (`family_identities`), from the manifest the
        sibling was resumed from and its episode's arm roster (#1187 S-red): what the query
        tool removes from model-visible fault text. A world resumed without the roster has no
        arm ids to name, and is refused rather than answering a set that leaves them out."""
        if self.world.arm_ids is None:
            raise EstateError(
                f"world {self.world.label!r} was resumed without its episode's arm roster, so "
                "its family's arm ids cannot be kept out of model-visible text")
        return family_identities(self.world.family, self.world.arm_ids)

    # -- the grant door -------------------------------------------------------------------------

    def authorize_call(self, system: str, verb: str, params: Mapping[str, Any]) -> VerbDecision:
        """Record a cold grant refusal once, before the callable resolution door."""
        _refuse_unstorable(system, verb, params)
        decision = super().authorize_call(system, verb, params)
        if decision.outcome == DENIED:
            _record_beside(self.ledger, ServedCall(
                system=system, verb=verb, params=dict(params),
                payload_text=decision.refusal or f"denied: {system}.{verb}", source=REFUSED,
                world_id=self.world.world_id, call_id=CALL_ID.get(),
            ))
        return decision

    def resolve_call(self, system: str, verb: str, params: Mapping[str, Any]) -> VerbDecision:
        """Record a callable loading fault once; runnable calls are recorded by `served`."""
        _refuse_unstorable(system, verb, params)
        try:
            return super().resolve_call(system, verb, params)
        except Exception as failure:
            _record_beside(self.ledger, ServedCall(
                system=system, verb=verb, params=dict(params),
                payload_text=f"{type(failure).__name__}: {failure}", source=FAULT,
                world_id=self.world.world_id, call_id=CALL_ID.get(),
            ))
            raise

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

    def _base(self, system: str, verb: str, fn: Any, ctx: Any,
              params: dict) -> tuple[str, bool]:
        """The call's base answer text and whether it is the family's recording (an answer the
        source received): the recording, else this world's own base store, else one live read
        at the fork time kept in that store (never a world-ledger row, M16). A live base keeps
        the adapter's own spelling (`payload_text_of`, #1255 G8). A real error on the read is
        recorded `real-error` and passes through untouched."""
        recorded = self.ledger.base_payload(system, verb, params)
        if recorded is not None:
            return recorded, True
        kept = self.store.base.get(request_key(system, verb, params))
        if kept is not None:
            return kept, False
        try:
            answer = fn(ctx, **params)
        except Exception as failure:
            _record_beside(self.ledger, ServedCall(
                system=system, verb=verb, params=dict(params),
                payload_text=str(failure) or type(failure).__name__, source=REAL_ERROR,
                world_id=self.world.world_id, call_id=CALL_ID.get()))
            raise
        text = payload_text_of(answer)
        self.store.keep_base(system, verb, params, text)
        return text, False

    def _from_store(self, system: str, verb: str, params: dict, answer: dict) -> Any:
        return self._record_answer(system, verb, params, answer)

    def _record_answer(self, system: str, verb: str, params: dict, answer: dict) -> Any:
        """The stored answer, delivered to this call (`_deliver`)."""
        return self._deliver(ServedCall(
            system=system, verb=verb, params=params,
            payload_text=payload_text_of(answer.get("served")),
            source=answer.get("decision") or ORACLE, world_id=self.world.world_id,
            base_digest=answer.get("base_digest"), claim=answer.get("claim"),
            verifier_verdict=answer.get("verifier_verdict"), attempts=answer.get("attempts"),
            # This call's id, never the stored answer's: a repeat is its own call (A12).
            call_id=CALL_ID.get()))

    def _deliver(self, call: ServedCall) -> Any:
        """`call`'s payload, handed to the caller and recorded as served — unless its caller
        stopped waiting (the lead was ended mid-call): an undelivered call leaves no row (N12).
        The one writer of a delivered call's row, whatever served it. A failed write is
        `CallRecordWriteFailed` and nothing is delivered: the run ends (A12)."""
        delivery = CALL_DELIVERY.get()
        if delivery is None or not delivery.abandoned:
            try:
                self.ledger.record(call)
            except OSError as failed:
                raise _ledger_write_failed(call, failed) from failed
        return json.loads(call.payload_text)

    @contextlib.contextmanager
    def _turn(self, ctx: Any, *, pauses_clock: bool) -> Iterator[None]:
        """One oracle turn at a time in this world (S11), its oracle-side queries run in `ctx`,
        and — for an investigator's call (`pauses_clock`) — the investigator's clock paused for
        as long as the turn is held (S12-S15). The clock is the run's own, on the run state the
        call's context carries (#1235); pre-flight's replay carries none and has no clock."""
        state = getattr(ctx, "run_state", None) if pauses_clock else None
        with self._turn_lock:
            self._turn_ctx = ctx
            if state is not None:
                oracle_turn_opened(state)
            ended = False
            try:
                yield
                ended = True
            finally:
                self._turn_ctx = None
                if state is not None:
                    try:
                        oracle_turn_closed(state)
                    except Exception as unclosed:
                        if ended:
                            # Nothing is recorded or delivered inside a turn (`serve_one`
                            # does both after it), so this replaces no answer (N12).
                            raise
                        # The turn's own abort (an unservable world, which ends the sibling)
                        # is what leaves; a turn left open lives only on the run's state
                        # (`budget_enforcer.oracle_held`), which ends with the run.
                        _logger.warning(f"the oracle turn's clock mark could not be closed "
                                        f"({unclosed!r}) while the turn was aborting")

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
            if base is not self._real_base:
                # This call's base, once: a check or submit re-reading the index does not
                # re-serialise the same answer.
                data.add(system, base)
                self._real_base = base
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
        if self._source_run is None:
            return []
        alert = source_alert(self._source_run)
        return [alert] if alert is not None else []

    def _source_writes(self) -> list[tuple[str, str]]:
        """The source run's own writes to the world after the branch point (#1255 P5, O6): the
        comments it posted on its case ticket when it closed, read off its host-only record
        (`case_ticket.read_posted_comments`). The host never transitions a case, so its
        comments are the writes there are. `[]` with no source run, or none posted."""
        if self._source_run is None:
            return []
        return [(f"its comment on case ticket {key}", body)
                for key, body in read_posted_comments(self._source_run)]

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
    def model_name(self) -> str:
        """The knob's model name, which prices the role without building it (`price_row`)."""
        return self.name

    @property
    def model(self) -> Any:
        return self._resolve().model

    @property
    def settings(self) -> Any:
        return self._resolve().settings

    def _resolve(self) -> Any:
        if self._built is None:
            from defender.providers import build_for_effort

            self._built = build_for_effort(self.name, self.effort)
        return self._built


def default_oracle_dir(world: Any, ledger: Ledger) -> Path:
    """The world's UUID oracle store under its episode or beside its standalone ledger."""
    episode_dir = getattr(world, "episode_dir", None)
    root = Path(episode_dir) if episode_dir is not None else Path(ledger.path).parent
    return root / LAYOUT.oracle_dir(str(world.world_id))


def _world_record(world: Any) -> OracleUnservable | None:
    episode_dir = getattr(world, "episode_dir", None)
    if episode_dir is None:
        return None
    try:
        doc = _yaml.safe_load(read_text_utf8(Path(episode_dir) / LAYOUT.world_record(str(world.world_id))))
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


#: One answer of the family's base recording: `(system, verb, answer)`.
FamilyAnswer = tuple[str, str, Any]


def read_family_answers(base_path: Path) -> list[FamilyAnswer]:
    """The family's base recording at `base_path` as `(system, verb, answer)`, in recorded
    order — read and parsed once per episode: it does not change while any world is served,
    and every world's host checks and family block read it."""
    return [(r["system"], str(r.get("verb")), _parsed(r["payload_text"]))
            for r in read_jsonl_rows(base_path)
            if isinstance(r.get("system"), str) and isinstance(r.get("payload_text"), str)]


def _parsed(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return text


_EXAMPLES_PER_SYSTEM = 2
#: The episode folder holding each world's oracle-side state (`oracle/<world-uuid>/`).


def _refuse_unstorable(system: str, verb: str, params: Mapping[str, Any]) -> None:
    """Refuse, as the table's own `LedgerError`, a call whose params no ledger row could carry.

    Every call entry (`authorize_call`, `resolve_call`, `served`) asks this before anything is
    decided,
    served or filed: past them every row is built from params already known to fit, so no
    refused or FAULT row is ever attempted and then dropped. `served` re-raises `LedgerError`
    untouched, where any other exception would be filed as a FAULT row."""
    try:
        _json_safe_params(params)
    except ParamsTooDeep as too_deep:
        raise LedgerError(f"{system}.{verb} was not served: {too_deep}") from too_deep


def _record_beside(ledger: Ledger, call: ServedCall) -> None:
    """Record the row of a call that is failing (`refused`, `fault`, `real-error`) beside the
    decision or exception its caller then returns or re-raises.

    A failed write is not dropped: the ledger's `OSError` becomes `CallRecordWriteFailed`,
    which replaces the call's own failure and ends the run (A12, #1234). The query tool lets it
    through as control flow, so it is never filed as a fault row or charged to the breaker."""
    try:
        ledger.record(call)
    except OSError as failed:
        raise _ledger_write_failed(call, failed) from failed


def _ledger_write_failed(call: ServedCall, failed: OSError) -> CallRecordWriteFailed:
    """What a failed write of `call`'s served-ledger row raises: the run ends, naming the
    record (A12). The ledger's own `OSError` is kept as the cause."""
    return CallRecordWriteFailed(
        TRUNCATED_BY_SERVED_LEDGER,
        f"the {call.source} row of {call.system}.{call.verb} "
        f"({call.call_id or 'no call id'}): {failed!r}")


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
