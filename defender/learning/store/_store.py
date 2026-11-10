"""The learning store (#1278): work items, batches and the commit-maker's record on PostgreSQL.

Each verb is one transaction. Rules races could break are the database's: the partial unique indexes
(one open author batch and one working batch per lane, one waiting request per case) and a fencing
token. A holder's verb is a compare-and-set on its batch, its token and a lease that has not run out by
the database's clock, so a holder that lost its lease changes nothing (P6). Reconcile has no holder: its
verbs are compare-and-set on the phase they expect (D7). A tenant that is not active gets no new batch
and no new findings, decided in the same transaction as the insert (O6).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import Text, and_, case, delete, exists, func, literal, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from defender.database import async_engine, sessions
from defender.records.formats import BatchId, TenantId
from defender.tenancy.models import TenantRecord

from .models import (
    AUTHOR_LANE,
    LANE_OF,
    LANES,
    LEAD_LANE,
    BatchRow,
    CommitChangeRow,
    CommitRow,
    WorkItemRow,
)

#: A lease must outlast the worker's 30 s stop grace (#1081), so a brief database blip costs no authoring run.
DEFAULT_LEASE_SECONDS = 120.0
#: After its lease ends a batch is still its holder's for this long before a takeover may fence it.
DEFAULT_GRACE_SECONDS = 60.0
DEFAULT_RENEW_SECONDS = 30.0
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_GENERATION_CEILING = 3
DEFAULT_REFUSAL_CEILING = 3

BRANCH_PREFIX = {AUTHOR_LANE: "lessons/", LEAD_LANE: "lead-author/"}
REVERT_PREFIX = "lessons/revert-"

_I = WorkItemRow.__table__
_B = BatchRow.__table__
_C = CommitRow.__table__
_CC = CommitChangeRow.__table__


class Stop(Exception):
    """The holder must stop: its batch was cancelled or its lease is gone. One stop for both (Renewal and stop)."""


class LeaseLost(Stop):
    """The batch is no longer this holder's: its lease ran out, it was taken over, or it ended."""


class NotLapsed(Exception):
    """A takeover or a recovery abandon of a batch whose lease (and grace) has not run out."""


class LaneBusy(Exception):
    """The lane has a batch that forbids this one (O3, H4, D6)."""


class TenantInactive(Exception):
    """The tenant is not active: no new batch and no new findings (O6)."""


class ItemRefused(Exception):
    """The database will never take this item (a NUL character jsonb refuses): waiting cannot cure it."""


class ImportRefused(Exception):
    """The one-time import of a tenant's file state refused; it wrote nothing (G-I10)."""


@dataclasses.dataclass(frozen=True)
class Outcome:
    """What a curator decided for one item (D1); the store applies it when the batch enters review or ends."""

    name: str
    reason: str | None = None

    @classmethod
    def waiting(cls) -> Outcome:
        return cls("waiting")

    @classmethod
    def skipped(cls, reason: str) -> Outcome:
        return cls("skipped", reason)

    @classmethod
    def held(cls, reason: str) -> Outcome:
        return cls("held", reason)

    @classmethod
    def dead(cls, reason: str) -> Outcome:
        return cls("dead", reason)

    @classmethod
    def published(cls) -> Outcome:
        return cls("published")

    @classmethod
    def deferred(cls) -> Outcome:
        return cls("deferred")


Outcomes = Mapping[tuple[str, str], Outcome]


@dataclasses.dataclass(frozen=True)
class WorkItem:
    kind: str
    key: str
    status: str
    reason: str | None
    fault: str | None
    batch_id: BatchId | None
    pr_number: int | None
    attempts: int
    deferrals: int
    offers_declined: int
    coalesce_key: str | None
    mistake_key: str | None
    payload: dict[str, Any]
    source_run: str | None
    enqueued_at: _dt.datetime
    updated_at: _dt.datetime


@dataclasses.dataclass(frozen=True)
class BatchView:
    id: BatchId
    tenant_id: TenantId
    kind: str
    lane: str
    branch: str
    base: str | None
    start: str | None
    phase: str
    outcome: str | None
    lease_owner: str | None
    lease_expiry: _dt.datetime | None
    token: int
    cancel_requested: bool
    pr_number: int | None
    replaces: BatchId | None
    generation: int
    refusals: int
    last_checked: _dt.datetime | None
    reason: str | None
    created_at: _dt.datetime
    ended_at: _dt.datetime | None


@dataclasses.dataclass(frozen=True)
class Held:
    """A batch a holder owns: the proof its verbs present (batch id, token) and what it holds."""

    tenant_id: TenantId
    batch_id: BatchId
    lane: str
    kind: str
    branch: str
    token: int
    owner: str
    items: tuple[tuple[str, str, dict[str, Any]], ...]
    replaces: BatchId | None = None
    #: The PR of the batch this one replaces: the feedback is read from it (H13).
    feedback_pr: int | None = None


@dataclasses.dataclass(frozen=True)
class CommitRecord:
    commit: str
    branch: str
    base: str
    start: str
    batch_id: BatchId | None
    changes: tuple[tuple[str, str | None, str | None], ...]
    #: `(batch, path)` a revert commit undoes (the batch by id; by branch for imported history); `None` otherwise.
    reverts: tuple[tuple[str, str], ...] | None
    #: The corpora the commit's batch writes (`DrainLabel.lanes`), by its branch's lane.
    lanes: tuple[str, ...] = ()


def _view(row: Any) -> BatchView:
    return BatchView(
        id=row.id, tenant_id=row.tenant_id, kind=row.kind, lane=row.lane, branch=row.branch, base=row.base,
        start=row.start, phase=row.phase, outcome=row.outcome, lease_owner=row.lease_owner,
        lease_expiry=row.lease_expiry, token=row.fencing_token, cancel_requested=row.cancel_requested,
        pr_number=row.pr_number, replaces=row.replaces, generation=row.generation, refusals=row.refusals,
        last_checked=row.last_checked, reason=row.reason, created_at=row.created_at, ended_at=row.ended_at)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:32]


def _has_nul(value: Any) -> bool:
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, Mapping):
        return any(_has_nul(k) or _has_nul(v) for k, v in value.items())
    if isinstance(value, list | tuple):
        return any(_has_nul(v) for v in value)
    return False


def _refuse_nul(value: Any) -> None:
    if _has_nul(value):
        raise ItemRefused("a NUL character cannot be stored")


def _superseded(item: Any) -> Any:
    """The test that a request returning to waiting has a fresher one waiting for its case."""
    other = _I.alias()
    return and_(item.c.kind == "curation_request", item.c.coalesce_key.is_not(None),
                exists().where(and_(other.c.tenant_id == item.c.tenant_id, other.c.kind == item.c.kind,
                                    other.c.coalesce_key == item.c.coalesce_key, other.c.status == "waiting",
                                    other.c.item_key != item.c.item_key)))


def _to_waiting() -> dict[str, Any]:
    """Values returning an item to waiting: a request with a fresher one waiting becomes skipped, superseded."""
    sup = _superseded(_I)
    return {"status": case((sup, "skipped"), else_="waiting"),
            "reason": case((sup, "superseded by a later run"), else_=_I.c.reason)}


class LearningStore:
    """Async store over PostgreSQL schema `learning`; tenant id is the first argument of every verb."""

    def __init__(self, dsn: str, *, lease: float = DEFAULT_LEASE_SECONDS, grace: float = DEFAULT_GRACE_SECONDS,
                 renew_every: float = DEFAULT_RENEW_SECONDS, max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                 generation_ceiling: int = DEFAULT_GENERATION_CEILING,
                 refusal_ceiling: int = DEFAULT_REFUSAL_CEILING, max_connections: int = 10) -> None:
        self.lease, self.grace, self.renew_every = lease, grace, renew_every
        self.max_attempts = max_attempts
        self.generation_ceiling, self.refusal_ceiling = generation_ceiling, refusal_ceiling
        self._engine = async_engine(dsn, max_connections=max_connections)
        self._sessions = sessions(self._engine)

    async def close(self) -> None:
        await self._engine.dispose()

    # -- small shared pieces ---------------------------------------------------------------------------------

    def _in(self, seconds: float) -> Any:
        return func.now() + literal(_dt.timedelta(seconds=seconds))

    async def _require_active(self, s: AsyncSession, tenant: str) -> None:
        """The tenant is active, held so for this transaction (a share lock keeps the offboarding's update behind it)."""
        state = (await s.execute(select(TenantRecord.state).where(TenantRecord.id == TenantId(tenant))
                                 .with_for_update(read=True))).scalar_one_or_none()
        if state != "active":
            raise TenantInactive(tenant)

    async def _guard(self, s: AsyncSession, held: Held) -> Any:
        """The batch row, locked, if `held` is still its live holder; else `LeaseLost`."""
        row = (await s.execute(select(_B).where(
            _B.c.id == held.batch_id, _B.c.tenant_id == held.tenant_id, _B.c.fencing_token == held.token,
            _B.c.phase == "working", _B.c.lease_expiry > func.now()).with_for_update())).first()
        if row is None:
            raise LeaseLost(str(held.batch_id))
        return row

    async def _batch(self, s: AsyncSession, tenant: str, batch_id: str, *, lock: bool = True) -> Any:
        query = select(_B).where(_B.c.id == BatchId(batch_id), _B.c.tenant_id == TenantId(tenant))
        row = (await s.execute(query.with_for_update() if lock else query)).first()
        if row is None:
            raise LookupError(f"no batch {batch_id}")
        return row

    # -- items arrive ------------------------------------------------------------------------------------------

    async def publish_findings(self, tenant: str, run_id: str, rows: Sequence[Mapping[str, Any]], *,
                               kind: str) -> tuple[int, int]:
        """Queue `rows` as `kind`: `(added, duplicates)`. A finding id is unique for good (O14)."""
        if LANE_OF.get(kind) != AUTHOR_LANE:
            raise ValueError(f"not a findings kind: {kind}")
        for row in rows:
            _refuse_nul(row)
        added = 0
        async with self._sessions.begin() as s:
            await self._require_active(s, tenant)
            for row in rows:
                added += await self._insert_item(s, tenant, kind, str(row["finding_id"]), dict(row), source_run=run_id)
        return added, len(rows) - added

    async def add_pitfall(self, tenant: str, row: Mapping[str, Any]) -> bool:
        """Queue one pitfall occurrence; a repeated pitfall id is ignored, a keyless row is keyed by its digest."""
        _refuse_nul(row)
        key = str(row["pitfall_id"]) if row.get("pitfall_id") else _digest(dict(row))
        mistake = _digest([row.get("system"), row.get("stderr_digest")])
        async with self._sessions.begin() as s:
            await self._require_active(s, tenant)
            return bool(await self._insert_item(s, tenant, "pitfall", key, dict(row), source_run=_text(row.get("source_run")),
                                                mistake_key=mistake))

    async def enqueue_request(self, tenant: str, run_id: str, case_id: str, spec: Mapping[str, Any]) -> bool:
        """File a curation request for `case_id`; the later run wins: an older waiting request is skipped, superseded."""
        _refuse_nul(spec)
        async with self._sessions.begin() as s:
            await self._require_active(s, tenant)
            have = (await s.execute(select(_I.c.item_key).where(
                _I.c.tenant_id == TenantId(tenant), _I.c.kind == "curation_request", _I.c.item_key == run_id))).first()
            if have is not None:
                return False
            await s.execute(update(_I).where(
                _I.c.tenant_id == TenantId(tenant), _I.c.kind == "curation_request", _I.c.coalesce_key == case_id,
                _I.c.status == "waiting").values(status="skipped", reason=f"superseded by run {run_id}",
                                                 updated_at=func.now()))
            return bool(await self._insert_item(s, tenant, "curation_request", run_id, dict(spec), source_run=run_id,
                                                coalesce_key=case_id))

    async def _insert_item(self, s: AsyncSession, tenant: str, kind: str, key: str, payload: dict[str, Any], *,
                           status: str = "waiting", source_run: str | None = None, coalesce_key: str | None = None,
                           mistake_key: str | None = None, reason: str | None = None, attempts: int = 0,
                           deferrals: int = 0, offers_declined: int = 0, batch_id: str | None = None) -> int:
        stmt = pg_insert(_I).values(
            tenant_id=TenantId(tenant), kind=kind, item_key=key, payload=payload, source_run=source_run, status=status,
            reason=reason, fault=None, batch_id=batch_id, attempts=attempts, deferrals=deferrals,
            offers_declined=offers_declined, coalesce_key=coalesce_key, mistake_key=mistake_key,
            enqueued_at=func.now(), updated_at=func.now()).on_conflict_do_nothing(
            index_elements=["tenant_id", "kind", "item_key"]).returning(_I.c.item_key)
        try:
            return len((await s.execute(stmt)).all())
        except DataError as refused:
            raise ItemRefused(str(refused.orig)) from refused

    # -- views -------------------------------------------------------------------------------------------------

    async def work(self, tenant: str) -> list[WorkItem]:
        async with self._sessions() as s:
            rows = (await s.execute(
                select(_I, _B.c.pr_number).select_from(_I.outerjoin(_B, _I.c.batch_id == _B.c.id))
                .where(_I.c.tenant_id == TenantId(tenant)).order_by(_I.c.kind, _I.c.item_key))).all()
        return [WorkItem(kind=r.kind, key=r.item_key, status=r.status, reason=r.reason, fault=r.fault,
                         batch_id=r.batch_id, pr_number=r.pr_number, attempts=r.attempts, deferrals=r.deferrals,
                         offers_declined=r.offers_declined, coalesce_key=r.coalesce_key, mistake_key=r.mistake_key,
                         payload=r.payload, source_run=r.source_run, enqueued_at=r.enqueued_at,
                         updated_at=r.updated_at) for r in rows]

    async def batches(self, tenant: str) -> list[BatchView]:
        async with self._sessions() as s:
            rows = (await s.execute(select(_B).where(_B.c.tenant_id == TenantId(tenant))
                                    .order_by(_B.c.created_at, _B.c.id))).all()
        return [_view(r) for r in rows]

    async def commit_record(self, tenant: str) -> list[CommitRecord]:
        async with self._sessions() as s:
            commits = (await s.execute(select(_C).where(_C.c.tenant_id == TenantId(tenant))
                                       .order_by(_C.c.created_at, _C.c.id))).all()
            changes = (await s.execute(select(_CC).where(_CC.c.tenant_id == TenantId(tenant))
                                       .order_by(_CC.c.commit_row, _CC.c.ordinal))).all()
        by_commit: dict[str, list[tuple[str, str | None, str | None]]] = {}
        for c in changes:
            by_commit.setdefault(c.commit_row, []).append((c.path, c.blob_base, c.blob_left))
        return [CommitRecord(commit=c.commit, branch=c.branch, base=c.base, start=c.start, batch_id=c.batch_id,
                             changes=tuple(by_commit.get(c.id, ())), lanes=lanes_of_branch(c.branch),
                             reverts=None if c.reverts is None else tuple((str(a), str(b)) for a, b in c.reverts))
                for c in commits]

    # -- claims ------------------------------------------------------------------------------------------------

    async def claim(self, tenant: str, lane: str, *, owner: str, thresholds: Mapping[str, int]) -> Held | None:
        """Start a working batch on `lane` over what is due, in one transaction (P2'); `None` when nothing is due.

        A replacement due (items still in a batch that closed with feedback) goes first and takes only those items;
        otherwise every waiting item of each kind at or over its threshold."""
        if lane not in LANES:
            raise ValueError(f"not a lane: {lane}")
        kinds = [k for k, ln in LANE_OF.items() if ln == lane]
        try:
            async with self._sessions.begin() as s:
                await self._require_active(s, tenant)
                await self._refuse_if_busy(s, tenant, lane)
                held = await self._claim_replacement(s, tenant, lane, kinds, owner)
                if held is None:
                    held = await self._claim_due(s, tenant, lane, kinds, owner, thresholds)
                return held
        except IntegrityError as raced:
            if _violates(raced, "batches_one_"):
                raise LaneBusy(lane) from None
            raise

    async def _refuse_if_busy(self, s: AsyncSession, tenant: str, lane: str) -> None:
        busy = (await s.execute(select(_B.c.id).where(
            _B.c.tenant_id == TenantId(tenant), _B.c.lane == lane,
            or_(_B.c.phase == "working", and_(_B.c.kind == "author", _B.c.phase != "ended"),
                and_(lane == AUTHOR_LANE, _B.c.kind == "revert", _B.c.phase == "in_review"))).limit(1))).first()
        if busy is not None:
            raise LaneBusy(lane)

    async def _claim_replacement(self, s: AsyncSession, tenant: str, lane: str, kinds: list[str],
                                 owner: str) -> Held | None:
        due = (await s.execute(
            select(_I.c.batch_id).select_from(_I.join(_B, _I.c.batch_id == _B.c.id))
            .where(_I.c.tenant_id == TenantId(tenant), _I.c.kind.in_(kinds), _I.c.status == "in_batch",
                   _B.c.phase == "ended", _B.c.outcome == "closed")
            .group_by(_I.c.batch_id, _B.c.ended_at).order_by(_B.c.ended_at.desc(), _I.c.batch_id).limit(1))).first()
        if due is None:
            return None
        old = (await s.execute(select(_B).where(_B.c.id == due.batch_id).with_for_update())).one()
        if old.generation >= self.generation_ceiling:
            await s.execute(update(_I).where(_I.c.tenant_id == TenantId(tenant), _I.c.batch_id == old.id,
                                             _I.c.status == "in_batch").values(
                status="held", updated_at=func.now(),
                reason=f"feedback reached the replacement ceiling ({self.generation_ceiling} replacement PRs)"))
            return None
        return await self._new_batch(s, tenant, lane, "author", owner, kinds, generation=old.generation,
                                     replaces=old.id, feedback_pr=old.pr_number, only_batch=old.id)

    async def _claim_due(self, s: AsyncSession, tenant: str, lane: str, kinds: list[str], owner: str,
                         thresholds: Mapping[str, int]) -> Held | None:
        counts = dict((await s.execute(
            select(_I.c.kind, func.count()).where(_I.c.tenant_id == TenantId(tenant), _I.c.kind.in_(kinds),
                                                  _I.c.status == "waiting").group_by(_I.c.kind))).all())
        due = [k for k in kinds if counts.get(k, 0) > 0 and counts[k] >= max(1, thresholds.get(k, 1))]
        if not due:
            return None
        return await self._new_batch(s, tenant, lane, "author", owner, due, generation=0, replaces=None,
                                     feedback_pr=None, only_batch=None)

    async def _new_batch(self, s: AsyncSession, tenant: str, lane: str, kind: str, owner: str, kinds: list[str], *,
                         generation: int, replaces: Any, feedback_pr: int | None, only_batch: Any,
                         branch: str | None = None) -> Held:
        batch_id = BatchId.mint()
        branch = branch or f"{BRANCH_PREFIX[lane]}{uuid.uuid4().hex[:12]}"
        await s.execute(_B.insert().values(
            id=batch_id, tenant_id=TenantId(tenant), kind=kind, lane=lane, branch=branch, phase="working",
            lease_owner=owner, lease_expiry=self._in(self.lease), fencing_token=1, cancel_requested=False,
            replaces=replaces, generation=generation, refusals=0, created_at=func.now()))
        if kinds:
            where = [_I.c.tenant_id == TenantId(tenant), _I.c.kind.in_(kinds)]
            where += [_I.c.status == "in_batch", _I.c.batch_id == only_batch] if only_batch else [_I.c.status == "waiting"]
            rows = (await s.execute(update(_I).where(*where).values(
                status="in_batch", batch_id=batch_id, attempts=_I.c.attempts + 1, updated_at=func.now())
                .returning(_I.c.kind, _I.c.item_key, _I.c.payload))).all()
        else:
            rows = []
        items = tuple(sorted(((r.kind, r.item_key, r.payload) for r in rows), key=lambda t: (t[0], t[1])))
        return Held(tenant_id=TenantId(tenant), batch_id=batch_id, lane=lane, kind=kind, branch=branch, token=1,
                    owner=owner, items=items, replaces=replaces, feedback_pr=feedback_pr)

    async def claim_revert(self, tenant: str, *, owner: str) -> Held:
        """A revert batch (no items): needs the working rule only; an open author PR does not block it."""
        try:
            async with self._sessions.begin() as s:
                await self._require_active(s, tenant)
                busy = (await s.execute(select(_B.c.id).where(
                    _B.c.tenant_id == TenantId(tenant), _B.c.lane == AUTHOR_LANE, _B.c.phase == "working").limit(1))).first()
                if busy is not None:
                    raise LaneBusy(AUTHOR_LANE)
                return await self._new_batch(s, tenant, AUTHOR_LANE, "revert", owner, [], generation=0, replaces=None,
                                             feedback_pr=None, only_batch=None,
                                             branch=f"{REVERT_PREFIX}{uuid.uuid4().hex[:12]}")
        except IntegrityError as raced:
            if _violates(raced, "batches_one_"):
                raise LaneBusy(AUTHOR_LANE) from None
            raise

    async def take_over(self, tenant: str, batch_id: str, *, owner: str) -> Held:
        """Fence a working batch whose lease and grace have run out and become its holder (O1, P6)."""
        async with self._sessions.begin() as s:
            row = await self._batch(s, tenant, batch_id)
            lapsed = (await s.execute(select(func.now() > row.lease_expiry + literal(_dt.timedelta(seconds=self.grace)))
                                      )).scalar_one() if row.lease_expiry is not None else False
            if row.phase != "working" or not lapsed:
                raise NotLapsed(batch_id)
            token = row.fencing_token + 1
            await s.execute(update(_B).where(_B.c.id == row.id).values(
                lease_owner=owner, lease_expiry=self._in(self.lease), fencing_token=token))
            items = (await s.execute(select(_I.c.kind, _I.c.item_key, _I.c.payload).where(
                _I.c.tenant_id == TenantId(tenant), _I.c.batch_id == row.id, _I.c.status == "in_batch")
                .order_by(_I.c.kind, _I.c.item_key))).all()
            feedback = None
            if row.replaces is not None:
                feedback = (await s.execute(select(_B.c.pr_number).where(_B.c.id == row.replaces))).scalar_one_or_none()
            return Held(tenant_id=TenantId(tenant), batch_id=row.id, lane=row.lane, kind=row.kind, branch=row.branch,
                        token=token, owner=owner, items=tuple((r.kind, r.item_key, r.payload) for r in items),
                        replaces=row.replaces, feedback_pr=feedback)

    # -- the holder's verbs --------------------------------------------------------------------------------

    async def renew(self, held: Held) -> None:
        """Extend the lease; a cancel is a stop (after the extension, so the stop path still holds the batch)."""
        async with self._sessions.begin() as s:
            await self._guard(s, held)
            cancelled = (await s.execute(update(_B).where(_B.c.id == held.batch_id).values(
                lease_expiry=self._in(self.lease)).returning(_B.c.cancel_requested))).scalar_one()
        if cancelled:
            raise Stop(f"batch {held.batch_id} was cancelled")

    async def record_commit(self, held: Held, commit: str, base: str, start: str,
                            changes: Sequence[tuple[str, str | None, str | None]], *, reverts: Any = None) -> None:
        """Record one commit before the branch moves. The first one sets the batch's base and start (D5)."""
        pairs = None
        if reverts:
            reverts = list(reverts)
            pairs = [[str(reverts[0]), str(reverts[1])]] if len(reverts) == 2 and all(
                isinstance(x, str) for x in reverts) else [[str(a), str(b)] for a, b in reverts]
        async with self._sessions.begin() as s:
            row = await self._guard(s, held)
            if row.base is None:
                await s.execute(update(_B).where(_B.c.id == held.batch_id).values(base=base, start=start))
            row_id = str(uuid.uuid4())
            await s.execute(_C.insert().values(
                id=row_id, tenant_id=held.tenant_id, batch_id=held.batch_id, commit=commit, branch=row.branch,
                base=base, start=start, reverts=pairs, created_at=func.clock_timestamp()))
            for ordinal, (path, before, after) in enumerate(changes):
                await s.execute(_CC.insert().values(commit_row=row_id, ordinal=ordinal, tenant_id=held.tenant_id,
                                                    path=path, blob_base=before, blob_left=after))

    async def in_review(self, held: Held, pr_number: int, outcomes: Outcomes) -> None:
        """The PR opened: the batch is in review, a replacement counts a generation, and `outcomes` are applied."""
        async with self._sessions.begin() as s:
            row = await self._guard(s, held)
            await s.execute(update(_B).where(_B.c.id == held.batch_id).values(
                phase="in_review", pr_number=pr_number, lease_owner=None, lease_expiry=None,
                last_checked=func.now(), refusals=0,
                generation=row.generation + (1 if row.replaces is not None else 0)))
            await self._apply(s, held.tenant_id, held.batch_id, outcomes, default=None)

    async def end_no_commits(self, held: Held, outcomes: Outcomes) -> None:
        """Nothing was committed: the batch ends and its items take their outcomes (unnamed: back to waiting; a
        replacement's unnamed items are held, so the same feedback cannot loop)."""
        async with self._sessions.begin() as s:
            row = await self._guard(s, held)
            await self._apply(s, held.tenant_id, held.batch_id, outcomes, default=(
                Outcome.held("the replacement committed nothing") if row.replaces is not None else Outcome.waiting()))
            await self._end(s, held.batch_id, "abandoned", reason="no commits", token=held.token + 1)

    async def abandon_clean(self, held: Held) -> None:
        """A clean stop: the batch ends abandoned; its items return with the attempt forgiven (a deploy costs nothing)."""
        async with self._sessions.begin() as s:
            row = await self._guard(s, held)
            await self._give_back(s, held.tenant_id, row, forgive=True, hold=False)
            await self._end(s, held.batch_id, "abandoned", reason="stopped", token=held.token + 1)

    async def expire_own(self, held: Held) -> None:
        """A clean stop that leaves commits on the branch: end the lease now so a takeover need not wait for it."""
        async with self._sessions.begin() as s:
            await self._guard(s, held)
            await s.execute(update(_B).where(_B.c.id == held.batch_id).values(
                lease_expiry=func.now() - literal(_dt.timedelta(seconds=self.grace + 1))))

    # -- exits and recovery ----------------------------------------------------------------------------------

    async def abandon(self, tenant: str, batch_id: str, *, by: str) -> None:
        """End a batch from outside its holder. `by="recovery"`: a working batch past lease and grace, its items back
        with the attempt counted (held at the ceiling). `by="person"`: any not-ended batch, or a closed one whose
        items wait for a replacement; its items are held (O7)."""
        if by not in {"recovery", "person"}:
            raise ValueError(by)
        async with self._sessions.begin() as s:
            row = await self._batch(s, tenant, batch_id)
            if by == "person":
                if row.phase == "ended" and row.outcome == "closed":
                    await self._give_back(s, tenant, row, forgive=False, hold=True, reason="abandoned by a person")
                elif row.phase != "ended":
                    await self._give_back(s, tenant, row, forgive=False, hold=True, reason="abandoned by a person")
                    await self._end(s, row.id, "abandoned", reason="abandoned by a person", token=row.fencing_token + 1)
                return
            lapsed = row.lease_expiry is not None and (await s.execute(select(
                func.now() > row.lease_expiry + literal(_dt.timedelta(seconds=self.grace))))).scalar_one()
            if row.phase != "working" or not lapsed:
                raise NotLapsed(batch_id)
            await self._give_back(s, tenant, row, forgive=False, hold=False)
            await self._end(s, row.id, "abandoned", reason="its holder was lost", token=row.fencing_token + 1)

    async def release_held(self, tenant: str, kind: str, key: str) -> None:
        """A person's release: a held item starts afresh (attempts and deferrals both) and waits again (O7)."""
        async with self._sessions.begin() as s:
            await s.execute(update(_I).where(
                _I.c.tenant_id == TenantId(tenant), _I.c.kind == kind, _I.c.item_key == key, _I.c.status == "held")
                .values(**_to_waiting(), attempts=0, deferrals=0, updated_at=func.now()))

    async def request_cancel(self, tenant: str) -> None:
        """Offboarding: tell the tenant's working holders to stop (their next renewal is a `Stop`)."""
        async with self._sessions.begin() as s:
            await s.execute(update(_B).where(_B.c.tenant_id == TenantId(tenant), _B.c.phase == "working")
                            .values(cancel_requested=True))

    # -- reconcile (no holder) -----------------------------------------------------------------------------

    async def note_check(self, tenant: str, batch_id: str, *, reset_refusals: bool = True) -> None:
        """A reconcile looked at the batch: `last_checked` moves whatever it found. A successful forge read also
        resets the refusals count (H15)."""
        values: dict[str, Any] = {"last_checked": func.now()}
        if reset_refusals:
            values["refusals"] = 0
        async with self._sessions.begin() as s:
            await s.execute(update(_B).where(_B.c.id == BatchId(batch_id), _B.c.tenant_id == TenantId(tenant))
                            .values(**values))

    async def note_refusal(self, tenant: str, batch_id: str, reason: str) -> tuple[int, str]:
        """A non-transient forge refusal (H15): count it; at the ceiling the batch goes to a person. Returns
        `(refusals, phase)`."""
        async with self._sessions.begin() as s:
            row = await self._batch(s, tenant, batch_id)
            if row.phase == "ended":
                return row.refusals, row.phase
            count = row.refusals + 1
            values: dict[str, Any] = {"refusals": count, "last_checked": func.now()}
            if count >= self.refusal_ceiling and row.phase != "needs_person":
                values.update(self._to_person(row, f"the forge refused {count} times: {reason}"))
            await s.execute(update(_B).where(_B.c.id == row.id).values(**values))
            return count, values.get("phase", row.phase)

    async def needs_person(self, tenant: str, batch_id: str, reason: str) -> None:
        """The batch cannot go on without a person (a foreign tip, a hand-made PR, repeated refusals)."""
        async with self._sessions.begin() as s:
            row = await self._batch(s, tenant, batch_id)
            if row.phase in {"working", "in_review"}:
                await s.execute(update(_B).where(_B.c.id == row.id).values(**self._to_person(row, reason)))

    def _to_person(self, row: Any, reason: str) -> dict[str, Any]:
        return {"phase": "needs_person", "reason": reason, "lease_owner": None, "lease_expiry": None,
                "fencing_token": row.fencing_token + 1}

    async def end_review(self, tenant: str, batch_id: str, *, expect_phase: str, outcome: str,
                         published: Sequence[tuple[str, str]], held: Sequence[tuple[str, str]],
                         reason: str | None = None) -> bool:
        """End a batch in review as `merged` or `closed`, only if it is still in `expect_phase` (D7).

        Merged: `published` items are published, `held` are held, any other still in the batch return to waiting.
        Closed: `held` items are held; the rest stay in the batch, a replacement due. False: nothing changed."""
        if outcome not in {"merged", "closed"}:
            raise ValueError(outcome)
        async with self._sessions.begin() as s:
            ended = (await s.execute(update(_B).where(
                _B.c.id == BatchId(batch_id), _B.c.tenant_id == TenantId(tenant), _B.c.phase == expect_phase)
                .values(phase="ended", outcome=outcome, ended_at=func.now(), last_checked=func.now(), refusals=0,
                        lease_owner=None, lease_expiry=None, reason=func.coalesce(literal(reason, Text), _B.c.reason))
                .returning(_B.c.id))).first()
            if ended is None:
                return False
            outcomes: dict[tuple[str, str], Outcome] = {k: Outcome.published() for k in published}
            outcomes.update({k: Outcome.held(reason or "held for a person") for k in held})
            await self._apply(s, tenant, batch_id, outcomes, default=Outcome.waiting() if outcome == "merged" else None)
            return True

    # -- internals: outcomes, giving items back, ending ----------------------------------------------------

    async def _apply(self, s: AsyncSession, tenant: str, batch_id: str, outcomes: Outcomes, *,
                     default: Outcome | None) -> None:
        """Apply per-item outcomes to the items still `in_batch` in `batch_id`; unnamed items take `default`
        (`None`: they stay in the batch)."""
        mine = [_I.c.tenant_id == TenantId(tenant), _I.c.batch_id == BatchId(batch_id), _I.c.status == "in_batch"]
        named = dict(outcomes)
        for (kind, key), out in named.items():
            where = [*mine, _I.c.kind == kind, _I.c.item_key == key]
            if out.name == "waiting":
                values: dict[str, Any] = _to_waiting()
            elif out.name == "deferred":
                values = self._deferral()
            elif out.name in {"skipped", "held", "dead", "published"}:
                values = {"status": out.name, "reason": out.reason if out.reason is not None else (
                    "dead" if out.name == "dead" else None)}
            else:
                raise ValueError(out.name)
            await s.execute(update(_I).where(*where).values(**values, updated_at=func.now()))
        if default is not None:
            rest = [*mine, *[or_(_I.c.kind != k, _I.c.item_key != i) for k, i in named]]
            if default.name == "waiting":
                values = _to_waiting()
            else:
                values = {"status": default.name, "reason": default.reason}
            await s.execute(update(_I).where(*rest).values(**values, updated_at=func.now()))

    def _deferral(self) -> dict[str, Any]:
        """A deferral is no attempt (the claim's is forgiven), counted on its own; at the ceiling the item is dead."""
        over = _I.c.deferrals + 1 >= self.max_attempts
        sup = _superseded(_I)
        return {"deferrals": _I.c.deferrals + 1, "attempts": func.greatest(_I.c.attempts - 1, 0),
                "status": case((over, "dead"), (sup, "skipped"), else_="waiting"),
                "reason": case((over, f"deferred {self.max_attempts} times"), (sup, "superseded by a later run"),
                               else_=_I.c.reason)}

    async def _give_back(self, s: AsyncSession, tenant: str, row: Any, *, forgive: bool, hold: bool,
                         reason: str | None = None) -> None:
        """The batch's items leave it unfinished. A replacement's go back to the batch it replaces (still due);
        otherwise they wait (held for a person, or at the attempt ceiling)."""
        mine = [_I.c.tenant_id == TenantId(tenant), _I.c.batch_id == row.id, _I.c.status == "in_batch"]
        attempts = func.greatest(_I.c.attempts - 1, 0) if forgive else _I.c.attempts
        if hold:
            await s.execute(update(_I).where(*mine).values(status="held", reason=reason, updated_at=func.now()))
        elif row.replaces is not None and row.phase == "working":
            await s.execute(update(_I).where(*mine).values(batch_id=row.replaces, attempts=attempts,
                                                           updated_at=func.now()))
        elif forgive:
            await s.execute(update(_I).where(*mine).values(**_to_waiting(), attempts=attempts, updated_at=func.now()))
        else:
            ceiling = _I.c.attempts >= self.max_attempts
            waiting = _to_waiting()
            await s.execute(update(_I).where(*mine).values(
                status=case((ceiling, "held"), else_=waiting["status"]),
                reason=case((ceiling, f"reached the attempt ceiling ({self.max_attempts})"), else_=waiting["reason"]),
                updated_at=func.now()))

    async def _end(self, s: AsyncSession, batch_id: str, outcome: str, *, reason: str, token: int) -> None:
        await s.execute(update(_B).where(_B.c.id == BatchId(batch_id)).values(
            phase="ended", outcome=outcome, ended_at=func.now(), reason=reason, lease_owner=None, lease_expiry=None,
            fencing_token=token))

    async def purge(self, tenant: str) -> None:
        """Offboarding's last step: every row of the tenant."""
        t = TenantId(tenant)
        async with self._sessions.begin() as s:
            await s.execute(delete(_CC).where(_CC.c.tenant_id == t))
            await s.execute(delete(_C).where(_C.c.tenant_id == t))
            await s.execute(delete(_I).where(_I.c.tenant_id == t))
            await s.execute(delete(_B).where(_B.c.tenant_id == t))


def lanes_of_branch(branch: str) -> tuple[str, ...]:
    """The corpora a batch on `branch` writes (`DrainLabel.lanes`): the lead lane's for its prefix, else the author
    lane's (a revert's included: it undoes an author-lane change)."""
    from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL

    return (LEAD_AUTHOR_DRAIN_LABEL if branch.startswith(BRANCH_PREFIX[LEAD_LANE]) else AUTHOR_DRAIN_LABEL).lanes


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _violates(error: IntegrityError, index_prefix: str) -> bool:
    return index_prefix in str(error.orig)

