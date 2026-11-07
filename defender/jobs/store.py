"""The job store (#1342): alerts and investigations on PostgreSQL, behind async methods.

Each operation is one transaction on a pooled connection. Rules that races could break are the
database's: the alert row is locked for create and delete, a claim is `FOR UPDATE SKIP LOCKED` and a
compare-and-set, and every write that moves a row is conditional on the stage it expects. Audit
events are emitted after the transaction commits, never inside it. Imports the database layer,
identity's tenant and alert admission, and nothing of the runtime, so the API can load it.

Learning jobs (#1344) live beside the investigations: the transaction that ends an investigation
`completed` queues its auto job, a claim of a job is the investigations' claim on its own table
(with the age limit for a first attempt, D4), take-over covers both tables, and the investigation
delete removes its jobs."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import logging
from collections.abc import AsyncIterator, Callable, Collection, Mapping
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import case, delete, func, select, update
from sqlalchemy import text as sql
from sqlalchemy.exc import DataError, DBAPIError, IntegrityError, InterfaceError, InternalError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeout
from sqlalchemy.ext.asyncio import AsyncSession

from defender._text import postgres_can_hold
from defender.database import async_engine, sessions
from defender.records.formats import (
    ALERT_MAPPING_MISSING,
    AlertId,
    AlertMapping,
    InvestigationId,
    LearningJobId,
    TenantId,
    admit,
    check_mapping,
    derive_display,
    derive_display_of_stored,
)

from .audit import SYSTEM, announce
from .errors import Conflict, NotFound, UnknownReference, UnstorableText
from defender.tenancy.models import AlertMappingRow, TenantRecord

from .models import (
    LEARNING_TERMINAL,
    LIVE,
    TERMINAL,
    AlertRow,
    Claim,
    InvestigationRecord,
    InvestigationRow,
    LearningClaim,
    LearningJobRecord,
    LearningJobRow,
    LearningProgress,
    StoredAlert,
    investigation_record,
    learning_job_record,
    stored_alert,
)

#: The first key of the per-tenant lock that serializes storing an alert with replacing its tenant's alert mapping
#: (#1345 M3): a fixed int4 of its own, not the lifecycle's `LOCK_NAMESPACE`, which the lifecycle holds for whole steps.
MAPPING_LOCK_NAMESPACE = 1345
#: Alerts re-derived per read of a replace's recompute.
_RECOMPUTE_BATCH = 200
#: How long a claim's lease runs before it lapses unless its holder renews it (#1343 B1).
LEASE_SECONDS = 30.0
#: Attempts of one request: the third attempt that lapses is not retried (#1343 B6).
MAX_ATTEMPTS = 3
#: How old a learning job's first attempt may be when a claim reaches it (#1344 D4).
LEARNING_MAX_AGE_SECONDS = 24 * 3600.0
#: The reserved prefix of an auto job's request key, which no client request id may carry (#1344).
AUTO_REQUEST_KEY_PREFIX = "auto:"

_logger = logging.getLogger(__name__)

_UNIQUE_VIOLATION = "23505"
_FOREIGN_KEY_VIOLATION = "23503"


@dataclasses.dataclass(frozen=True)
class _TakeOver:
    """What one take-over did: the row, its tenant, why it ended, and the retry it queued, if any."""

    old_id: str
    tenant_id: str
    reason: str
    retry_id: str | None
    refused: bool = False
    of_learning: bool = False


class _Refused(Exception):
    """A write the schema refused; `sqlstate` is PostgreSQL's class of it."""

    def __init__(self, sqlstate: str | None) -> None:
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


def is_refusal(fault: BaseException) -> bool:
    """Whether a failed store call means the database will never take this value (data or
    constraint): waiting cannot cure it, and writing less can."""
    return isinstance(fault, _Refused | DataError | IntegrityError)


def is_outage(fault: BaseException) -> bool:
    """Whether a failed store call is the environment's fault (B5, r5 item 13): the database could
    not be reached, or answered with a condition of its own, such as a standby's read-only refusal
    during a failover. Waiting can cure these. Anything else (a refusal, a bug, anything unplanned)
    is not cured by waiting."""
    if isinstance(fault, DBAPIError) and fault.connection_invalidated:
        return True
    return isinstance(fault, OperationalError | InterfaceError | InternalError | PoolTimeout | OSError)


def _refuse_unstorable_text(**fields: str) -> None:
    """`UnstorableText` naming the first field PostgreSQL text cannot hold, before any query."""
    for name, text in fields.items():
        if not postgres_can_hold(text):
            raise UnstorableText(f"{name} holds a NUL or a lone surrogate, which PostgreSQL text cannot hold")


class JobStore:
    def __init__(
        self, dsn: str, *, clock: Callable[[], _dt.datetime], lease: float = LEASE_SECONDS, max_connections: int = 10,
        learning_max_age: float = LEARNING_MAX_AGE_SECONDS,
    ) -> None:
        self._engine = async_engine(dsn, max_connections=max_connections)
        self._sessions = sessions(self._engine)
        self._clock = clock
        self._lease = _dt.timedelta(seconds=lease)
        self._learning_max_age = _dt.timedelta(seconds=learning_max_age)

    @property
    def lease_seconds(self) -> float:
        """How long a claim's lease runs; a holder's own clock counts the same span."""
        return self._lease.total_seconds()

    def _lease_end(self) -> Any:
        """A fresh lease's end, by the database's clock, so workers on different machines agree (B1)."""
        return func.now() + self._lease

    async def close(self) -> None:
        await self._engine.dispose()

    @asynccontextmanager
    async def _tx(self) -> AsyncIterator[AsyncSession]:
        """One transaction; a write the schema refuses is `_Refused`."""
        try:
            async with self._sessions() as session, session.begin():
                yield session
        except IntegrityError as e:
            raise _Refused(getattr(e.orig, "sqlstate", None)) from e

    # --- alerts -------------------------------------------------------------------------

    @staticmethod
    async def _lock_mappings_of(s: AsyncSession, tenant_id: TenantId) -> None:
        """Hold the tenant's mapping lock until this transaction ends (#1345 M3): taken by the alert insert and by the
        replace before either reads or writes the mapping or touches an alert row, so an alert never keeps a
        value derived from a mapping the replace has superseded. Another tenant is never held up."""
        await s.execute(sql("SELECT pg_advisory_xact_lock(:ns, hashtext(CAST(:tenant AS text)))"),
                        {"ns": MAPPING_LOCK_NAMESPACE, "tenant": str(tenant_id)})

    async def insert_alert(  # noqa: PLR0913 — the ratified signature
        self, tenant_id: TenantId, *, vendor: str, vendor_ticket_id: str, fired_at: _dt.datetime,
        changed_at: _dt.datetime, received_at: _dt.datetime, raw: bytes,
    ) -> StoredAlert:
        """Store an alert's exact bytes, with the title and description its tenant's mapping derives from them
        (null while the tenant has no mapping). `AlertRefused` for anything alert admission refuses; `Conflict`
        for a second alert with this vendor's ticket id; `UnknownReference` for a tenant with no row;
        `UnstorableText` for a text field PostgreSQL cannot hold."""
        _refuse_unstorable_text(vendor=vendor, vendor_ticket_id=vendor_ticket_id)
        admitted = admit(raw)
        row = AlertRow(
            id=AlertId.mint(), tenant_id=tenant_id, vendor=vendor, vendor_ticket_id=vendor_ticket_id,
            fired_at=fired_at, changed_at=changed_at, received_at=received_at, title=None,
            description=None, raw=raw)
        try:
            async with self._tx() as s:
                await self._lock_mappings_of(s, tenant_id)
                mapping = await self._mapping_in(s, tenant_id)
                if mapping is not None:
                    row.title, row.description = derive_display(admitted.document, mapping)
                s.add(row)
        except _Refused as refused:
            if refused.sqlstate == _FOREIGN_KEY_VIOLATION:
                raise UnknownReference(f"no tenant {tenant_id!r}") from None
            if refused.sqlstate == _UNIQUE_VIOLATION:
                raise Conflict(f"alert {vendor_ticket_id!r} from {vendor!r} is already stored") from None
            raise
        return stored_alert(row)

    async def get_alert(self, tenant_id: TenantId, alert_id: AlertId) -> StoredAlert | None:
        async with self._tx() as s:
            row = (await s.execute(select(AlertRow).where(
                AlertRow.tenant_id == tenant_id, AlertRow.id == alert_id))).scalars().first()
        return None if row is None else stored_alert(row)

    # --- the alert mapping (#1345) ------------------------------------------------------

    @staticmethod
    async def _mapping_in(s: AsyncSession, tenant_id: TenantId) -> AlertMapping | None:
        row = (await s.execute(select(AlertMappingRow).where(AlertMappingRow.tenant_id == tenant_id))).scalars().first()
        return None if row is None else row.as_mapping()

    async def get_alert_mapping(self, tenant_id: TenantId) -> AlertMapping | None:
        """The tenant's alert mapping, `None` until one is saved."""
        async with self._tx() as s:
            return await self._mapping_in(s, tenant_id)

    async def put_alert_mapping(self, tenant_id: TenantId, mapping: AlertMapping, *, actor: str) -> bool:
        """Replace the tenant's alert mapping whole and re-derive the title and description of every alert of the
        tenant in the same transaction (M1, M3): the one writer. `created` when this is the tenant's first save.
        `AlertMappingFault` naming the entry for an invalid mapping (a re-check for callers that are not the API),
        `UnknownReference` for a tenant with no row. A database error fails the whole replace."""
        check_mapping(dict(mapping.paths))
        try:
            async with self._tx() as s:
                await self._lock_mappings_of(s, tenant_id)
                created = await s.get(AlertMappingRow, tenant_id) is None
                await s.merge(AlertMappingRow.of(tenant_id, mapping))
                await s.flush()
                await self._re_derive(s, tenant_id, mapping)
        except _Refused as refused:
            if refused.sqlstate == _FOREIGN_KEY_VIOLATION:
                raise UnknownReference(f"no tenant {tenant_id!r}") from None
            raise
        announce("alert_mapping.update", actor=actor, tenant_id=tenant_id, target=tenant_id)
        return created

    @staticmethod
    async def _re_derive(s: AsyncSession, tenant_id: TenantId, mapping: AlertMapping) -> None:
        """Every alert of the tenant, from its stored bytes through `mapping` (by JSON parse only, so one alert's
        content never fails the replace), a batch at a time; a row already right is not written."""
        after = None
        while True:
            query = select(AlertRow.id, AlertRow.title, AlertRow.description, AlertRow.raw).where(
                AlertRow.tenant_id == tenant_id).order_by(AlertRow.id).limit(_RECOMPUTE_BATCH)
            if after is not None:
                query = query.where(AlertRow.id > after)
            batch = (await s.execute(query)).all()
            for alert_id, title, description, raw in batch:
                derived = derive_display_of_stored(bytes(raw), mapping)
                if derived != (title, description):
                    await s.execute(update(AlertRow).where(AlertRow.id == alert_id).values(
                        title=derived[0], description=derived[1]).execution_options(synchronize_session=False))
            if len(batch) < _RECOMPUTE_BATCH:
                return
            after = batch[-1][0]

    # --- reads --------------------------------------------------------------------------

    async def get_investigation(self, tenant_id: TenantId, investigation_id: InvestigationId) -> InvestigationRecord | None:
        async with self._tx() as s:
            row = await self._row(s, tenant_id, investigation_id)
        return None if row is None else investigation_record(row)

    @staticmethod
    async def _row(s: AsyncSession, tenant_id: TenantId, investigation_id: InvestigationId) -> InvestigationRow | None:
        return (await s.execute(select(InvestigationRow).where(
            InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == investigation_id))
        ).scalars().first()

    # --- create -------------------------------------------------------------------------

    async def create_investigation(
        self, tenant_id: TenantId, alert_id: AlertId, request_key: str, *, actor: str,
    ) -> tuple[InvestigationRecord, bool]:
        """Start an investigation of the alert, or answer the one this request already has (#1081
        §4.1): the latest attempt under the key; else the alert's live investigation, without
        recording this key; else a new attempt 1. `created` only when this call inserted the row.
        `UnknownReference` for an alert this tenant lacks; `Conflict` naming the missing mapping when a new attempt is
        due and the tenant has saved no alert mapping (#1345 O4)."""
        _refuse_unstorable_text(request_key=request_key)
        async with self._tx() as s:
            locked = (await s.execute(select(AlertRow.id).where(
                AlertRow.tenant_id == tenant_id, AlertRow.id == alert_id).with_for_update())).first()
            if locked is None:
                raise UnknownReference(f"no alert {alert_id!r}")
            replay = (await s.execute(select(InvestigationRow).where(
                InvestigationRow.tenant_id == tenant_id, InvestigationRow.alert_id == alert_id,
                InvestigationRow.request_key == request_key)
                .order_by(InvestigationRow.attempt.desc()).limit(1))).scalars().first()
            if replay is not None:
                return investigation_record(replay), False
            live = (await s.execute(select(InvestigationRow).where(
                InvestigationRow.tenant_id == tenant_id, InvestigationRow.alert_id == alert_id,
                InvestigationRow.stage.in_(LIVE)))).scalars().first()
            if live is not None:
                return investigation_record(live), False
            if await self._mapping_in(s, tenant_id) is None:  # never deleted, so no lock (#1345 O4)
                raise Conflict(ALERT_MAPPING_MISSING)
            row = InvestigationRow(
                id=InvestigationId.mint(), tenant_id=tenant_id, alert_id=alert_id, request_key=request_key,
                attempt=1, stage="queued", created_at=self._clock(), cost_usd=0.0)
            s.add(row)
            record = investigation_record(row)
        announce("investigation.start", actor=actor, tenant_id=tenant_id, target=record.investigation_id)
        return record, True

    # --- claim --------------------------------------------------------------------------

    async def claim(self) -> Claim | None:
        """Move the oldest queued investigation (by `created_at`, ties by id) to `running`, with its
        tenant's state read in the same transaction (#1342 r7 R7-1), or `None`. A row another
        transaction holds is skipped, never waited for. The state read takes no lock: a teardown
        that commits just after it still races the job, and the job's own tenant admission is what
        refuses it then."""
        async with self._tx() as s:
            oldest = (select(InvestigationRow.id).where(InvestigationRow.stage == "queued")
                      .order_by(InvestigationRow.created_at, InvestigationRow.id).limit(1)
                      .with_for_update(skip_locked=True))
            picked = (await s.execute(oldest)).scalars().first()
            if picked is None:
                return None
            row = (await s.execute(
                update(InvestigationRow).where(InvestigationRow.id == picked, InvestigationRow.stage == "queued")
                .values(stage="running", started_at=self._clock(), lease_expires_at=self._lease_end())
                .returning(InvestigationRow)
                .execution_options(synchronize_session=False))).scalars().first()
            if row is None:  # not reachable while this transaction holds the row; the compare-and-set is the contract
                return None
            record = investigation_record(row)
            # The investigation's tenant is a `tenancy.tenants` row (its foreign key), never deleted.
            state = (await s.execute(select(TenantRecord.state).where(TenantRecord.id == record.tenant_id))).scalar_one()
        announce("investigation.claim", actor=SYSTEM, tenant_id=record.tenant_id, target=record.investigation_id)
        return Claim(record=record, tenant_state=state)

    # --- cancel -------------------------------------------------------------------------

    async def cancel_investigation(
        self, tenant_id: TenantId, investigation_id: InvestigationId, *, actor: str,
    ) -> InvestigationRecord:
        """Abort a queued or running investigation (`aborted`, reason `cancelled`); a running one's
        worker ends its child at its next renewal (B3, B9). `NotFound`; `Conflict` for an ended one,
        naming the live retry when the ended attempt has one."""
        async with self._tx() as s:
            row = (await s.execute(
                update(InvestigationRow).where(
                    InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == investigation_id,
                    InvestigationRow.stage.in_(LIVE))
                .values(stage="aborted", failure_reason="cancelled", finished_at=self._clock())
                .returning(InvestigationRow).execution_options(synchronize_session=False))).scalars().first()
            if row is None:
                current = await self._row(s, tenant_id, investigation_id)
                if current is None:
                    raise NotFound(f"no investigation {investigation_id!r}")
                retry = (await s.execute(select(InvestigationRow.id).where(
                    InvestigationRow.tenant_id == tenant_id, InvestigationRow.alert_id == current.alert_id,
                    InvestigationRow.request_key == current.request_key,
                    InvestigationRow.attempt > current.attempt, InvestigationRow.stage.in_(LIVE))
                    .order_by(InvestigationRow.attempt).limit(1))).scalars().first()
                if retry is not None:
                    raise Conflict(f"the investigation already ended and was retried as {retry}; cancel that one")
                raise Conflict("the investigation already ended")
            record = investigation_record(row)
        announce("investigation.cancel", actor=actor, tenant_id=tenant_id, target=investigation_id)
        return record

    # --- delete -------------------------------------------------------------------------

    async def delete_investigation(self, tenant_id: TenantId, investigation_id: InvestigationId, *, actor: str) -> None:
        """Remove every attempt under the named investigation's request key, with their learning
        jobs, queued or ended (#1344 O10, D6). `NotFound`; `Conflict` while any attempt is queued or
        running, or any of their jobs is running. Takes the alert lock, so it serializes with create,
        and locks the jobs' rows before judging them, so it serializes with their claim."""
        async with self._tx() as s:
            named = await self._row(s, tenant_id, investigation_id)
            if named is None:
                raise NotFound(f"no investigation {investigation_id!r}")
            await s.execute(select(AlertRow.id).where(
                AlertRow.tenant_id == tenant_id, AlertRow.id == named.alert_id).with_for_update())
            attempts = (await s.execute(select(InvestigationRow).where(
                InvestigationRow.tenant_id == tenant_id, InvestigationRow.alert_id == named.alert_id,
                InvestigationRow.request_key == named.request_key))).scalars().all()
            if not any(a.id == investigation_id for a in attempts):  # deleted while this waited for the lock
                raise NotFound(f"no investigation {investigation_id!r}")
            if any(a.stage in LIVE for a in attempts):
                raise Conflict("cannot delete an investigation that is queued or running")
            # Its jobs' rows are locked before they are judged (#1344 O10), waiting for any claim
            # that holds one, so a job claimed meanwhile is seen running and refuses the delete.
            inv_ids = [a.id for a in attempts]
            jobs = (await s.execute(select(LearningJobRow.id, LearningJobRow.status).where(
                LearningJobRow.investigation_id.in_(inv_ids)).with_for_update())).all()
            if any(status == "running" for _, status in jobs):
                raise Conflict("cannot delete an investigation while one of its learning jobs is running")
            if jobs:
                await s.execute(delete(LearningJobRow).where(LearningJobRow.investigation_id.in_(inv_ids)))
            await s.execute(delete(InvestigationRow).where(
                InvestigationRow.tenant_id == tenant_id, InvestigationRow.alert_id == named.alert_id,
                InvestigationRow.request_key == named.request_key))
        announce("investigation.delete", actor=actor, tenant_id=tenant_id, target=investigation_id)

    # --- the worker's write -------------------------------------------------------------

    async def finish(
        self, tenant_id: TenantId, investigation_id: InvestigationId, *, stage: str, disposition: str | None = None,
        cost_usd: float | None = None, knowledge: dict[str, Any] | None = None,
        failure_reason: str | None = None, failure_message: str | None = None,
    ) -> InvestigationRecord | None:
        """Record the one terminal stage of a running investigation, with its final cost (null when
        unknown) and knowledge, and the accounting mark. Conditional on the row still being `running`
        (the fence; a row is claimed at most once, so no claim identity is needed): `None` when it
        changed nothing (the row moved, was deleted, or never ran), and the caller then writes its
        final accounting instead (`write_accounting`). A `completed` end queues the investigation's
        auto learning job in the same transaction (#1344 O1); a job the schema refuses takes the
        end back with it, raised as a refusal (D10)."""
        if stage not in TERMINAL:
            raise ValueError(f"{stage!r} is not a terminal stage")
        async with self._tx() as s:
            row = (await s.execute(
                update(InvestigationRow).where(
                    InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == investigation_id,
                    InvestigationRow.stage == "running")
                .values(stage=stage, finished_at=self._clock(), disposition=disposition, cost_usd=cost_usd,
                        knowledge=knowledge, failure_reason=failure_reason, failure_message=failure_message,
                        accounting_written_at=self._clock())
                .returning(InvestigationRow).execution_options(synchronize_session=False))).scalars().first()
            if row is None:
                return None
            record = investigation_record(row)
            if stage == "completed":
                # Not announced: the investigation's finish is its audit event (#1342's audit stream).
                s.add(LearningJobRow(
                    id=LearningJobId.mint(), tenant_id=record.tenant_id, alert_id=record.alert_id,
                    investigation_id=record.investigation_id,
                    request_key=f"{AUTO_REQUEST_KEY_PREFIX}{record.investigation_id}", attempt=1, trigger="auto",
                    status="queued", created_at=self._clock()))
        detail = f"stage={stage}" + (f" reason={failure_reason}" if failure_reason else "")
        announce("investigation.finish", actor=SYSTEM, tenant_id=tenant_id, target=investigation_id, detail=detail)
        return record

    # --- the holder's lease and end writes (#1343) ---------------------------------------------

    async def renew(
        self, held: Collection[str], *, costs: Mapping[str, float] | None = None,
        progress: Mapping[str, LearningProgress] | None = None,
    ) -> list[str]:
        """Extend the lease of every held row, investigation or learning job, that is still
        `running` and not yet handed back, in one transaction, and return the ids it covered. A
        held row missing from the answer was cancelled, taken over or deleted (B3). `costs` copies
        a cost-so-far figure onto the investigations it names (B2), `progress` the job entry's
        progress onto the learning jobs it names (#1344 O13); a covered row without one keeps its
        values. Late renewals of a lapsed row nobody took over succeed (B1)."""
        ids = set(held)
        if not ids:
            return []
        figures = {i: c for i, c in (costs or {}).items() if i in ids}
        cost = (case(*((InvestigationRow.id == i, c) for i, c in figures.items()), else_=InvestigationRow.cost_usd)
                if figures else InvestigationRow.cost_usd)
        async with self._tx() as s:
            covered = (await s.execute(
                update(InvestigationRow).where(
                    InvestigationRow.id.in_(ids), InvestigationRow.stage == "running",
                    InvestigationRow.accounting_written_at.is_(None))
                .values(lease_expires_at=self._lease_end(), cost_usd=cost)
                .returning(InvestigationRow.id).execution_options(synchronize_session=False))).scalars().all()
            found = [str(i) for i in covered]
            rest = ids - set(found)
            if rest:
                found += [str(i) for i in (await s.execute(
                    update(LearningJobRow).where(
                        LearningJobRow.id.in_(rest), LearningJobRow.status == "running",
                        LearningJobRow.finished_at.is_(None))
                    .values(lease_expires_at=self._lease_end(),
                            **_progress_values({i: p for i, p in (progress or {}).items() if i in rest}))
                    .returning(LearningJobRow.id).execution_options(synchronize_session=False))).scalars().all()]
        return found

    async def write_accounting(
        self, tenant_id: str, investigation_id: str, *, cost_usd: float | None, knowledge: dict[str, Any] | None,
    ) -> InvestigationRecord | None:
        """The holder's final cost and knowledge on a row someone else already ended (cancel,
        take-over): written once, changing no stage or failure detail (B-P2, B4). `None` when the
        row is not an ended one of this tenant, or its mark is already set."""
        async with self._tx() as s:
            row = (await s.execute(
                update(InvestigationRow).where(
                    InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == investigation_id,
                    InvestigationRow.stage.in_(TERMINAL), InvestigationRow.accounting_written_at.is_(None))
                .values(cost_usd=cost_usd, knowledge=knowledge, accounting_written_at=self._clock())
                .returning(InvestigationRow).execution_options(synchronize_session=False))).scalars().first()
            return None if row is None else investigation_record(row)

    async def hand_back(
        self, tenant_id: str, investigation_id: str, *, cost_usd: float | None, knowledge: dict[str, Any] | None,
    ) -> InvestigationRecord | None:
        """A stopping worker gives a running row back: its lease lapses at once, so any worker takes
        it over within seconds, and its final cost and knowledge and the mark are written (B11).
        `None` when the row is not a running, unmarked one of this tenant."""
        async with self._tx() as s:
            row = (await s.execute(
                update(InvestigationRow).where(
                    InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == investigation_id,
                    InvestigationRow.stage == "running", InvestigationRow.accounting_written_at.is_(None))
                .values(lease_expires_at=func.now() - _dt.timedelta(seconds=1), cost_usd=cost_usd,
                        knowledge=knowledge, accounting_written_at=self._clock())
                .returning(InvestigationRow).execution_options(synchronize_session=False))).scalars().first()
            return None if row is None else investigation_record(row)

    async def take_over(self, *, held: Collection[str] = frozenset()) -> list[str]:
        """One pass of take-over (B6, B7), over investigations and learning jobs alike (#1344 O6):
        every `running` row whose lease has lapsed and that the caller does not hold (B-P3) is
        failed (`lease_lapsed`) and, below the third attempt, retried (a new `queued` row, attempt
        + 1; a learning job's retry keeps its original's `created_at`); the third attempt ends
        `retry_cap`. One transaction per row, `SKIP LOCKED`; no accounting and no host read.
        Returns the ids taken over. A row whose take-over the schema refuses rolls back whole and
        is left for the next pass."""
        taken: list[str] = []
        for take_one in (self._take_over_one, self._take_over_learning_one):
            passed_over: set[str] = set(held)
            while (outcome := await take_one(passed_over)) is not None:
                passed_over.add(outcome.old_id)
                if outcome.refused:
                    _logger.warning("the take-over of %s was refused by the schema; it is left for the next pass",
                                    outcome.old_id)
                    continue
                taken.append(outcome.old_id)
                kind = "learning_job" if outcome.of_learning else "investigation"
                announce(f"{kind}.takeover", actor=SYSTEM, tenant_id=outcome.tenant_id,  # type: ignore[arg-type]
                         target=outcome.old_id, detail=f"reason={outcome.reason}")
                if outcome.retry_id is not None:
                    announce(f"{kind}.retry", actor=SYSTEM, tenant_id=outcome.tenant_id,  # type: ignore[arg-type]
                             target=outcome.retry_id)
        return taken

    async def _take_over_one(self, passed_over: Collection[str]) -> _TakeOver | None:
        """Take over the oldest lapsed row not passed over, in its own transaction; `None` when
        there is none (a row another transaction holds counts as none)."""
        old_id = tenant = ""
        try:
            async with self._tx() as s:
                lapsed = (await s.execute(
                    select(InvestigationRow).where(
                        InvestigationRow.stage == "running", InvestigationRow.lease_expires_at < func.now(),
                        InvestigationRow.id.notin_(passed_over))
                    .order_by(InvestigationRow.lease_expires_at, InvestigationRow.id).limit(1)
                    .with_for_update(skip_locked=True))).scalars().first()
                if lapsed is None:
                    return None
                old_id, tenant = lapsed.id, lapsed.tenant_id
                capped = lapsed.attempt >= MAX_ATTEMPTS
                reason = "retry_cap" if capped else "lease_lapsed"
                lapsed.stage, lapsed.failure_reason = "failed", reason
                # A handed-back row already carries its holder's final accounting (B11); a lost
                # worker's row never does, so the message tells the two apart.
                why = ("its worker stopped and handed it back" if lapsed.accounting_written_at is not None
                       else "its worker stopped renewing its lease")
                lapsed.failure_message = why + ("; the request used all its attempts" if capped else "; it is retried")
                lapsed.finished_at = self._clock()
                retry_id = None
                if not capped:
                    retry_id = InvestigationId.mint()
                    await s.flush()  # the old row leaves `running` before the retry takes its place in the index
                    s.add(InvestigationRow(
                        id=retry_id, tenant_id=lapsed.tenant_id, alert_id=lapsed.alert_id,
                        request_key=lapsed.request_key, attempt=lapsed.attempt + 1, stage="queued",
                        created_at=self._clock(), cost_usd=0.0))
        except _Refused:
            return _TakeOver(old_id, tenant, "", None, refused=True)
        return _TakeOver(old_id, tenant, reason, retry_id)

    async def _take_over_learning_one(self, passed_over: Collection[str]) -> _TakeOver | None:
        """`_take_over_one` for a learning job: the retry is a new row of the same request,
        attempt + 1, keeping its original's age (O6, D4)."""
        old_id = tenant = ""
        try:
            async with self._tx() as s:
                lapsed = (await s.execute(
                    select(LearningJobRow).where(
                        LearningJobRow.status == "running", LearningJobRow.lease_expires_at < func.now(),
                        LearningJobRow.id.notin_(passed_over))
                    .order_by(LearningJobRow.lease_expires_at, LearningJobRow.id).limit(1)
                    .with_for_update(skip_locked=True))).scalars().first()
                if lapsed is None:
                    return None
                old_id, tenant = lapsed.id, lapsed.tenant_id
                capped = lapsed.attempt >= MAX_ATTEMPTS
                reason = "retry_cap" if capped else "lease_lapsed"
                why = ("its worker stopped and handed it back" if lapsed.finished_at is not None
                       else "its worker stopped renewing its lease")
                lapsed.status, lapsed.reason = "failed", reason
                lapsed.message = why + ("; the request used all its attempts" if capped else "; it is retried")
                lapsed.finished_at = self._clock()
                lapsed.lease_expires_at = None
                retry_id = None
                if not capped:
                    retry_id = LearningJobId.mint()
                    s.add(LearningJobRow(
                        id=retry_id, tenant_id=lapsed.tenant_id, alert_id=lapsed.alert_id,
                        investigation_id=lapsed.investigation_id, request_key=lapsed.request_key,
                        attempt=lapsed.attempt + 1, trigger=lapsed.trigger, status="queued",
                        created_at=lapsed.created_at))
        except _Refused:
            return _TakeOver(old_id, tenant, "", None, refused=True, of_learning=True)
        return _TakeOver(old_id, tenant, reason, retry_id, of_learning=True)

    # --- learning jobs (#1344) ------------------------------------------------------------------

    async def create_learning_job(
        self, tenant_id: TenantId, investigation_id: InvestigationId, client_request_id: str, *, actor: str,
    ) -> tuple[LearningJobRecord, bool]:
        """Queue an explicit re-learn of a `completed` investigation, or answer the job this
        request already has: the latest attempt under `(investigation, client request id)` (O11).
        `created` only when this call inserted the row. `UnknownReference` for an investigation
        this tenant lacks; `Conflict` for one that did not end `completed`, and for a request id
        carrying the auto jobs' reserved prefix."""
        _refuse_unstorable_text(client_request_id=client_request_id)
        if client_request_id.startswith(AUTO_REQUEST_KEY_PREFIX):
            raise Conflict(f"a client request id may not start with {AUTO_REQUEST_KEY_PREFIX!r}, the auto jobs' prefix")
        async with self._tx() as s:
            named = await self._row(s, tenant_id, investigation_id)
            if named is None:
                raise UnknownReference(f"no investigation {investigation_id!r}")
            # The alert lock serializes this with the investigation delete, which takes it first.
            await s.execute(select(AlertRow.id).where(
                AlertRow.tenant_id == tenant_id, AlertRow.id == named.alert_id).with_for_update())
            named = await self._row(s, tenant_id, investigation_id)
            if named is None:  # deleted while this waited for the lock
                raise UnknownReference(f"no investigation {investigation_id!r}")
            replay = (await s.execute(select(LearningJobRow).where(
                LearningJobRow.tenant_id == tenant_id, LearningJobRow.investigation_id == investigation_id,
                LearningJobRow.trigger == "explicit", LearningJobRow.request_key == client_request_id)
                .order_by(LearningJobRow.attempt.desc()).limit(1))).scalars().first()
            if replay is not None:
                return learning_job_record(replay), False
            if named.stage != "completed":
                raise Conflict(f"only a completed investigation can be learned from; this one is {named.stage}")
            row = LearningJobRow(
                id=LearningJobId.mint(), tenant_id=tenant_id, alert_id=named.alert_id, investigation_id=named.id,
                request_key=client_request_id, attempt=1, trigger="explicit", status="queued",
                created_at=self._clock())
            s.add(row)
            record = learning_job_record(row)
        announce("learning_job.start", actor=actor, tenant_id=tenant_id, target=record.learning_job_id,
                 detail="trigger=explicit")
        return record, True

    async def claim_learning_job(self) -> LearningClaim | None:
        """Move the oldest queued learning job (by `created_at`, ties by id) to `running`, with
        its tenant's state read in the same transaction, or `None`. A first attempt older than the
        age limit when the claim reaches it is ended `skipped`/`expired` and the next one is picked
        (D4); a retry is exempt. A row another transaction holds is skipped, never waited for."""
        while True:
            expired: LearningJobRecord | None = None
            async with self._tx() as s:
                row = (await s.execute(
                    select(LearningJobRow).where(LearningJobRow.status == "queued")
                    .order_by(LearningJobRow.created_at, LearningJobRow.id).limit(1)
                    .with_for_update(skip_locked=True))).scalars().first()
                if row is None:
                    return None
                now = self._clock()
                if row.attempt == 1 and now - row.created_at > self._learning_max_age:
                    row.status, row.reason, row.finished_at = "skipped", "expired", now
                    row.message = (f"it waited in the queue longer than the age limit "
                                   f"({self._learning_max_age.total_seconds():g} s) before a learning slot reached it")
                    await s.flush()
                    expired = learning_job_record(row)
                else:
                    claimed = (await s.execute(
                        update(LearningJobRow).where(LearningJobRow.id == row.id, LearningJobRow.status == "queued")
                        .values(status="running", started_at=now, lease_expires_at=self._lease_end())
                        .returning(LearningJobRow).execution_options(synchronize_session=False))).scalars().first()
                    if claimed is None:  # not reachable while this transaction holds the row
                        return None
                    record = learning_job_record(claimed)
                    state = (await s.execute(
                        select(TenantRecord.state).where(TenantRecord.id == record.tenant_id))).scalar_one()
            if expired is not None:
                announce("learning_job.finish", actor=SYSTEM, tenant_id=expired.tenant_id,
                         target=expired.learning_job_id, detail="status=skipped reason=expired")
                continue
            announce("learning_job.claim", actor=SYSTEM, tenant_id=record.tenant_id, target=record.learning_job_id)
            return LearningClaim(record=record, tenant_state=state)

    async def finish_learning_job(  # noqa: PLR0913 — the end record's values
        self, tenant_id: str, learning_job_id: str, *, status: str, reason: str | None, message: str | None,
        progress: LearningProgress | None, findings_count: int = 0,
    ) -> LearningJobRecord | None:
        """Record the one terminal status of a running, not handed-back learning job (the fence,
        O2): `completed` sets its findings `pending`. `progress` is the end record's final pick,
        stage and sibling cost; `None` keeps what the running row was last given. `None` when it
        changed nothing (the row moved, was deleted or handed back)."""
        if status not in LEARNING_TERMINAL:
            raise ValueError(f"{status!r} is not a terminal status")
        values: dict[str, Any] = {
            "status": status, "reason": reason, "message": message, "finished_at": self._clock(),
            "lease_expires_at": None, "findings_count": findings_count,
            "publish_state": "pending" if status == "completed" else "none"}
        if progress is not None:
            values.update(fork_message_id=progress.fork_message_id, stage=progress.stage,
                          sibling_cost_usd=progress.sibling_cost_usd)
        async with self._tx() as s:
            row = (await s.execute(
                update(LearningJobRow).where(
                    LearningJobRow.tenant_id == tenant_id, LearningJobRow.id == learning_job_id,
                    LearningJobRow.status == "running", LearningJobRow.finished_at.is_(None))
                .values(**values).returning(LearningJobRow).execution_options(synchronize_session=False))
            ).scalars().first()
            if row is None:
                return None
            record = learning_job_record(row)
        announce("learning_job.finish", actor=SYSTEM, tenant_id=tenant_id, target=learning_job_id,
                 detail=f"status={status}" + (f" reason={reason}" if reason else ""))
        return record

    async def hand_back_learning_job(
        self, tenant_id: str, learning_job_id: str, *, progress: LearningProgress | None = None,
    ) -> LearningJobRecord | None:
        """A stopped family's row given back (O6): its lease lapses at once, so the next take-over
        retries it, and it is marked so no renewal covers it again. `None` when the row is not a
        running, not handed-back one of this tenant."""
        values: dict[str, Any] = {"lease_expires_at": func.now() - _dt.timedelta(seconds=1),
                                  "finished_at": self._clock()}
        if progress is not None:
            values.update(fork_message_id=progress.fork_message_id, stage=progress.stage,
                          sibling_cost_usd=progress.sibling_cost_usd)
        async with self._tx() as s:
            row = (await s.execute(
                update(LearningJobRow).where(
                    LearningJobRow.tenant_id == tenant_id, LearningJobRow.id == learning_job_id,
                    LearningJobRow.status == "running", LearningJobRow.finished_at.is_(None))
                .values(**values).returning(LearningJobRow).execution_options(synchronize_session=False))
            ).scalars().first()
            return None if row is None else learning_job_record(row)

    async def pending_publish(self, tenant_id: str) -> list[str]:
        """The tenant's `completed` jobs whose findings wait to be published (O14), oldest end first."""
        async with self._tx() as s:
            found = (await s.execute(select(LearningJobRow.id).where(
                LearningJobRow.tenant_id == tenant_id, LearningJobRow.status == "completed",
                LearningJobRow.publish_state == "pending")
                .order_by(LearningJobRow.finished_at, LearningJobRow.id))).scalars().all()
        return [str(i) for i in found]

    async def record_publish(
        self, tenant_id: str, *, published: Collection[str], refused: Collection[str],
    ) -> tuple[int, int]:
        """A post-step's answer (O8, O14): the named `pending` jobs of this tenant become `done` or
        `refused`; any other row is left as it is. Returns how many rows each became."""
        counts = []
        async with self._tx() as s:
            for ids, state in ((set(published), "done"), (set(refused) - set(published), "refused")):
                if not ids:
                    counts.append(0)
                    continue
                moved = (await s.execute(
                    update(LearningJobRow).where(
                        LearningJobRow.tenant_id == tenant_id, LearningJobRow.id.in_(ids),
                        LearningJobRow.status == "completed", LearningJobRow.publish_state == "pending")
                    .values(publish_state=state).returning(LearningJobRow.id)
                    .execution_options(synchronize_session=False))).scalars().all()
                counts.append(len(moved))
        return counts[0], counts[1]


def _progress_values(progress: Mapping[str, LearningProgress]) -> dict[str, Any]:
    """The `renew` values that copy each named job's progress onto its row; none, none copied."""
    if not progress:
        return {}

    def per_row(field: str) -> Any:
        column = getattr(LearningJobRow, field)
        return case(*((LearningJobRow.id == i, getattr(p, field)) for i, p in progress.items()), else_=column)

    return {field: per_row(field) for field in ("fork_message_id", "stage", "sibling_cost_usd")}
