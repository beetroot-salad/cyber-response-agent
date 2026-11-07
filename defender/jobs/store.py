"""The job store (#1342): alerts and investigations on PostgreSQL, behind async methods.

Each operation is one transaction on a pooled connection. Rules that races could break are the
database's: the alert row is locked for create and delete, a claim is `FOR UPDATE SKIP LOCKED` and a
compare-and-set, and every write that moves a row is conditional on the stage it expects. Audit
events are emitted after the transaction commits, never inside it. Imports the database layer,
identity's tenant and alert admission, and nothing of the runtime, so the API can load it."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import logging
from collections.abc import AsyncIterator, Callable, Collection, Mapping
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import case, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DataError, DBAPIError, IntegrityError, InterfaceError, InternalError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeout
from sqlalchemy.ext.asyncio import AsyncSession

from defender._text import postgres_can_hold
from defender.database import async_engine, sessions
from defender.records.formats import (
    ALERT_MAPPING_MISSING,
    MAPPING_KEYS,
    AlertId,
    AlertMapping,
    InvestigationId,
    TenantId,
    admit,
    check_mapping,
    derive_display,
)

from .audit import SYSTEM, announce
from .errors import Conflict, NotFound, UnknownReference, UnstorableText
from defender.tenancy.models import AlertMappingRow, TenantRecord

from .models import (
    LIVE,
    TERMINAL,
    AlertRow,
    Claim,
    InvestigationRecord,
    InvestigationRow,
    StoredAlert,
    investigation_record,
    stored_alert,
)

#: How long a claim's lease runs before it lapses unless its holder renews it (#1343 B1).
LEASE_SECONDS = 30.0
#: Attempts of one request: the third attempt that lapses is not retried (#1343 B6).
MAX_ATTEMPTS = 3

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
    ) -> None:
        self._engine = async_engine(dsn, max_connections=max_connections)
        self._sessions = sessions(self._engine)
        self._clock = clock
        self._lease = _dt.timedelta(seconds=lease)

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

    async def insert_alert(  # noqa: PLR0913 — the ratified signature
        self, tenant_id: TenantId, *, vendor: str, vendor_ticket_id: str, fired_at: _dt.datetime,
        changed_at: _dt.datetime, received_at: _dt.datetime, raw: bytes,
    ) -> StoredAlert:
        """Store an alert's exact bytes, with the title and description its tenant's mapping derives from them when it
        is stored (null while the tenant has no mapping); nothing rewrites them later (#1420). Takes no per-tenant
        lock, so inserts never wait on each other or on a mapping save, and one that overlaps a save may derive from
        either mapping. `AlertRefused` for anything alert admission refuses; `Conflict`
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
        """Replace the tenant's alert mapping whole: the one writer (M1). It applies to alerts stored from now on;
        alerts already stored keep their title and description (#1420). `created` when this is the tenant's first save.
        `AlertMappingFault` naming the entry for an invalid mapping (a re-check for callers that are not the API),
        `UnknownReference` for a tenant with no row. A database error fails the whole replace. No lock: the insert of the
        row decides `created`, so of two first saves racing, exactly one creates and the other updates (#1420)."""
        check_mapping(dict(mapping.paths))
        paths = {key: mapping.path_of(key) for key in MAPPING_KEYS}
        try:
            async with self._tx() as s:
                created = (await s.execute(
                    pg_insert(AlertMappingRow).values(tenant_id=tenant_id, **paths)
                    .on_conflict_do_nothing(index_elements=[AlertMappingRow.tenant_id])
                    .returning(AlertMappingRow.tenant_id))).first() is not None
                if not created:
                    await s.execute(update(AlertMappingRow).where(AlertMappingRow.tenant_id == tenant_id).values(**paths))
        except _Refused as refused:
            if refused.sqlstate == _FOREIGN_KEY_VIOLATION:
                raise UnknownReference(f"no tenant {tenant_id!r}") from None
            raise
        announce("alert_mapping.update", actor=actor, tenant_id=tenant_id, target=tenant_id)
        return created

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
        """Remove every attempt under the named investigation's request key. `NotFound`; `Conflict`
        while any of them is queued or running. Takes the alert lock, so it serializes with create."""
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
        final accounting instead (`write_accounting`)."""
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
        detail = f"stage={stage}" + (f" reason={failure_reason}" if failure_reason else "")
        announce("investigation.finish", actor=SYSTEM, tenant_id=tenant_id, target=investigation_id, detail=detail)
        return record

    # --- the holder's lease and end writes (#1343) ---------------------------------------------

    async def renew(self, held: Collection[str], *, costs: Mapping[str, float] | None = None) -> list[str]:
        """Extend the lease of every held row that is still `running` and not yet handed back, in
        one statement, and return the ids it covered. A held row missing from the answer was
        cancelled, taken over or deleted (B3). `costs` copies a cost-so-far figure onto the rows it
        names (B2); a covered row without a figure keeps its cost. Late renewals of a lapsed row
        nobody took over succeed (B1)."""
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
        return list(covered)

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
        """One pass of take-over (B6, B7): every `running` row whose lease has lapsed and that the
        caller does not hold (B-P3) is failed (`lease_lapsed`) and, below the third attempt, retried
        (a new `queued` row, attempt + 1); the third attempt ends `retry_cap`. One transaction per
        row, `SKIP LOCKED`; no accounting and no host read. Returns the ids taken over. A row whose
        take-over the schema refuses rolls back whole and is left for the next pass."""
        taken: list[str] = []
        passed_over: set[str] = set(held)
        while (outcome := await self._take_over_one(passed_over)) is not None:
            passed_over.add(outcome.old_id)
            if outcome.refused:
                _logger.warning("the take-over of %s was refused by the schema; it is left for the next pass",
                                outcome.old_id)
                continue
            taken.append(outcome.old_id)
            announce("investigation.takeover", actor=SYSTEM, tenant_id=outcome.tenant_id, target=outcome.old_id,
                     detail=f"reason={outcome.reason}")
            if outcome.retry_id is not None:
                announce("investigation.retry", actor=SYSTEM, tenant_id=outcome.tenant_id, target=outcome.retry_id)
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
