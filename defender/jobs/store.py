"""The job store (#1342): alerts and investigations on PostgreSQL, behind async methods.

Each operation is one transaction on a pooled connection. Rules that races could break are the
database's: the alert row is locked for create and delete, a claim is `FOR UPDATE SKIP LOCKED` and a
compare-and-set, and every write that moves a row is conditional on the stage it expects. Audit
events are emitted after the transaction commits, never inside it. Imports the database layer,
identity's tenant and alert admission, and nothing of the runtime, so the API can load it."""

from __future__ import annotations

import datetime as _dt
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from defender._text import postgres_can_hold
from defender.database import async_engine, sessions
from defender.records.formats import admit

from .audit import SYSTEM, announce
from .errors import Conflict, NotFound, UnknownReference, UnstorableText
from defender.tenancy.models import TenantRecord

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

_UNIQUE_VIOLATION = "23505"
_FOREIGN_KEY_VIOLATION = "23503"


class _Refused(Exception):
    """A write the schema refused; `sqlstate` is PostgreSQL's class of it."""

    def __init__(self, sqlstate: str | None) -> None:
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


def _refuse_unstorable_text(**fields: str) -> None:
    """`UnstorableText` naming the first field PostgreSQL text cannot hold, before any query."""
    for name, text in fields.items():
        if not postgres_can_hold(text):
            raise UnstorableText(f"{name} holds a NUL or a lone surrogate, which PostgreSQL text cannot hold")


class JobStore:
    def __init__(self, dsn: str, *, clock: Callable[[], _dt.datetime], max_connections: int = 10) -> None:
        self._engine = async_engine(dsn, max_connections=max_connections)
        self._sessions = sessions(self._engine)
        self._clock = clock

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
        self, tenant_id: str, *, vendor: str, vendor_ticket_id: str, fired_at: _dt.datetime,
        changed_at: _dt.datetime, received_at: _dt.datetime, title: str, description: str, raw: bytes,
    ) -> StoredAlert:
        """Store an alert's exact bytes. `AlertRefused` for anything alert admission refuses; `Conflict`
        for a second alert with this vendor's ticket id; `UnknownReference` for a tenant with no row;
        `UnstorableText` for a text field PostgreSQL cannot hold."""
        _refuse_unstorable_text(vendor=vendor, vendor_ticket_id=vendor_ticket_id, title=title,
                           description=description)
        admit(raw)
        row = AlertRow(
            id=str(uuid.uuid4()), tenant_id=tenant_id, vendor=vendor, vendor_ticket_id=vendor_ticket_id,
            fired_at=fired_at, changed_at=changed_at, received_at=received_at, title=title,
            description=description, raw=raw)
        try:
            async with self._tx() as s:
                s.add(row)
        except _Refused as refused:
            if refused.sqlstate == _FOREIGN_KEY_VIOLATION:
                raise UnknownReference(f"no tenant {tenant_id!r}") from None
            if refused.sqlstate == _UNIQUE_VIOLATION:
                raise Conflict(f"alert {vendor_ticket_id!r} from {vendor!r} is already stored") from None
            raise
        return stored_alert(row)

    async def get_alert(self, tenant_id: str, alert_id: str) -> StoredAlert | None:
        if not postgres_can_hold(alert_id):
            return None
        async with self._tx() as s:
            row = (await s.execute(select(AlertRow).where(
                AlertRow.tenant_id == tenant_id, AlertRow.id == alert_id))).scalars().first()
        return None if row is None else stored_alert(row)

    # --- reads --------------------------------------------------------------------------

    async def get_investigation(self, tenant_id: str, investigation_id: str) -> InvestigationRecord | None:
        if not postgres_can_hold(investigation_id):
            return None
        async with self._tx() as s:
            row = await self._row(s, tenant_id, investigation_id)
        return None if row is None else investigation_record(row)

    @staticmethod
    async def _row(s: AsyncSession, tenant_id: str, investigation_id: str) -> InvestigationRow | None:
        return (await s.execute(select(InvestigationRow).where(
            InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == investigation_id))
        ).scalars().first()

    # --- create -------------------------------------------------------------------------

    async def create_investigation(
        self, tenant_id: str, alert_id: str, request_key: str, *, actor: str,
    ) -> tuple[InvestigationRecord, bool]:
        """Start an investigation of the alert, or answer the one this request already has (#1081
        §4.1): the latest attempt under the key; else the alert's live investigation, without
        recording this key; else a new attempt 1. `created` only when this call inserted the row.
        `UnknownReference` for an alert this tenant lacks."""
        if not postgres_can_hold(alert_id):
            raise UnknownReference(f"no alert {alert_id!r}")
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
            row = InvestigationRow(
                id=str(uuid.uuid4()), tenant_id=tenant_id, alert_id=alert_id, request_key=request_key,
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
                .values(stage="running", started_at=self._clock()).returning(InvestigationRow)
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
        self, tenant_id: str, investigation_id: str, *, actor: str,
    ) -> InvestigationRecord:
        """Abort a queued investigation (`aborted`, reason `cancelled`). `NotFound`; `Conflict` for a
        running one (cancelling a running investigation is not supported yet) and for an ended one."""
        if not postgres_can_hold(investigation_id):
            raise NotFound(f"no investigation {investigation_id!r}")
        async with self._tx() as s:
            row = (await s.execute(
                update(InvestigationRow).where(
                    InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == investigation_id,
                    InvestigationRow.stage == "queued")
                .values(stage="aborted", failure_reason="cancelled", finished_at=self._clock())
                .returning(InvestigationRow).execution_options(synchronize_session=False))).scalars().first()
            if row is None:
                current = await self._row(s, tenant_id, investigation_id)
                if current is None:
                    raise NotFound(f"no investigation {investigation_id!r}")
                if current.stage == "running":
                    raise Conflict("cannot cancel a running investigation yet")
                raise Conflict("the investigation already ended")
            record = investigation_record(row)
        announce("investigation.cancel", actor=actor, tenant_id=tenant_id, target=investigation_id)
        return record

    # --- delete -------------------------------------------------------------------------

    async def delete_investigation(self, tenant_id: str, investigation_id: str, *, actor: str) -> None:
        """Remove every attempt under the named investigation's request key. `NotFound`; `Conflict`
        while any of them is queued or running. Takes the alert lock, so it serializes with create."""
        if not postgres_can_hold(investigation_id):
            raise NotFound(f"no investigation {investigation_id!r}")
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
        self, tenant_id: str, investigation_id: str, *, stage: str, disposition: str | None = None,
        cost_usd: float | None = None, knowledge: dict[str, Any] | None = None,
        failure_reason: str | None = None, failure_message: str | None = None,
    ) -> InvestigationRecord | None:
        """Record the one terminal stage of a running investigation. Conditional on the row still
        being `running` (the fence): `None` when it changed nothing (the row moved, was deleted, or
        never ran), and the caller logs that and stops working on the row."""
        if stage not in TERMINAL:
            raise ValueError(f"{stage!r} is not a terminal stage")
        if not postgres_can_hold(investigation_id):
            return None
        async with self._tx() as s:
            row = (await s.execute(
                update(InvestigationRow).where(
                    InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == investigation_id,
                    InvestigationRow.stage == "running")
                .values(stage=stage, finished_at=self._clock(), disposition=disposition, cost_usd=cost_usd,
                        knowledge=knowledge, failure_reason=failure_reason, failure_message=failure_message)
                .returning(InvestigationRow).execution_options(synchronize_session=False))).scalars().first()
            if row is None:
                return None
            record = investigation_record(row)
        detail = f"stage={stage}" + (f" reason={failure_reason}" if failure_reason else "")
        announce("investigation.finish", actor=SYSTEM, tenant_id=tenant_id, target=investigation_id, detail=detail)
        return record
