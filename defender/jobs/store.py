"""The job store (#1342): alerts and investigations on PostgreSQL, behind async methods.

Each operation is one transaction on a pooled connection. Rules that races could break are the
database's: the alert row is locked for create and delete, a claim is `FOR UPDATE SKIP LOCKED` and a
compare-and-set, and every write that moves a row is conditional on the stage it expects. Audit
events are emitted after the transaction commits, never inside it. Imports the database layer,
identity's tenant and alert admission, and nothing of the runtime, so the API can load it.

Learning jobs (#1344) live beside the investigations: the transaction that ends an investigation
`completed` queues its auto job, a claim of a job is the investigations' claim on its own table
(with the age limit for a first attempt, D4), take-over covers both tables, and the investigation
delete removes its jobs.

Host requests (#1471, readiness checks and adoptions) are one table of their own: one queued row per kind and dedupe key,
a claim of the oldest queued row of any kind, a fenced finish, renewal beside the jobs', and a take-over and an offboard
that end a live row `failed` and never retry it (B1, B2); a drain is one more kind (#1546 D7).

Run evidence (#1546): every claim mints its token and writes its claim row in its own transaction; the claim's helper
stages facts and upload rows under it only while it is live (the write fence); and every ending of a job row, the
worker's, a cancel, an offboard, a take-over and a queue expiry, is one `apply` of a decision (`ending`), the one
writer of a row's terminal values, its evidence state and its uploads' promotion (PR9)."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import logging
import secrets
from collections.abc import AsyncIterator, Callable, Collection, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any, TypeVar

from sqlalchemy import Text, and_, case, delete, false, func, literal, select, tuple_, update
from sqlalchemy import cast as sql_cast
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DataError, DBAPIError, IntegrityError, InterfaceError, InternalError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeout
from sqlalchemy.ext.asyncio import AsyncSession

from defender._text import postgres_can_hold
from defender._vocab import Disposition, NoOutcome, normalized_disposition
from defender.database import async_engine, newest_first_query, sessions
from defender.records.formats import (
    ALERT_MAPPING_MISSING,
    MAPPING_KEYS,
    AlertId,
    AlertMapping,
    HostRequestId,
    IdRefused,
    InvestigationId,
    LearningJobId,
    TenantId,
    admit,
    check_mapping,
    derive_display,
    derive_facts,
    digest_of,
)

from defender.records.job_facts import (
    EXPIRED,
    LEASE_LAPSED,
    RETRY_CAP,
    TENANT_OFFBOARDED,
)

from . import ending
from .audit import SYSTEM, announce
from .errors import Conflict, NotFound, OffboardNotSettled, UnknownReference, UnstorableText
from .learning_check import arm_learning_check
from defender.tenancy.models import AlertMappingRow, CaseVersionRow, TenantRecord
from defender.tenancy.models import offboard as _tenancy_offboard
from defender.tenancy.models import share_tenant

from .models import (
    ADOPTION,
    ALERT_LISTING_COLUMNS,
    CLAIM_REFERENCE,
    DRAIN,
    HOST_REQUEST_KINDS,
    HOST_REQUEST_LIVE,
    INVESTIGATION_CLAIM,
    LEARNING_CLAIM,
    POST_STEP_CLAIM,
    READABLE_EVIDENCE,
    READINESS,
    LIVE,
    is_terminal,
    AcceptedObject,
    AlertListing,
    AlertRow,
    Claim,
    ClaimRow,
    ClaimView,
    HostRequestClaim,
    HostRequestRecord,
    HostRequestRow,
    InvestigationRecord,
    InvestigationRow,
    LearningCheckRow,
    LearningCheckClaim,
    LearningClaim,
    LearningJobRecord,
    LearningJobRow,
    LearningProgress,
    StagedFactRow,
    StoredAlert,
    UploadRow,
    alert_listing,
    claim_view,
    host_request_record,
    investigation_record,
    learning_job_record,
    stored_alert,
    with_token,
)

#: How long a claim's lease runs before it lapses unless its holder renews it (#1343 B1).
LEASE_SECONDS = 30.0
#: Attempts of one request: the third attempt that lapses is not retried (#1343 B6).
MAX_ATTEMPTS = 3
#: How old a learning job's first attempt may be when a claim reaches it (#1344 D4).
LEARNING_MAX_AGE_SECONDS = 24 * 3600.0
#: The reserved prefix of an auto job's request key, which no client request id may carry (#1344).
AUTO_REQUEST_KEY_PREFIX = "auto:"

#: Passes of the offboard's ending of the tenant's live rows before it gives up (#1360 D8): one pass ends them all,
#: a second when a take-over or a finish inserted a row while the first waited; more means rows keep appearing.
OFFBOARD_MAX_PASSES = 5
_LEARNING_LIVE = ("queued", "running")
#: The tenant states that take no new job and start nothing new (#1360 D7).
_BEING_REMOVED = ("offboarding", "offboarded")
#: How often a host request's create tries again when the queued row its insert met was claimed before it was read.
_HOST_CREATE_TRIES = 3

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
    #: The audit family of the row: `investigation`, `learning_job`, or a host request's kind (#1471).
    kind: str = "investigation"


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



def _latest_status() -> Any:
    """The listed alert's newest investigation's stage by `(created_at, id)`, or null: a correlated lookup (#1581 O1)."""
    return (select(InvestigationRow.stage)
            .where(InvestigationRow.tenant_id == AlertRow.tenant_id, InvestigationRow.alert_id == AlertRow.id)
            .order_by(InvestigationRow.created_at.desc(), InvestigationRow.id.desc())
            .limit(1).correlate(AlertRow).scalar_subquery().label("latest_status"))


# The alert's stored outcome (#1581 AP1) is a copy of the disposition of its newest `completed` investigation by
# `(created_at, id)`, with that investigation's id and `created_at` (its source). Only a finish to `completed` and the
# investigation delete can change it, and each does one conditional update of the alert row, judged against the stored
# source, so the copy is right whichever order racing writes commit in: PostgreSQL applies two updates of one row one
# after the other, and the second re-checks its condition against the first's committed result.

async def _outcome_after_completion(s: AsyncSession, row: InvestigationRow) -> None:
    """After a finish's fenced update to `completed`: this investigation becomes the alert's outcome unless the stored
    source is newer by `(created_at, id)`. Locks the alert row after the investigation row (D1: a plain update takes
    `FOR NO KEY UPDATE`, which does not block take-over's retry insert)."""
    await s.execute(
        update(AlertRow).where(
            AlertRow.tenant_id == row.tenant_id, AlertRow.id == row.alert_id,
            AlertRow.outcome_investigation_id.is_(None)
            | (tuple_(AlertRow.outcome_created_at, AlertRow.outcome_investigation_id)
               < tuple_(literal(row.created_at, AlertRow.outcome_created_at.type),
                        literal(row.id, AlertRow.outcome_investigation_id.type))))
        .values(outcome=row.disposition, outcome_investigation_id=row.id, outcome_created_at=row.created_at)
        .execution_options(synchronize_session=False))


async def _outcome_after_delete(s: AsyncSession, tenant_id: TenantId, alert_id: AlertId, deleted: Sequence[str]) -> None:
    """After the investigation delete removed `deleted`: when the stored source is one of them, the alert's outcome
    becomes the newest remaining completed investigation's, or none. The delete holds the alert's lock already."""
    newest = (await s.execute(
        select(InvestigationRow.disposition, InvestigationRow.id, InvestigationRow.created_at).where(
            InvestigationRow.tenant_id == tenant_id, InvestigationRow.alert_id == alert_id,
            InvestigationRow.stage == "completed")
        .order_by(InvestigationRow.created_at.desc(), InvestigationRow.id.desc()).limit(1))).first()
    disposition, source, created_at = newest if newest is not None else (None, None, None)
    await s.execute(
        update(AlertRow).where(
            AlertRow.tenant_id == tenant_id, AlertRow.id == alert_id, AlertRow.outcome_investigation_id.in_(deleted))
        .values(outcome=disposition, outcome_investigation_id=source, outcome_created_at=created_at)
        .execution_options(synchronize_session=False))


def _refuse_unstorable_text(**fields: str) -> None:
    """`UnstorableText` naming the first field PostgreSQL text cannot hold, before any query."""
    for name, text in fields.items():
        if not postgres_can_hold(text):
            raise UnstorableText(f"{name} holds a NUL or a lone surrogate, which PostgreSQL text cannot hold")


#: A check clock's time that makes it due whatever the interval: a hold's end leaves the clock so
#: when a job ended `completed` while the hold stood (amendment 3, #1487 O7).
_DUE_AT_ONCE = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)


def _unheld() -> Any:
    """No post-step holds the check clock: never held, or its hold lapsed."""
    return (LearningCheckRow.checking_until.is_(None)) | (LearningCheckRow.checking_until < func.now())


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

    async def list_alerts(  # noqa: PLR0913 — the list's filters, cursor and page size
        self, tenant_id: TenantId, *, fired_after: _dt.datetime | None, fired_before: _dt.datetime | None,
        outcome: Disposition | NoOutcome | None, after: tuple[_dt.datetime, str] | None, limit: int,
    ) -> list[AlertListing]:
        """Up to `limit` of the tenant's alerts with `fired_after <= fired_at < fired_before` (a bound left `None`
        is open), newest first by `(fired_at, id)` descending, strictly after the position `after` when given.
        `outcome` narrows to the alerts whose stored outcome is that disposition, or (`NoOutcome`) is null, before the
        limit; `None` does not narrow (#1581 O2). Selects no `raw` (#1507); each alert's `latest_status` is its newest
        investigation's stage, one index lookup per row returned."""
        query = select(*ALERT_LISTING_COLUMNS, _latest_status()).where(AlertRow.tenant_id == tenant_id)
        if fired_after is not None:
            query = query.where(AlertRow.fired_at >= fired_after)
        if fired_before is not None:
            query = query.where(AlertRow.fired_at < fired_before)
        if outcome is not None:
            if isinstance(outcome, NoOutcome):
                query = query.where(AlertRow.outcome.is_(None))
            elif normalized_disposition(outcome) == outcome:
                query = query.where(AlertRow.outcome == outcome)
            else:
                raise ValueError(f"{outcome!r} is not a disposition")
            # A constant within the filter, so the order is unchanged; leading with it makes `alerts_outcome_newest_first`
            # the one index that reads the page in order. Without it the planner, its null fraction pooled over every
            # tenant, walked `alerts_newest_first` filtering a tenant where `none` is rare (C8b: 300-500 ms at 50k).
            query = query.order_by(AlertRow.outcome)
        query = newest_first_query(query, AlertRow.fired_at, AlertRow.id, after, limit)
        async with self._tx() as s:
            rows: Sequence[Any] = (await s.execute(query)).all()
        return [alert_listing(row) for row in rows]

    # --- the alert mapping (#1345) ------------------------------------------------------

    @staticmethod
    async def _mapping_in(s: AsyncSession, tenant_id: TenantId) -> AlertMapping | None:
        row = (await s.execute(select(AlertMappingRow).where(AlertMappingRow.tenant_id == tenant_id))).scalars().first()
        return None if row is None else row.as_mapping()

    async def get_alert_mapping(self, tenant_id: TenantId) -> AlertMapping | None:
        """The tenant's alert mapping, `None` until one is saved."""
        async with self._tx() as s:
            return await self._mapping_in(s, tenant_id)

    async def put_alert_mapping(
        self, tenant_id: TenantId, mapping: AlertMapping, *, actor: str, credential_id: str | None = None,
    ) -> tuple[AlertMapping, bool]:
        """Replace the tenant's alert mapping whole: the one writer (M1). It applies to alerts stored from now on;
        alerts already stored keep their title and description (#1420). Returns the mapping as stored and whether it was
        created, its tenant's first save. `AlertMappingFault` naming the entry for an invalid mapping (a re-check for
        callers that are not the API), `UnknownReference` for a tenant with no row. A database error fails the whole
        replace. No lock: the insert of the row decides `created`, so of two first saves racing, exactly one creates and
        the other updates (#1420)."""
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
                stored = await self._mapping_in(s, tenant_id)
        except _Refused as refused:
            if refused.sqlstate == _FOREIGN_KEY_VIOLATION:
                raise UnknownReference(f"no tenant {tenant_id!r}") from None
            raise
        assert stored is not None
        announce("alert_mapping.update", actor=actor, tenant_id=tenant_id, target=tenant_id, credential_id=credential_id)
        return stored, created

    # --- reads --------------------------------------------------------------------------

    async def get_investigation(self, tenant_id: TenantId, investigation_id: InvestigationId) -> InvestigationRecord | None:
        async with self._tx() as s:
            row = await self._row(s, tenant_id, investigation_id)
        return None if row is None else investigation_record(row)

    async def list_investigations(
        self, tenant_id: TenantId, *, alert_id: AlertId | None, after: tuple[_dt.datetime, str] | None, limit: int,
    ) -> list[InvestigationRecord]:
        """Up to `limit` of the tenant's investigations (of one alert when `alert_id` is given), newest first by
        `(created_at, id)` descending, strictly after the position `after` when given."""
        query = select(InvestigationRow).where(InvestigationRow.tenant_id == tenant_id)
        if alert_id is not None:
            query = query.where(InvestigationRow.alert_id == alert_id)
        query = newest_first_query(query, InvestigationRow.created_at, InvestigationRow.id, after, limit)
        async with self._tx() as s:
            rows: Sequence[Any] = (await s.execute(query)).scalars().all()
        return [investigation_record(row) for row in rows]

    @staticmethod
    async def _row(s: AsyncSession, tenant_id: TenantId, investigation_id: InvestigationId) -> InvestigationRow | None:
        return (await s.execute(select(InvestigationRow).where(
            InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == investigation_id))
        ).scalars().first()

    # --- create -------------------------------------------------------------------------

    async def create_investigation(
        self, tenant_id: TenantId, alert_id: AlertId, request_key: str, *, actor: str,
        credential_id: str | None = None, update_ticket: bool = False,
    ) -> tuple[InvestigationRecord, bool]:
        """Start an investigation of the alert, or answer the one this request already has (#1081
        §4.1): the latest attempt under the key; else the alert's live investigation, without
        recording this key; else a new attempt 1. `created` only when this call inserted the row.
        `UnknownReference` for an alert this tenant lacks; `Conflict` naming the tenant's state when a new attempt is
        due and the tenant is offboarding or offboarded (#1360 O4), naming the missing mapping when it has saved
        no alert mapping (#1345 O4), and naming the ticket when `update_ticket` is set and this alert names none
        (#1471 W1: no case record, a mapping with no `case_key`, or a key this alert does not yield). A replay or a
        live answer is the existing row with its own flag; the new request's flag is not compared."""
        _refuse_unstorable_text(request_key=request_key)
        async with self._tx() as s:
            state = await share_tenant(s, tenant_id)
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
            _refuse_removed(state, tenant_id)
            mapping = await self._mapping_in(s, tenant_id)
            if mapping is None:  # never deleted, so no lock (#1345 O4)
                raise Conflict(ALERT_MAPPING_MISSING)
            if update_ticket:
                await self._refuse_without_ticket(s, tenant_id, alert_id, mapping)
            row = InvestigationRow(
                id=InvestigationId.mint(), tenant_id=tenant_id, alert_id=alert_id, request_key=request_key,
                attempt=1, stage="queued", created_at=self._clock(), cost_usd=0.0, update_ticket=update_ticket)
            s.add(row)
            record = investigation_record(row)
        announce("investigation.start", actor=actor, tenant_id=tenant_id, target=record.investigation_id,
                 detail=f"alert {alert_id}", credential_id=credential_id)
        return record, True

    @staticmethod
    async def _refuse_without_ticket(s: AsyncSession, tenant_id: TenantId, alert_id: AlertId,
                                     mapping: AlertMapping) -> None:
        """`Conflict` unless this alert names a ticket: the tenant has a case record, its mapping maps a `case_key`,
        and the key is one this alert's document yields (#1471 W1)."""
        case_row = (await s.execute(select(CaseVersionRow).where(CaseVersionRow.tenant_id == tenant_id)
                                    .order_by(CaseVersionRow.version.desc()).limit(1))).scalars().first()
        if case_row is None or case_row.deleted:
            raise Conflict("the tenant has no case record, so there is no ticket to update")
        raw = (await s.execute(select(AlertRow.raw).where(
            AlertRow.tenant_id == tenant_id, AlertRow.id == alert_id))).scalar_one()
        key = derive_facts(admit(raw).document, mapping).case_key
        if key is None:
            raise Conflict("this alert names no ticket (the tenant's alert mapping yields no case key from it), "
                           "so there is no ticket to update")

    # --- claim --------------------------------------------------------------------------

    async def claim(self) -> Claim | None:
        """Move the oldest queued investigation (by `created_at`, ties by id) to `running`, with its
        tenant's state read in the same transaction (#1342 r7 R7-1), or `None`. A row another
        transaction holds is skipped, never waited for. The state read takes no lock: a teardown
        that commits just after it still races the job, and the job's own tenant admission is what
        refuses it then. The claim's token is minted here and its claim row written in the same transaction (#1546
        PR7): no inputs; its launch facts are the launch record the helper copies into the job's root (the alert, its
        digest and label as stored now, and the run box's start token), with the attempt."""
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
            token = _mint(s, record.tenant_id, INVESTIGATION_CLAIM, investigation_id=record.investigation_id,
                          launch=await _investigation_launch(s, record))
        announce("investigation.claim", actor=SYSTEM, tenant_id=record.tenant_id, target=record.investigation_id)
        return with_token(Claim(record=record, tenant_state=state), token)

    # --- the claim's staged facts and uploads (#1546 PR7, A-O3) ----------------------------------------------------------

    async def claim_live(self, token: str) -> bool:
        """Whether the claim `token` is live: the row it references has not ended (a lapsed lease alone does not end it,
        since a late renewal may revive it), or, for a post-step, the tenant's hold still names it. False for an unknown
        token."""
        async with self._tx() as s:
            return await _live_claim(s, token) is not None

    async def stage_fact(self, token: str, name: str, body: Any) -> None:
        """Stage one fact under the live claim `token` (the helper's write, PR2/PR7): `progress` replaces the one staged
        before it; every other name is create-once. `Conflict` for a claim that is unknown or no longer live, and for a
        second fact of a create-once name (the first body stays). Liveness is read under a share lock of the referenced
        row in the write's own transaction, so a write racing an uncommitted ender waits for it and is then refused."""
        async with self._tx() as s:
            await _require_live(s, token)
            insert = pg_insert(StagedFactRow).values(token=token, name=name, body=body, staged_at=func.now())
            if name == PROGRESS_FACT:
                insert = insert.on_conflict_do_update(
                    index_elements=[StagedFactRow.token, StagedFactRow.name],
                    set_={"body": insert.excluded.body, "staged_at": insert.excluded.staged_at})
            else:
                insert = insert.on_conflict_do_nothing()
            if (await s.execute(insert.returning(StagedFactRow.name))).first() is None:
                raise Conflict(f"the fact {name!r} is already staged under this claim; it is staged once")

    async def begin_upload(  # noqa: PLR0913 — the upload row's values
        self, token: str, obj: str, *, size: int, sha256: str, wrapped_key: str, scrub: str | None = None,
    ) -> None:
        """Insert the `pending` upload row of `obj` under the live claim `token`, before its PUT (A-O3): create-once,
        `Conflict` for a second row of the object (the first stays) or a claim not live. Its age is the database's
        clock (the grace sweep's)."""
        async with self._tx() as s:
            await _require_live(s, token)
            made = (await s.execute(
                pg_insert(UploadRow).values(token=token, object=obj, size=size, sha256=sha256, wrapped_key=wrapped_key,
                                            status="pending", scrub=scrub, created_at=func.now())
                .on_conflict_do_nothing().returning(UploadRow.object))).first()
            if made is None:
                raise Conflict(f"the object {obj!r} already has an upload row under this claim")

    async def refuse_upload(self, token: str, obj: str, *, scrub: str | None = None) -> None:
        """Make the upload row of `obj` `refused` at once under the live claim `token`, for an object the helper could not
        put at all (no data key could be made): nothing was computed, so it carries no size, digest or key. Create-once
        as `begin_upload`: `Conflict` for a second row of the object or a claim not live."""
        async with self._tx() as s:
            await _require_live(s, token)
            made = (await s.execute(
                pg_insert(UploadRow).values(token=token, object=obj, size=None, sha256=None, wrapped_key=None,
                                            status="refused", scrub=scrub, created_at=func.now())
                .on_conflict_do_nothing().returning(UploadRow.object))).first()
            if made is None:
                raise Conflict(f"the object {obj!r} already has an upload row under this claim")

    async def finish_upload(self, token: str, obj: str, *, status: str) -> None:
        """Move the `pending` upload row of `obj` to `uploaded` or `refused`, once, while the claim is live (A-O3).
        `Conflict` for a row that is not pending (moved already, or accepted), absent, or under a claim not live."""
        if status not in ("uploaded", "refused"):
            raise ValueError(f"{status!r} is not an upload's end (uploaded or refused)")
        async with self._tx() as s:
            await _require_live(s, token)
            moved = (await s.execute(
                update(UploadRow).where(UploadRow.token == token, UploadRow.object == obj, UploadRow.status == "pending",
                                        UploadRow.accepted_at.is_(None))
                .values(status=status).returning(UploadRow.object).execution_options(synchronize_session=False))).first()
            if moved is None:
                raise Conflict(f"the object {obj!r} has no pending upload row under this claim")

    async def staged(self, token: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        """What the claim `token`'s helper left, as `decide` reads it: its staged facts `{name: body}` and its upload rows
        `{object: {"status", "scrub"}}`. Empty for an unknown token."""
        async with self._tx() as s:
            return await _staged_under(s, token)

    async def get_claim(self, token: str) -> ClaimView | None:
        """The claim row `token` as its helper reads it (its kind, reference, launch facts and fixed input set), or
        `None` when there is none."""
        async with self._tx() as s:
            row = (await s.execute(select(ClaimRow).where(ClaimRow.token == token))).scalars().first()
        return None if row is None else claim_view(row)

    async def run_unusable(self, tenant_id: str, run_id: str) -> bool:
        """Whether the investigation `run_id` of `tenant_id` can never be a drain's input (#1546 PR6, A-O6, D7): no such row
        (an id of no investigation's form included), its evidence `expired`, or its scrub not `clean`. The complement of
        the rule `_drain_inputs` fixes a drain's set by. Read-only."""
        try:
            run = InvestigationId(run_id)
        except (IdRefused, ValueError):
            return True
        async with self._tx() as s:
            usable = (await s.execute(select(InvestigationRow.id).where(
                InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == run, _usable_run()))).first()
        return usable is None

    async def accepted_input(self, tenant_id: str, owner_id: str, obj: str) -> AcceptedObject:
        """The accepted object `obj` of the owner `owner_id` (an investigation or a learning job of `tenant_id`), as a pull
        reads it (A-O6). `NotFound` for an owner that is no row of this tenant; `Conflict` for one that cannot be read
        now: its tenant is not active, its evidence is not readable (`none`, `expired`), it is not `clean`, or it has no
        accepted upload of `obj`. Read-only."""
        async with self._tx() as s:
            column: Any
            inv = (await s.execute(select(InvestigationRow.tenant_id, InvestigationRow.evidence_state,
                                          InvestigationRow.scrub).where(InvestigationRow.id == owner_id))).first()
            if inv is not None:
                owner_kind, column, (tenant, state, scrub) = ending.INVESTIGATION, ClaimRow.investigation_id, inv
            else:
                job = (await s.execute(select(LearningJobRow.tenant_id, LearningJobRow.evidence_state)
                                       .where(LearningJobRow.id == owner_id))).first()
                if job is None:
                    raise NotFound(f"no owner {owner_id!r}")
                owner_kind, column, (tenant, state), scrub = ending.LEARNING, ClaimRow.learning_job_id, job, "clean"
            if str(tenant) != str(tenant_id):
                raise NotFound(f"no owner {owner_id!r} of this tenant")
            tenant_state = (await s.execute(select(TenantRecord.state).where(TenantRecord.id == tenant))).scalar()
            if tenant_state != "active" or state not in READABLE_EVIDENCE or scrub != "clean":
                raise Conflict(f"the owner {owner_id!r} cannot be read now")
            found = (await s.execute(
                select(UploadRow.token, UploadRow.size, UploadRow.sha256, UploadRow.wrapped_key)
                .join(ClaimRow, ClaimRow.token == UploadRow.token)
                .where(column == owner_id, UploadRow.object == obj, UploadRow.status == "uploaded",
                       UploadRow.accepted_at.is_not(None)))).first()
        claim, size, sha256, wrapped = (None, None, None, None) if found is None else found
        if size is None:
            raise Conflict(f"the owner {owner_id!r} has no accepted {obj!r}")
        return AcceptedObject(owner_kind=owner_kind, claim=str(claim), size=int(size), sha256=str(sha256),
                              wrapped_key=str(wrapped))

    # --- cancel -------------------------------------------------------------------------

    async def cancel_investigation(
        self, tenant_id: TenantId, investigation_id: InvestigationId, *, actor: str, credential_id: str | None = None,
    ) -> InvestigationRecord:
        """Abort a queued or running investigation (`aborted`, reason `cancelled`) through `apply`, its evidence
        `none` and its cost the last staged progress, a lower limit (#1546 D15); a running one's worker ends its child
        at its next renewal (B3, B9). `NotFound`; `Conflict` for an ended one, naming the live retry when the ended
        attempt has one."""
        async with self._tx() as s:
            record = await self.apply(tenant_id, investigation_id, _Deferred(ending.INVESTIGATION, ending.Cancelled()),
                                      session=s)
            if record is None:
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
        announce("investigation.cancel", actor=actor, tenant_id=tenant_id, target=investigation_id,
                 credential_id=credential_id)
        return _as(InvestigationRecord, record)

    # --- offboard (#1360) ---------------------------------------------------------------

    async def offboard_tenant(self, tenant_id: TenantId, *, actor: str) -> TenantRecord:
        """Move the tenant to `offboarding` and end every queued or running job of it, in one transaction (O3).
        Tenancy's own transition runs first (`NotFound`, `Conflict`: its refusals, nothing changed); then the tenant's
        live investigations end `aborted` and its live learning jobs `skipped`, both with the reason
        `tenant_offboarded`, each through `apply` (evidence `none`, #1546), until a fresh read finds none: a take-over
        or a finish that the first pass waited on may have inserted a retry or an auto job it could not see.
        Investigations are ended until none are left, then learning jobs (investigations derive only from
        investigations, so the first phase is never repeated after a learning job is locked); rows are locked in id
        order (D9). `OffboardNotSettled`, with nothing changed, when rows keep appearing past the cap (D8), counted over
        both phases. Then the tenant's live host requests (#1471 B1) end `failed`/`tenant_offboarded`, in one uncounted
        pass: no host request is inserted for a tenant once its row is offboarding (a create shares the tenant's row
        lock first and refuses that state; a take-over never queues one). Each ended job is audited after the commit,
        by `actor`."""
        investigations: list[str] = []
        learning: list[str] = []
        phases = (
            (InvestigationRow, InvestigationRow.stage.in_(LIVE), investigations, ending.INVESTIGATION),
            (LearningJobRow, LearningJobRow.status.in_(_LEARNING_LIVE), learning, ending.LEARNING),
        )
        async with self._tx() as s:
            record = await _tenancy_offboard(s, tenant_id)
            passes = 0
            for row, live, ended, kind in phases:  # investigations until none are left, then learning jobs
                while True:
                    if passes >= OFFBOARD_MAX_PASSES:
                        raise OffboardNotSettled(
                            f"tenant {tenant_id} still had live jobs after {OFFBOARD_MAX_PASSES} passes of ending "
                            f"them; the offboard was rolled back")
                    passes += 1
                    ended += await self._offboard_live(s, row, tenant_id, live, kind)
                    if not (await s.execute(select(row.id).where(row.tenant_id == tenant_id, live).limit(1))).first():
                        break
            hosted = await self._end_live_host_requests(s, tenant_id)
        for job_id in sorted(investigations):
            announce("investigation.cancel", actor=actor, tenant_id=tenant_id, target=job_id,
                     detail=f"reason={TENANT_OFFBOARDED}")
        for job_id in sorted(learning):
            announce("learning_job.finish", actor=actor, tenant_id=tenant_id, target=job_id,
                     detail=f"status=skipped reason={TENANT_OFFBOARDED}")
        for request_id, kind in hosted:
            announce(f"{kind}.finish", actor=actor, tenant_id=tenant_id, target=request_id,  # type: ignore[arg-type]
                     detail=f"status=failed reason={TENANT_OFFBOARDED}")
        return record

    async def _end_live_host_requests(self, s: AsyncSession, tenant_id: TenantId) -> list[tuple[str, str]]:
        """The offboard's host-request phase (#1471 B1): the tenant's queued and running rows end `failed` /
        `tenant_offboarded` with the offboard's words, none deleted. Returns `(id, kind)` of each, in id order."""
        live = HostRequestRow.stage.in_(HOST_REQUEST_LIVE)
        ended = set(await self._offboard_live(s, HostRequestRow, tenant_id, live, ending.HOST_REQUEST))
        if not ended:
            return []
        kinds = (await s.execute(select(HostRequestRow.id, HostRequestRow.kind)
                                 .where(HostRequestRow.id.in_(ended)))).all()
        return sorted((str(i), kind) for i, kind in kinds)

    async def _offboard_live(self, s: AsyncSession, row: Any, tenant_id: TenantId, live: Any, kind: str) -> list[str]:
        """End the tenant's live rows of one table through `apply`: lock them in id order, then end exactly those.
        Returns their ids."""
        locked: Sequence[Any] = (await s.execute(select(row.id).where(row.tenant_id == tenant_id, live)
                                  .order_by(row.id).with_for_update())).scalars().all()
        ended = []
        for owner in locked:
            if await self.apply(tenant_id, str(owner), _Deferred(kind, ending.Offboarded()), session=s) is not None:
                ended.append(str(owner))
        return ended

    # --- delete -------------------------------------------------------------------------

    async def delete_investigation(
        self, tenant_id: TenantId, investigation_id: InvestigationId, *, actor: str, credential_id: str | None = None,
    ) -> None:
        """Remove every attempt under the named investigation's request key, with their learning
        jobs, queued or ended (#1344 O10, D6), and the claims of all of them with the facts and upload rows staged under
        those claims (#1546). `NotFound`; `Conflict` while any attempt is queued or
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
            await _delete_claims(s, (ClaimRow.investigation_id.in_(inv_ids)
                                     | ClaimRow.learning_job_id.in_([job_id for job_id, _ in jobs])))
            if jobs:
                await s.execute(delete(LearningJobRow).where(LearningJobRow.investigation_id.in_(inv_ids)))
            await s.execute(delete(InvestigationRow).where(
                InvestigationRow.tenant_id == tenant_id, InvestigationRow.alert_id == named.alert_id,
                InvestigationRow.request_key == named.request_key))
            await _outcome_after_delete(s, tenant_id, named.alert_id, inv_ids)
        announce("investigation.delete", actor=actor, tenant_id=tenant_id, target=investigation_id,
                 credential_id=credential_id)

    # --- the ending: the one writer of a job row's terminal values (#1546 PR9) --------------------------------------------

    async def apply(
        self, tenant_id: str, owner_id: str, decision: ending.Decision | _Deferred, *, session: AsyncSession | None = None,
    ) -> InvestigationRecord | LearningJobRecord | HostRequestRecord | None:
        """Write `decision` on the tenant's row `owner_id` (an investigation, a learning job or a host request, as its
        `kind` says), in one transaction, and answer the row as it now stands; `None`, changing nothing, when the row is
        not the tenant's or is not in the state its ending needs (the fence: running and not handed back for a helper's
        end or a hand-back, running for a take-over, queued or running for a cancel or an offboard, queued for a queue
        expiry). An `End` writes every terminal value with its evidence state, promotes the upload rows it names that
        are `uploaded`, and runs its follow-ons (the alert's outcome, the auto learning job, the check clock, a learning
        job's findings, a take-over's retry); a `HandBack` lapses the lease at once and writes the last cost and
        knowledge. A refusal of the schema raises (`is_refusal`), the whole ending with it: the caller applies
        `ending.lesser(decision)`. The store's own enders pass what ended the row instead of a decision, decided here
        from the claim's staged facts and uploads under the row's lock, and their own `session` (the caller's
        transaction; audited by the caller). With no `session` the tenant's row is share-locked first (#1360 Flow 2)
        and the ending is audited after the commit."""
        if session is not None:
            state = (await session.execute(select(TenantRecord.state).where(TenantRecord.id == tenant_id))).scalar()
            applied = await self._apply_ending(session, tenant_id, owner_id, decision, state)
            return None if applied is None else applied.record
        async with self._tx() as s:
            state = await share_tenant(s, TenantId(tenant_id))
            applied = await self._apply_ending(s, tenant_id, owner_id, decision, state)
        if applied is None:
            return None
        if applied.announce is not None:
            action, detail = applied.announce
            announce(action, actor=SYSTEM, tenant_id=tenant_id, target=owner_id, detail=detail)  # type: ignore[arg-type]
        return applied.record

    async def _apply_ending(self, s: AsyncSession, tenant_id: str, owner_id: str, decision: ending.Decision | _Deferred,
                            state: str | None) -> _Applied | None:
        if decision.kind == ending.INVESTIGATION:
            return await self._apply_investigation(s, tenant_id, owner_id, decision)
        if decision.kind == ending.LEARNING:
            return await self._apply_learning(s, tenant_id, owner_id, decision, state)
        if decision.kind == ending.HOST_REQUEST:
            return await self._apply_host_request(s, tenant_id, owner_id, decision)
        raise ValueError(f"{decision.kind!r} is not a kind of row")

    async def _apply_investigation(self, s: AsyncSession, tenant_id: str, owner_id: str,
                                   decision: ending.Decision | _Deferred) -> _Applied | None:
        row = (await s.execute(
            select(InvestigationRow).where(InvestigationRow.tenant_id == tenant_id, InvestigationRow.id == owner_id,
                                           _ending_fence(InvestigationRow.stage, InvestigationRow.accounting_written_at, decision))
            .with_for_update().execution_options(populate_existing=True))).scalars().first()
        if row is None:
            return None
        token = await _claim_token(s, ClaimRow.investigation_id, owner_id)
        decided = await _decision_under_lock(s, token, decision)
        if token is None and isinstance(decided, ending.End) and decided.cost_usd is None:
            # A row ended before any claim (a queued row cancelled or offboarded): nothing ran, so exactly 0 (S2).
            decided = dataclasses.replace(decided, cost_usd=0.0, cost_is_lower_limit=False)
        where = (InvestigationRow.id == owner_id,)
        if isinstance(decided, ending.HandBack):
            done = (await s.execute(
                update(InvestigationRow).where(*where)
                .values(lease_expires_at=func.now() - _dt.timedelta(seconds=1), cost_usd=decided.cost_usd,
                        cost_is_lower_limit=decided.cost_is_lower_limit, knowledge=decided.knowledge,
                        accounting_written_at=self._clock())
                .returning(InvestigationRow).execution_options(synchronize_session=False, populate_existing=True))).scalars().one()
            return _Applied(investigation_record(done))
        reason, message, retry = _apply_lapse_words(decided, row.attempt, row.accounting_written_at is not None)
        values: dict[str, Any] = {
            "stage": decided.stage, "failure_reason": reason, "failure_message": message,
            "disposition": decided.disposition, "cost_usd": decided.cost_usd,
            "cost_is_lower_limit": decided.cost_is_lower_limit, "knowledge": decided.knowledge, "scrub": decided.scrub,
            "evidence_state": decided.evidence_state, "finished_at": self._clock()}
        if isinstance(decided.ended_by, ending.Exited | ending.Stopped | ending.NotLaunched):
            values["accounting_written_at"] = self._clock()  # the holder's own end carries its final accounting (B4)
        if isinstance(decided.ended_by, ending.Offboarded):
            values["lease_expires_at"] = None
        done = (await s.execute(
            update(InvestigationRow).where(*where).values(**values)
            .returning(InvestigationRow).execution_options(synchronize_session=False, populate_existing=True))).scalars().one()
        record = investigation_record(done)
        await _apply_promotion(s, token, decided.promote)
        if decided.follow_ons.alert_outcome:
            await _outcome_after_completion(s, done)
        if decided.follow_ons.auto_learning_job:
            # Not announced: the investigation's finish is its audit event (#1342's audit stream).
            s.add(LearningJobRow(
                id=LearningJobId.mint(), tenant_id=record.tenant_id, alert_id=record.alert_id,
                investigation_id=record.investigation_id,
                request_key=f"{AUTO_REQUEST_KEY_PREFIX}{record.investigation_id}", attempt=1, trigger="auto",
                status="queued", created_at=func.now()))  # its queue age is the database's clock (#1546 D10)
        if decided.follow_ons.arm_check_clock:
            await arm_learning_check(s, record.tenant_id)
        if retry:
            s.add(InvestigationRow(
                id=InvestigationId.mint(), tenant_id=row.tenant_id, alert_id=row.alert_id, request_key=row.request_key,
                attempt=row.attempt + 1, stage="queued", created_at=self._clock(), cost_usd=0.0,
                update_ticket=row.update_ticket))
        detail = f"stage={record.stage}" + (f" reason={reason}" if reason else "")
        return _Applied(record, ("investigation.finish", detail))

    async def _apply_learning(self, s: AsyncSession, tenant_id: str, owner_id: str,
                              decision: ending.Decision | _Deferred, state: str | None) -> _Applied | None:
        row = (await s.execute(
            select(LearningJobRow).where(LearningJobRow.tenant_id == tenant_id, LearningJobRow.id == owner_id,
                                         _ending_fence(LearningJobRow.status, LearningJobRow.finished_at, decision))
            .with_for_update().execution_options(populate_existing=True))).scalars().first()
        if row is None:
            return None
        token = await _claim_token(s, ClaimRow.learning_job_id, owner_id)
        decided = await _decision_under_lock(s, token, decision)
        where = (LearningJobRow.id == owner_id,)
        progress = _apply_progress_values(decided)
        if isinstance(decided, ending.HandBack):
            done = (await s.execute(
                update(LearningJobRow).where(*where)
                .values(lease_expires_at=func.now() - _dt.timedelta(seconds=1), finished_at=self._clock(), **progress)
                .returning(LearningJobRow).execution_options(synchronize_session=False, populate_existing=True))).scalars().one()
            return _Applied(learning_job_record(done))
        reason, message, retry = _apply_lapse_words(decided, row.attempt, row.finished_at is not None)
        publish, added = decided.publish_state, None
        if decided.stage == "completed":
            publish, added = await _store_findings(s, tenant_id, owner_id, state, decided.findings)
        done = (await s.execute(
            update(LearningJobRow).where(*where)
            .values(status=decided.stage, reason=reason, message=message, finished_at=self._clock(),
                    lease_expires_at=None, publish_state=publish, evidence_state=decided.evidence_state, **progress)
            .returning(LearningJobRow).execution_options(synchronize_session=False, populate_existing=True))).scalars().one()
        await _apply_promotion(s, token, decided.promote)
        if decided.follow_ons.arm_check_clock:
            await arm_learning_check(s, tenant_id, mark_held=True)
        if retry:
            s.add(LearningJobRow(
                id=LearningJobId.mint(), tenant_id=row.tenant_id, alert_id=row.alert_id,
                investigation_id=row.investigation_id, request_key=row.request_key, attempt=row.attempt + 1,
                trigger=row.trigger, status="queued", created_at=row.created_at))
            await arm_learning_check(s, tenant_id)
        record = learning_job_record(done)
        detail = (f"status={record.status}" + (f" reason={reason}" if reason else "")
                  + (f" findings={record.publish_state}" if record.status == "completed" else "")
                  + (f" added={added}" if added is not None else ""))
        return _Applied(record, ("learning_job.finish", detail))

    async def _apply_host_request(self, s: AsyncSession, tenant_id: str, owner_id: str,
                                  decision: ending.Decision | _Deferred) -> _Applied | None:
        row = (await s.execute(
            select(HostRequestRow).where(HostRequestRow.tenant_id == tenant_id, HostRequestRow.id == owner_id,
                                         _ending_fence(HostRequestRow.stage, None, decision))
            .with_for_update().execution_options(populate_existing=True))).scalars().first()
        if row is None:
            return None
        token = await _claim_token(s, ClaimRow.host_request_id, owner_id)
        decided = await _decision_under_lock(s, token, decision)
        if isinstance(decided, ending.HandBack):  # never decided: a host request is not handed back
            raise ValueError("a host request is never handed back")
        result = decided.result if decided.stage == "completed" else None
        done = (await s.execute(
            update(HostRequestRow).where(HostRequestRow.id == owner_id)
            .values(stage=decided.stage, finished_at=self._clock(), lease_expires_at=None,
                    result=dict(result) if isinstance(result, Mapping) else result,
                    failure_reason=decided.failure_reason, failure_message=decided.failure_message)
            .returning(HostRequestRow).execution_options(synchronize_session=False, populate_existing=True))).scalars().one()
        record = host_request_record(done)
        detail = f"status={record.stage}" + (f" reason={record.failure_reason}" if record.failure_reason else "")
        return _Applied(record, (f"{record.kind}.finish", detail))

    # --- the worker's writes before #1546 (kept for their callers; each goes through `apply`) ----------------------------

    async def finish(  # noqa: PLR0913 — the one terminal write: stage, figures, knowledge and failure detail
        self, tenant_id: TenantId, investigation_id: InvestigationId, *, stage: str, disposition: str | None = None,
        cost_usd: float | None = None, cost_is_lower_limit: bool = False, knowledge: dict[str, Any] | None = None,
        failure_reason: str | None = None, failure_message: str | None = None,
    ) -> InvestigationRecord | None:
        """Record the one terminal stage of a running investigation as stated, with its final cost (null when unknown)
        and knowledge, and the accounting mark, through `apply` (`ending.stated`: evidence `none`, scrub `not_run`, no
        upload promoted, so a `completed` end copies its verdict to the alert and queues no learning job, #1546
        A-O7). Conditional on the row still being `running` and not handed back (the fence): `None` when it changed
        nothing. A refusal of the schema raises (D10)."""
        if not is_terminal(stage):
            raise ValueError(f"{stage!r} is not a terminal stage")
        record = await self.apply(tenant_id, investigation_id, ending.stated(
            ending.INVESTIGATION, stage, disposition=disposition, cost_usd=cost_usd,
            cost_is_lower_limit=cost_is_lower_limit, knowledge=knowledge, failure_reason=failure_reason,
            failure_message=failure_message, scrub="not_run"))
        return None if record is None else _as(InvestigationRecord, record)

    # --- the holder's lease (#1343) ---------------------------------------------------------------------------------------

    async def renew(
        self, held: Collection[str], *, costs: Mapping[str, float] | None = None,
        progress: Mapping[str, LearningProgress] | None = None, checks: Collection[str] = (),
    ) -> list[str]:
        """Extend the lease of every held row, investigation, learning job or host request (#1471), that is still
        `running` and not yet handed back, in one transaction, and return the ids it covered. A
        held row missing from the answer was cancelled, taken over or deleted (B3). `costs` copies
        a cost-so-far figure onto the investigations it names (B2), `progress` the job entry's
        progress onto the learning jobs it names (#1344 O13); a covered row without one keeps its
        values. `checks` names check-clock holds by their holder tokens (amendment 3): each one
        still held is extended and its token returned with the ids. Late renewals of a lapsed row
        nobody took over succeed (B1)."""
        ids = set(held)
        holders = set(checks)
        if not ids and not holders:
            return []
        figures = {i: c for i, c in (costs or {}).items() if i in ids}
        cost = (case(*((InvestigationRow.id == i, c) for i, c in figures.items()), else_=InvestigationRow.cost_usd)
                if figures else InvestigationRow.cost_usd)
        async with self._tx() as s:
            # Rows are locked in id order before they are updated (#1360 D9): one UPDATE locks in plan order, which
            # could cross another transaction that takes several of them in id order, the offboard.
            covered = (await s.execute(
                update(InvestigationRow).where(
                    InvestigationRow.id.in_(_locked_in_id_order(InvestigationRow.id, InvestigationRow.id.in_(ids),
                                                                InvestigationRow.stage == "running",
                                                                InvestigationRow.accounting_written_at.is_(None))),
                    InvestigationRow.stage == "running", InvestigationRow.accounting_written_at.is_(None))
                .values(lease_expires_at=self._lease_end(), cost_usd=cost)
                .returning(InvestigationRow.id).execution_options(synchronize_session=False))).scalars().all() \
                if ids else []
            found = [str(i) for i in covered]
            rest = ids - set(found)
            if rest:
                found += [str(i) for i in (await s.execute(
                    update(LearningJobRow).where(
                        LearningJobRow.id.in_(_locked_in_id_order(
                            LearningJobRow.id, LearningJobRow.id.in_(rest), LearningJobRow.status == "running",
                            LearningJobRow.finished_at.is_(None))),
                        LearningJobRow.status == "running", LearningJobRow.finished_at.is_(None))
                    .values(lease_expires_at=self._lease_end(),
                            **_progress_values({i: p for i, p in (progress or {}).items() if i in rest}))
                    .returning(LearningJobRow.id).execution_options(synchronize_session=False))).scalars().all()]
            rest = ids - set(found)
            if rest:
                found += await self._renew_host_requests(s, rest)
            if holders:
                found += [str(h) for h in (await s.execute(
                    update(LearningCheckRow).where(LearningCheckRow.holder.in_(holders))
                    .values(checking_until=self._lease_end())
                    .returning(LearningCheckRow.holder).execution_options(synchronize_session=False))).scalars().all()]
        return found

    async def _renew_host_requests(self, s: AsyncSession, ids: Collection[str]) -> list[str]:
        """The running host requests among `ids` given a fresh lease, locked in id order (#1360 D9); their ids."""
        renewed = (await s.execute(
            update(HostRequestRow).where(
                HostRequestRow.id.in_(_locked_in_id_order(HostRequestRow.id, HostRequestRow.id.in_(ids),
                                                          HostRequestRow.stage == "running")),
                HostRequestRow.stage == "running")
            .values(lease_expires_at=self._lease_end())
            .returning(HostRequestRow.id).execution_options(synchronize_session=False))).scalars().all()
        return [str(i) for i in renewed]

    # --- take-over (#1343 B6, B7) -------------------------------------------------------------------------------------------

    async def take_over(self, *, held: Collection[str] = frozenset()) -> list[str]:
        """One pass of take-over (B6, B7), over investigations, learning jobs (#1344 O6) and host requests (#1471)
        alike: every `running` row whose lease has lapsed and that the caller does not hold (B-P3) is ended through
        `apply` by the ordinary rules (#1546 D8-D10): a row that decided keeps its verdict and evidence state, and is
        not retried; an undecided one fails (`lease_lapsed`) with evidence `none` and, below the third attempt, is
        retried (a new `queued` row, attempt + 1; a learning job's retry keeps its original's `created_at`), the third
        attempt ending `retry_cap`. A lapsed host request is decided by its staged `result`, else `failed`/
        `worker_lost`, and is never retried (B2). One transaction per row, the tenant's row share-locked first, the row
        `SKIP LOCKED`. Returns the ids taken over. A row whose take-over the schema refuses rolls back whole and is
        left for the next pass."""
        taken: list[str] = []
        for kind in (ending.INVESTIGATION, ending.LEARNING, ending.HOST_REQUEST):
            passed_over: set[str] = set(held)
            while (outcome := await self._take_over_next(kind, passed_over)) is not None:
                passed_over.add(outcome.old_id)
                if outcome.refused:
                    _logger.warning("the take-over of %s was refused by the schema; it is left for the next pass",
                                    outcome.old_id)
                    continue
                if not outcome.reason:  # held by another transaction, or ended meanwhile
                    continue
                taken.append(outcome.old_id)
                announce(f"{outcome.kind}.takeover", actor=SYSTEM, tenant_id=outcome.tenant_id,  # type: ignore[arg-type]
                         target=outcome.old_id, detail=f"reason={outcome.reason}")
                if outcome.retry_id is not None:
                    announce(f"{outcome.kind}.retry", actor=SYSTEM, tenant_id=outcome.tenant_id,  # type: ignore[arg-type]
                             target=outcome.retry_id)
        return taken

    async def _take_over_next(self, kind: str, passed_over: Collection[str]) -> _TakeOver | None:
        """Take over the oldest lapsed row of `kind` not passed over, in its own transaction; `None` when there is none.
        A row another transaction holds is passed over with no reason."""
        table = _TABLES[kind]
        running = _status_of(table) == "running"
        old_id = tenant = ""
        try:
            async with self._tx() as s:
                found = (await s.execute(
                    select(table.id, table.tenant_id).where(running, table.lease_expires_at < func.now(),
                                                            table.id.notin_(passed_over))
                    .order_by(table.lease_expires_at, table.id).limit(1))).first()
                if found is None:
                    return None
                old_id, tenant = str(found.id), str(found.tenant_id)
                await share_tenant(s, TenantId(tenant))  # before the row, as every ender (#1360 Flow 2)
                locked = (await s.execute(
                    select(table.id).where(table.id == old_id, running, table.lease_expires_at < func.now())
                    .with_for_update(skip_locked=True))).first()
                if locked is None:
                    return _TakeOver(old_id, tenant, "", None)
                record = await self.apply(tenant, old_id, _Deferred(kind, ending.Lapsed()), session=s)
                if record is None:
                    return _TakeOver(old_id, tenant, "", None)
                audit, reason, retry_id = await _take_over_report(s, record)
        except _Refused:
            return _TakeOver(old_id, tenant, "", None, refused=True)
        return _TakeOver(old_id, tenant, reason, retry_id, kind=audit)

    # --- learning jobs (#1344) ------------------------------------------------------------------

    async def create_learning_job(
        self, tenant_id: TenantId, investigation_id: InvestigationId, client_request_id: str, *, actor: str,
        credential_id: str | None = None,
    ) -> tuple[LearningJobRecord, bool]:
        """Queue an explicit re-learn of a `completed` investigation whose evidence is `complete`, or answer the job
        this request already has: the latest attempt under `(investigation, client request id)` (O11).
        `created` only when this call inserted the row. `UnknownReference` for an investigation
        this tenant lacks; `Conflict` for one that did not end `completed`, for one whose evidence is not `complete`
        (#1546 A-O7: its bundle is the job's input), and for a request id carrying the auto jobs' reserved prefix; and,
        when a new job is due, for a tenant that is offboarding or offboarded (#1360 O4). The source row is read under
        a share lock held to the commit, so the retention sweep's expiry of it waits for this insert, and this insert
        waits for an expiry in progress and then reads `expired`."""
        _refuse_unstorable_text(client_request_id=client_request_id)
        if client_request_id.startswith(AUTO_REQUEST_KEY_PREFIX):
            raise Conflict(f"a client request id may not start with {AUTO_REQUEST_KEY_PREFIX!r}, the auto jobs' prefix")
        async with self._tx() as s:
            state = await share_tenant(s, tenant_id)  # the tenant row first, as every outside create (#1360 Flow 2)
            named = await self._row(s, tenant_id, investigation_id)
            if named is None:
                raise UnknownReference(f"no investigation {investigation_id!r}")
            # The alert lock serializes this with the investigation delete, which takes it first.
            await s.execute(select(AlertRow.id).where(
                AlertRow.tenant_id == tenant_id, AlertRow.id == named.alert_id).with_for_update())
            named = (await s.execute(
                select(InvestigationRow).where(InvestigationRow.tenant_id == tenant_id,
                                               InvestigationRow.id == investigation_id)
                .with_for_update(read=True).execution_options(populate_existing=True))).scalars().first()
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
            if named.evidence_state != "complete":
                raise Conflict(f"only an investigation whose evidence is complete can be learned from; this one's is "
                               f"{named.evidence_state}")
            _refuse_removed(state, tenant_id)
            row = LearningJobRow(
                id=LearningJobId.mint(), tenant_id=tenant_id, alert_id=named.alert_id, investigation_id=named.id,
                request_key=client_request_id, attempt=1, trigger="explicit", status="queued",
                created_at=func.now())  # its queue age is the database's clock, the expiry's (#1546 D10)
            s.add(row)
            await s.flush()
            await s.refresh(row, ["created_at"])
            await arm_learning_check(s, tenant_id)
            record = learning_job_record(row)
        announce("learning_job.start", actor=actor, tenant_id=tenant_id, target=record.learning_job_id,
                 detail=f"investigation {investigation_id}; trigger=explicit", credential_id=credential_id)
        return record, True

    async def get_learning_job(self, tenant_id: TenantId, learning_job_id: LearningJobId) -> LearningJobRecord | None:
        """The tenant's learning job, `None` for one it does not have."""
        async with self._tx() as s:
            row = (await s.execute(select(LearningJobRow).where(
                LearningJobRow.tenant_id == tenant_id, LearningJobRow.id == learning_job_id))).scalars().first()
        return None if row is None else learning_job_record(row)

    async def list_learning_jobs(
        self, tenant_id: TenantId, *, investigation_id: InvestigationId | None, after: tuple[_dt.datetime, str] | None,
        limit: int,
    ) -> list[LearningJobRecord]:
        """Up to `limit` of the tenant's learning jobs (of one investigation when `investigation_id` is given), newest
        first by `(created_at, id)` descending, strictly after the position `after` when given."""
        query = select(LearningJobRow).where(LearningJobRow.tenant_id == tenant_id)
        if investigation_id is not None:
            query = query.where(LearningJobRow.investigation_id == investigation_id)
        query = newest_first_query(query, LearningJobRow.created_at, LearningJobRow.id, after, limit)
        async with self._tx() as s:
            rows: Sequence[Any] = (await s.execute(query)).scalars().all()
        return [learning_job_record(row) for row in rows]

    async def claim_learning_job(self) -> LearningClaim | None:
        """Move the oldest queued learning job (by `created_at`, ties by id) to `running`, with
        its tenant's state read in the same transaction, or `None`. Every first attempt older than
        the age limit by the database's clock is ended `skipped`/`expired` first, through `apply` (evidence `none`), in
        the same transaction (D4); a retry is exempt. A row another transaction holds is skipped, never waited for. The claim's token is
        minted with its claim row (#1546 PR7): its one input is its source's bundle, its launch facts carry the
        source's knowledge pin."""
        now = self._clock()
        message = (f"it waited in the queue longer than the age limit "
                   f"({self._learning_max_age.total_seconds():g} s) before a learning slot reached it")
        claim: LearningClaim | None = None
        expired: list[tuple[str, str]] = []
        async with self._tx() as s:
            too_old = (await s.execute(
                select(LearningJobRow.id, LearningJobRow.tenant_id)
                .where(LearningJobRow.status == "queued", LearningJobRow.attempt == 1,
                       LearningJobRow.created_at < func.now() - self._learning_max_age)
                .order_by(LearningJobRow.id).with_for_update(skip_locked=True))).all()
            for job_id, tenant_id in too_old:
                if await self.apply(str(tenant_id), str(job_id),
                                    _Deferred(ending.LEARNING, ending.ExpiredInQueue(message)), session=s) is not None:
                    expired.append((str(job_id), str(tenant_id)))
            # Only the id is read here, never the row as an entity: the claim's UPDATE ... RETURNING
            # below must hand back the row as it now stands, and an entity already in the session
            # would be returned as loaded, still `queued`.
            picked = (await s.execute(
                select(LearningJobRow.id).where(LearningJobRow.status == "queued")
                .order_by(LearningJobRow.created_at, LearningJobRow.id).limit(1)
                .with_for_update(skip_locked=True))).scalar()
            if picked is not None:
                claimed = (await s.execute(
                    update(LearningJobRow).where(LearningJobRow.id == picked, LearningJobRow.status == "queued")
                    .values(status="running", started_at=now, lease_expires_at=self._lease_end())
                    .returning(LearningJobRow).execution_options(synchronize_session=False, populate_existing=True))).scalars().one()
                record = learning_job_record(claimed)
                state = (await s.execute(
                    select(TenantRecord.state).where(TenantRecord.id == record.tenant_id))).scalar_one()
                knowledge = (await s.execute(select(InvestigationRow.knowledge).where(
                    InvestigationRow.id == record.investigation_id))).scalar()
                pin = knowledge.get("commit") if isinstance(knowledge, dict) else None
                token = _mint(s, record.tenant_id, LEARNING_CLAIM, learning_job_id=record.learning_job_id,
                              inputs=[{"owner": record.investigation_id, "object": ending.BUNDLE}],
                              launch={"source": record.investigation_id, "knowledge_commit": pin})
                claim = with_token(LearningClaim(record=record, tenant_state=state), token)
        for ended_id, ended_tenant in expired:
            announce("learning_job.finish", actor=SYSTEM, tenant_id=ended_tenant, target=ended_id,
                     detail=f"status=skipped reason={EXPIRED}")
        if claim is not None:
            announce("learning_job.claim", actor=SYSTEM, tenant_id=claim.record.tenant_id,
                     target=claim.record.learning_job_id)
        return claim

    async def create_readiness(
        self, tenant_id: TenantId, *, actor: str, credential_id: str | None = None,
    ) -> tuple[HostRequestRecord, bool]:
        """Queue a readiness check of the tenant, or answer the one already queued for it (R1): `created` only when this
        call inserted the row. See `_create_host_request`."""
        return await self._create_host_request(tenant_id, READINESS, None, actor=actor, credential_id=credential_id)

    async def create_adoption(
        self, tenant_id: TenantId, system_id: str, *, actor: str, credential_id: str | None = None,
    ) -> tuple[HostRequestRecord, bool]:
        """Queue an adoption of the system's base files, or answer the one already queued for this tenant and system
        (A1). The caller has checked the system's record and catalog entry. See `_create_host_request`."""
        return await self._create_host_request(tenant_id, ADOPTION, system_id, actor=actor, credential_id=credential_id)

    async def create_drain(
        self, tenant_id: TenantId, *, actor: str, credential_id: str | None = None,
    ) -> tuple[HostRequestRecord, bool]:
        """Queue a drain of the tenant's lead lane (the operator command's call, #1546 D7), or answer the one already
        queued or running for it: at most one live drain per tenant (the database's partial unique index), never
        retried. `created` only when this call inserted the row. See `_create_host_request`."""
        return await self._create_host_request(tenant_id, DRAIN, None, actor=actor, credential_id=credential_id)

    async def _create_host_request(
        self, tenant_id: TenantId, kind: str, system_id: str | None, *, actor: str, credential_id: str | None,
    ) -> tuple[HostRequestRecord, bool]:
        """One request of `kind`, deduped on its key while queued: the tenant (readiness, drain) or `<tenant>/<system>`
        (adoption; `/` is no record id's character); a drain is deduped while queued or running. The tenant's row is
        share-locked first (#1360 Flow 2), so an offboard that wrote first is seen here and refused with `Conflict`
        naming the state, and an offboard after it ends the row this made. The insert decides `created` (the unique
        indexes): of two racing starts one inserts and the other answers its row. A running or ended row dedupes nothing
        but a running drain (R1, B2, D7). `UnknownReference` for a tenant with no row; `UnstorableText` for text
        PostgreSQL cannot hold. Announced `<kind>.start` after the commit, an adoption's naming its system; a replay
        announces nothing."""
        _refuse_unstorable_text(requester=actor, **({} if system_id is None else {"system_id": system_id}))
        key = str(tenant_id) if system_id is None else f"{tenant_id}/{system_id}"
        dedupes = (HostRequestRow.stage.in_(HOST_REQUEST_LIVE) if kind == DRAIN else HostRequestRow.stage == "queued")
        for _ in range(_HOST_CREATE_TRIES):
            async with self._tx() as s:
                state = await share_tenant(s, tenant_id)
                if state is None:
                    raise UnknownReference(f"no tenant {tenant_id!r}")
                _refuse_removed(state, tenant_id)
                made = (await s.execute(
                    pg_insert(HostRequestRow).values(
                        id=HostRequestId.mint(), tenant_id=tenant_id, kind=kind, dedupe_key=key, system_id=system_id,
                        requester=actor, created_at=self._clock(), stage="queued")
                    .on_conflict_do_nothing()
                    .returning(HostRequestRow.id))).scalar()
                picked = made if made is not None else (await s.execute(select(HostRequestRow.id).where(
                    HostRequestRow.kind == kind, HostRequestRow.dedupe_key == key, dedupes))).scalar()
                row = None if picked is None else (await s.execute(
                    select(HostRequestRow).where(HostRequestRow.id == picked))).scalars().one()
            if row is None:  # the live row the insert met moved before it could be read: try again
                continue
            record = host_request_record(row)
            if made is None:
                return record, False
            announce(f"{kind}.start", actor=actor, tenant_id=tenant_id, target=record.request_id,  # type: ignore[arg-type]
                     detail=None if system_id is None else f"system {system_id}", credential_id=credential_id)
            return record, True
        raise Conflict(f"the {kind} request could not be queued: the queued one kept being claimed; try again")

    async def get_host_request(self, tenant_id: TenantId, request_id: str, *, kind: str) -> HostRequestRecord | None:
        """The tenant's host request of `kind`; `None` for an unknown id, another tenant's or the other kind's (R2)."""
        async with self._tx() as s:
            row = (await s.execute(select(HostRequestRow).where(
                HostRequestRow.tenant_id == tenant_id, HostRequestRow.id == request_id,
                HostRequestRow.kind == kind))).scalars().first()
        return None if row is None else host_request_record(row)

    async def claim_host_request(self) -> HostRequestClaim | None:
        """Move the oldest queued host request of any kind (by `created_at`, ties by id; R13-6) to `running` with a
        lease, or `None`. The tenant's state is not read: the helper's own admission refuses a tenant that is not
        active. A row another transaction holds is skipped, never waited for. The claim's token is minted with its
        claim row (#1546 PR7), of the request's kind: a drain's input set is fixed here (`_drain_inputs`), every other kind
        has none. Announced `<kind>.claim`."""
        async with self._tx() as s:
            # The id only, never the row as an entity: the UPDATE ... RETURNING below must hand back the row as it now
            # stands (see `claim_learning_job`).
            picked = (await s.execute(
                select(HostRequestRow.id).where(HostRequestRow.stage == "queued")
                .order_by(HostRequestRow.created_at, HostRequestRow.id).limit(1)
                .with_for_update(skip_locked=True))).scalar()
            if picked is None:
                return None
            row = (await s.execute(
                update(HostRequestRow).where(HostRequestRow.id == picked, HostRequestRow.stage == "queued")
                .values(stage="running", started_at=self._clock(), lease_expires_at=self._lease_end())
                .returning(HostRequestRow).execution_options(synchronize_session=False))).scalars().first()
            if row is None:  # not reachable while this transaction holds the row; the compare-and-set is the contract
                return None
            record = host_request_record(row)
            inputs = await _drain_inputs(s, record.tenant_id) if record.kind == DRAIN else ()
            token = _mint(s, record.tenant_id, record.kind, host_request_id=record.request_id, inputs=inputs,
                          launch={"kind": record.kind, "system_id": record.system_id})
        announce(f"{record.kind}.claim", actor=SYSTEM, tenant_id=record.tenant_id,  # type: ignore[arg-type]
                 target=record.request_id)
        return with_token(HostRequestClaim(record=record), token)

    # --- the family-less check clock (#1344 amendment 3) ---------------------------------------

    async def claim_learning_check(self, interval: float) -> LearningCheckClaim | None:
        """Hold the most overdue tenant due a family-less check, or `None`: an `active` tenant whose clock is not idle,
        whose last post-step ended `interval` seconds ago or more, and that no post-step holds. The hold runs a lease
        and is named by the token minted here with its post-step claim row (#1546 PR7), which is the hold's `holder`;
        a row another transaction holds is skipped, never waited for, so two workers never hold one tenant."""
        due = (select(LearningCheckRow.tenant_id)
               .join(TenantRecord, TenantRecord.id == LearningCheckRow.tenant_id)
               .where(TenantRecord.state == "active", LearningCheckRow.idle.is_(False),
                      LearningCheckRow.checked_at <= func.now() - _dt.timedelta(seconds=interval),
                      _unheld())
               .order_by(LearningCheckRow.checked_at, LearningCheckRow.tenant_id).limit(1)
               .with_for_update(of=LearningCheckRow, skip_locked=True))
        token = _new_token()
        async with self._tx() as s:
            held = (await s.execute(
                update(LearningCheckRow).where(LearningCheckRow.tenant_id == due.scalar_subquery())
                .values(checking_until=self._lease_end(), holder=token, armed_while_held=False)
                .returning(LearningCheckRow.tenant_id).execution_options(synchronize_session=False))).scalar()
            if held is None:
                return None
            _mint(s, TenantId(str(held)), POST_STEP_CLAIM, hold_tenant_id=TenantId(str(held)), token=token)
        return LearningCheckClaim(tenant_id=TenantId(str(held)), token=token)

    async def hold_learning_check(self, tenant_id: str) -> str | None:
        """Hold the tenant's check clock for a job's own post-step, under a token minted here with its post-step claim
        row (#1546 PR7), the hold's `holder`; answers the token, or `None` when another post-step holds it. The clock
        is armed either way: the holder's end then finds the job's findings not handed to it and makes the tenant due
        at once. Refused (`None`, the clock not armed) for a tenant that is offboarding or offboarded: nothing new
        starts for a tenant being removed (#1360 O6)."""
        token = _new_token()
        async with self._tx() as s:
            state = (await s.execute(select(TenantRecord.state).where(TenantRecord.id == tenant_id))).scalar()
            if state in _BEING_REMOVED:
                return None
            await arm_learning_check(s, tenant_id)
            held = (await s.execute(
                update(LearningCheckRow).where(LearningCheckRow.tenant_id == tenant_id, _unheld())
                .values(checking_until=self._lease_end(), holder=token, armed_while_held=False)
                .returning(LearningCheckRow.tenant_id).execution_options(synchronize_session=False))).scalar()
            if held is None:
                return None
            _mint(s, TenantId(tenant_id), POST_STEP_CLAIM, hold_tenant_id=TenantId(tenant_id), token=token)
        return token

    async def end_learning_check(self, tenant_id: str, holder: str, *, idle: bool) -> bool:
        """`holder`'s post-step of the tenant ended: the hold is let go and the clock restarts now,
        idle as `idle` says (the worker's answer to "is work still waiting", Flow 3). A job that
        ended `completed` while the hold stood (its mark, #1487 O7) makes the tenant due at once
        instead, never idle, and the mark is spent: read and written in one statement on the
        locked row. False, changing nothing, when the hold is no longer `holder`'s."""
        marked = LearningCheckRow.armed_while_held
        async with self._tx() as s:
            ended = (await s.execute(
                update(LearningCheckRow).where(LearningCheckRow.tenant_id == tenant_id,
                                               LearningCheckRow.holder == holder)
                .values(checked_at=case((marked, literal(_DUE_AT_ONCE)), else_=func.now()),
                        idle=case((marked, false()), else_=literal(idle)), armed_while_held=False,
                        checking_until=None, holder=None)
                .returning(LearningCheckRow.tenant_id).execution_options(synchronize_session=False))).scalar()
        return ended is not None



async def _store_findings(s: AsyncSession, tenant_id: str, job_id: str, state: str | None,
                          findings: Mapping[str, Sequence[Mapping[str, Any]]] | None) -> tuple[str, int | None]:
    """A `completed` end's findings, in its transaction after the fence (#1487 Flow 1 step 3): the row's publish state
    and how many rows the insert added (`None` when refused; the row keeps no count, #1589). Stored only for an `active` tenant (its state as the share lock read it) and findings the worker
    accepted; anything else, or a refusal at the insert, is `refused`, logged with the job and the refusal's kind.
    An outage at the insert raises."""
    from .learning_models import insert_findings  # the learning store's tables load only for a learning job's end

    if findings is None:
        kind = "refused by the worker"  # the worker logged why
    elif state != "active":
        kind = f"tenant {state or 'absent'}"
    else:
        inserted = await insert_findings(s, tenant_id, findings, source_run=job_id)
        if inserted.stored:
            return "done", inserted.added
        kind = f"refused at the insert: {inserted.why}"
    if findings is not None:
        _logger.warning("learning job %s: its findings are refused (%s); the job ends completed and none of them is "
                        "stored", job_id, kind)
    return "refused", None


def _locked_in_id_order(column: Any, *where: Any) -> Any:
    """A subquery of the ids matching `where`, each row locked, in id order (#1360 D9): one UPDATE would lock in plan
    order, which could cross another transaction that takes several of these rows in id order, the offboard."""
    return select(column).where(*where).order_by(column).with_for_update().scalar_subquery()


def _refuse_removed(state: str | None, tenant_id: str) -> None:
    """`Conflict` naming the state, for a tenant that is offboarding or offboarded (#1360 O4, D7)."""
    if state in _BEING_REMOVED:
        raise Conflict(f"tenant {tenant_id} is {state}; it takes no new job")


def _progress_values(progress: Mapping[str, LearningProgress]) -> dict[str, Any]:
    """The `renew` values that copy each named job's progress onto its row; none, none copied."""
    if not progress:
        return {}

    def per_row(field: str) -> Any:
        column = getattr(LearningJobRow, field)
        return case(*((LearningJobRow.id == i, getattr(p, field)) for i, p in progress.items()), else_=column)

    return {field: per_row(field) for field in ("fork_message_id", "stage", "sibling_cost_usd")}


#: The one staged fact a helper replaces; every other is create-once (#1546 staged facts).
PROGRESS_FACT = "progress"
_TABLES: Mapping[str, Any] = {ending.INVESTIGATION: InvestigationRow, ending.LEARNING: LearningJobRow,
                              ending.HOST_REQUEST: HostRequestRow}
_CLAIMED_TABLE: Mapping[str, Any] = {INVESTIGATION_CLAIM: InvestigationRow, LEARNING_CLAIM: LearningJobRow,
                                     **{kind: HostRequestRow for kind in HOST_REQUEST_KINDS}}


@dataclasses.dataclass(frozen=True)
class _Deferred:
    """What ended a row, for `apply` to decide under the row's lock from the claim's staged facts and uploads: the
    store's own enders (cancel, offboard, take-over, queue expiry) know no more."""

    kind: str
    ended_by: ending.EndedBy


@dataclasses.dataclass(frozen=True)
class _Applied:
    """What `apply` wrote: the row as it now stands, and the audit event its own transaction announces after commit."""

    record: InvestigationRecord | LearningJobRecord | HostRequestRecord
    announce: tuple[str, str] | None = None


def _status_of(table: Any) -> Any:
    return LearningJobRow.status if table is LearningJobRow else table.stage


def _new_token() -> str:
    return secrets.token_hex(16)


def _mint(s: AsyncSession, tenant_id: TenantId, kind: str, *, inputs: Sequence[Mapping[str, Any]] = (),
          launch: Mapping[str, Any] | None = None, token: str | None = None, **reference: Any) -> str:
    """Write the claim row of a child about to launch, in the claim's own transaction (#1546 PR7: the store is the one
    minter), naming exactly its kind's reference; answers its token."""
    token = token or _new_token()
    s.add(ClaimRow(token=token, tenant_id=tenant_id, kind=kind, inputs=[dict(i) for i in inputs],
                   launch=None if launch is None else dict(launch), created_at=func.now(), **reference))
    return token


async def _investigation_launch(s: AsyncSession, record: InvestigationRecord) -> dict[str, Any]:
    """An investigation's launch facts (#1546 PR7): the launch record its helper copies into the job's root (the row, its
    tenant and alert, the alert's digest and label as stored at the claim, and the run box's start token, r5 C1), with the
    attempt. The alert is the row's foreign key, never deleted while the row lives."""
    alert = (await s.execute(select(AlertRow.raw, AlertRow.title, AlertRow.vendor_ticket_id).where(
        AlertRow.tenant_id == record.tenant_id, AlertRow.id == record.alert_id))).first()
    launch: dict[str, Any] = {"investigation_id": str(record.investigation_id), "tenant_id": str(record.tenant_id),
                              "alert_id": str(record.alert_id), "attempt": record.attempt, "box_token": _new_token()}
    if alert is not None:
        raw, title, ticket = alert
        launch.update(digest=digest_of(bytes(raw)), label=title or ticket)
    return launch


async def _drain_inputs(s: AsyncSession, tenant_id: TenantId) -> list[dict[str, str]]:
    """A drain's input set, fixed in its claim's transaction (#1546 D7, amendment r9 "Drain"): the bundle of each run the
    tenant's open curation requests name (the lead lane's only run-naming kind) whose investigation is `clean` and not
    `expired`. A request whose run is outside the set waits for the next drain; one whose run is unusable is dead."""
    from .learning_models import curation_request_runs  # the learning store's tables load only for a drain's claim

    named = curation_request_runs(str(tenant_id))
    owners = (await s.execute(
        select(InvestigationRow.id).where(
            InvestigationRow.tenant_id == tenant_id, sql_cast(InvestigationRow.id, Text).in_(named), _usable_run())
        .order_by(InvestigationRow.id))).scalars().all()
    return [{"owner": str(owner), "object": ending.BUNDLE} for owner in owners]


def _usable_run() -> Any:
    """An investigation a drain may take as an input (#1546 PR6): `clean` and not `expired` (`run_unusable` is its
    complement)."""
    return and_(InvestigationRow.scrub == "clean", InvestigationRow.evidence_state.is_distinct_from("expired"))


async def _live_claim(s: AsyncSession, token: str) -> ClaimRow | None:
    """The claim `token` when it is live, its reference read under a share lock held to the caller's commit: the row has
    not ended (queued or running), or the hold still names the token. A writer racing an ender that holds the row waits
    for it and then reads its end (PR7: liveness under the row's lock, not read-then-write)."""
    claim = (await s.execute(select(ClaimRow).where(ClaimRow.token == token))).scalars().first()
    if claim is None:
        return None
    if claim.kind == POST_STEP_CLAIM:
        query = select(LearningCheckRow.tenant_id).where(LearningCheckRow.tenant_id == claim.hold_tenant_id,
                                                         LearningCheckRow.holder == token)
    else:
        table = _CLAIMED_TABLE[claim.kind]
        query = select(table.id).where(table.id == getattr(claim, CLAIM_REFERENCE[claim.kind]),
                                       _status_of(table).in_(_LEARNING_LIVE))
    return claim if (await s.execute(query.with_for_update(read=True))).first() is not None else None


async def _require_live(s: AsyncSession, token: str) -> None:
    if await _live_claim(s, token) is None:
        raise Conflict("the claim is unknown or no longer live; nothing is written under it")


async def _staged_under(s: AsyncSession, token: str | None) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if token is None:
        return {}, {}
    facts: dict[str, Any] = {str(name): body for name, body in (await s.execute(
        select(StagedFactRow.name, StagedFactRow.body).where(StagedFactRow.token == token))).all()}
    uploads: dict[str, dict[str, Any]] = {obj: {"status": status, "scrub": scrub} for obj, status, scrub in (await s.execute(
        select(UploadRow.object, UploadRow.status, UploadRow.scrub).where(UploadRow.token == token))).all()}
    return facts, uploads


async def _claim_token(s: AsyncSession, column: Any, owner_id: str) -> str | None:
    """The token of the one claim naming the row, `None` for a row never claimed."""
    return (await s.execute(select(ClaimRow.token).where(column == owner_id))).scalar()


async def _decision_under_lock(s: AsyncSession, token: str | None, decision: ending.Decision | _Deferred) -> ending.Decision:
    if not isinstance(decision, _Deferred):
        return decision
    facts, uploads = await _staged_under(s, token)
    return ending.decide(facts, uploads, decision.ended_by, kind=decision.kind)


def _ending_fence(status: Any, mark: Any, decision: ending.Decision | _Deferred) -> Any:
    """The state the row must be in for this ending: queued or running for a cancel or an offboard, queued for a queue
    expiry, running for a take-over, running and not handed back (`mark` unset) for a helper's end or a hand-back."""
    by = None if isinstance(decision, ending.HandBack) else decision.ended_by
    if isinstance(by, ending.Cancelled | ending.Offboarded):
        return status.in_(_LEARNING_LIVE)
    if isinstance(by, ending.ExpiredInQueue):
        return status == "queued"
    if isinstance(by, ending.Lapsed) or mark is None:
        return status == "running"
    return (status == "running") & mark.is_(None)


def _apply_lapse_words(decided: ending.End, attempt: int, handed_back: bool) -> tuple[str | None, str | None, bool]:
    """`(reason, message, retried)`: a take-over of an undecided row says whether its worker handed it back or was lost
    (B11) and is retried below the attempt cap (`retry_cap` at it, B6); every other ending keeps its own words."""
    if not (isinstance(decided.ended_by, ending.Lapsed) and decided.failure_reason == LEASE_LAPSED):
        return decided.failure_reason, decided.failure_message, False
    capped = attempt >= MAX_ATTEMPTS
    why = "its worker stopped and handed it back" if handed_back else "its worker stopped renewing its lease"
    return (RETRY_CAP if capped else LEASE_LAPSED,
            why + ("; the request used all its attempts" if capped else "; it is retried"), not capped)


def _apply_progress_values(decided: ending.End | ending.HandBack) -> dict[str, Any]:
    """A learning ending's family progress and sibling cost with its mark; none when the ending keeps the row's."""
    if decided.sibling_cost_usd is None:
        return {}
    return {"sibling_cost_usd": decided.sibling_cost_usd,
            "sibling_cost_is_lower_limit": decided.sibling_cost_is_lower_limit,
            "fork_message_id": decided.fork_message_id, "stage": decided.family_stage}


async def _apply_promotion(s: AsyncSession, token: str | None, objects: Sequence[str]) -> None:
    """Accept the claim's `uploaded` rows the ending names (A-O3: the applier alone; an accepted row never changes)."""
    if token is None or not objects:
        return
    await s.execute(
        update(UploadRow).where(UploadRow.token == token, UploadRow.object.in_(list(objects)),
                                UploadRow.status == "uploaded", UploadRow.accepted_at.is_(None))
        .values(accepted_at=func.now()).execution_options(synchronize_session=False))


async def _take_over_report(s: AsyncSession, record: Any) -> tuple[str, str, str | None]:
    """`(audit family, reason, retry id)` of a take-over's ending: its failure reason, or its stage when it decided."""
    if isinstance(record, HostRequestRecord):
        return record.kind, record.failure_reason or record.stage, None
    learning = isinstance(record, LearningJobRecord)
    reason = (record.reason or record.status) if learning else (record.failure_reason or record.stage)
    retry = None
    if reason == LEASE_LAPSED:
        table: Any = LearningJobRow if learning else InvestigationRow
        owner = (table.investigation_id == record.investigation_id) if learning else (table.alert_id == record.alert_id)
        retry = (await s.execute(select(table.id).where(
            table.tenant_id == record.tenant_id, owner, table.request_key == record.request_key,
            table.attempt == record.attempt + 1))).scalar()
    return ("learning_job" if learning else "investigation"), reason, None if retry is None else str(retry)


async def _delete_claims(s: AsyncSession, where: Any) -> None:
    """Delete the claims matching `where` with every fact and upload row staged under them."""
    tokens = list((await s.execute(select(ClaimRow.token).where(where))).scalars().all())
    if not tokens:
        return
    await s.execute(delete(UploadRow).where(UploadRow.token.in_(tokens)))
    await s.execute(delete(StagedFactRow).where(StagedFactRow.token.in_(tokens)))
    await s.execute(delete(ClaimRow).where(ClaimRow.token.in_(tokens)))


_R = TypeVar("_R")


def _as(kind: type[_R], record: object) -> _R:
    assert isinstance(record, kind), record
    return record
