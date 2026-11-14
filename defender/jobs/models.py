"""The job store's tables and the records it hands out. Every value is set in Python (no server
defaults). The alerts and investigations tables carry exactly the lean constraints of #1081's
design; the migration `0004_jobs` creates them and `0005_uuid_ids` makes their ids `uuid` (#1382).
The learning jobs and learning checks tables (#1344) are `0008_learning_jobs`'s."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import Any, Protocol

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKeyConstraint, Index, Integer, LargeBinary, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from defender._model import model
from defender.database import Base, IdColumn
from defender.records.formats import AlertId, InvestigationId, LearningJobId, TenantId
from defender.tenancy.models import SCHEMA as TENANCY_SCHEMA

SCHEMA = "jobs"

STAGES = ("queued", "running", "completed", "unparseable", "failed", "aborted")
#: Stages in which an investigation holds its alert: at most one per alert.
LIVE = ("queued", "running")
TERMINAL = tuple(stage for stage in STAGES if stage not in LIVE)

_TIME = DateTime(timezone=True)


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(repr(v) for v in values)


class AlertRow(Base, kw_only=True):
    __tablename__ = "alerts"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        # The target of investigations' composite key: an investigation cannot name another tenant's alert.
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("tenant_id", "vendor", "vendor_ticket_id"),
        Index("alerts_newest_first", "tenant_id", text("fired_at DESC"), text("id DESC")),
        {"schema": SCHEMA},
    )

    id: Mapped[AlertId] = mapped_column(IdColumn(AlertId), primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    vendor: Mapped[str] = mapped_column(Text)
    vendor_ticket_id: Mapped[str] = mapped_column(Text)
    fired_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    changed_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    received_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    #: Derived by the store from `raw` through the tenant's alert mapping when the alert is stored, and never rewritten
    #: by a later save of the mapping (#1345 O2, #1420); null when the tenant had no mapping then, or unmapped or unusable.
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[bytes] = mapped_column(LargeBinary)


class InvestigationRow(Base, kw_only=True):
    __tablename__ = "investigations"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "alert_id"], [f"{SCHEMA}.alerts.tenant_id", f"{SCHEMA}.alerts.id"]),
        UniqueConstraint("tenant_id", "alert_id", "request_key", "attempt"),
        CheckConstraint(f"stage IN ({_quoted(STAGES)})", name="stage"),
        CheckConstraint("stage <> 'running' OR lease_expires_at IS NOT NULL", name="running_has_a_lease"),
        CheckConstraint("NOT cost_is_lower_limit OR cost_usd IS NOT NULL", name="lower_limit_has_a_cost"),
        Index("investigations_one_live_per_alert", "tenant_id", "alert_id", unique=True,
              postgresql_where=text(f"stage IN ({_quoted(LIVE)})")),
        Index("investigations_newest_first", "tenant_id", text("created_at DESC"), text("id DESC")),
        {"schema": SCHEMA},
    )

    id: Mapped[InvestigationId] = mapped_column(IdColumn(InvestigationId), primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    alert_id: Mapped[AlertId] = mapped_column(IdColumn(AlertId))
    request_key: Mapped[str] = mapped_column(Text)
    attempt: Mapped[int] = mapped_column(Integer)
    stage: Mapped[str] = mapped_column(Text)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    started_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    finished_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    disposition: Mapped[str | None] = mapped_column(Text, default=None)
    #: Null only when unknown (a cost read that faulted); 0 until the end.
    cost_usd: Mapped[float | None] = mapped_column(Float, default=None)
    #: True when the cost is only a lower limit ("at least": spend may be missing from it, #1377 S2);
    #: never true beside a null cost (the table's check).
    cost_is_lower_limit: Mapped[bool] = mapped_column(Boolean, default=False)
    #: The API's mapped shape (`status`, `commit`, `stale_kind`), or null.
    knowledge: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), default=None)
    failure_reason: Mapped[str | None] = mapped_column(Text, default=None)
    failure_message: Mapped[str | None] = mapped_column(Text, default=None)
    #: When the holder's claim lapses (by the database's clock); a running row always has one (#1343 B1).
    lease_expires_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: When the holder wrote its final cost and knowledge: internal, written once (#1343 B-P2).
    accounting_written_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


LEARNING_STATUSES = ("queued", "running", "completed", "failed", "skipped")
LEARNING_TRIGGERS = ("auto", "explicit")
#: Whether a job's findings reached the queue (#1344): `none` until a `completed` end, then
#: `pending`; `done` once published; `refused` when they fail validation for good.
PUBLISH_STATES = ("none", "pending", "done", "refused")
LEARNING_TERMINAL = ("completed", "failed", "skipped")


class LearningJobRow(Base, kw_only=True):
    """One attempt of a learning job (#1344): attempts of one request share its request key and
    are numbered 1, 2, 3; a retry is a new row. The worker copies the job entry's progress record
    onto a running row and its end record onto the row it ends; nothing here is resumed from."""

    __tablename__ = "learning_jobs"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "alert_id"], [f"{SCHEMA}.alerts.tenant_id", f"{SCHEMA}.alerts.id"]),
        # No ON DELETE action: the investigation delete removes its jobs itself, under their row locks (O10).
        ForeignKeyConstraint(["investigation_id"], [f"{SCHEMA}.investigations.id"]),
        UniqueConstraint("tenant_id", "investigation_id", "request_key", "attempt"),
        CheckConstraint(f"status IN ({_quoted(LEARNING_STATUSES)})", name="status"),
        CheckConstraint(f"trigger IN ({_quoted(LEARNING_TRIGGERS)})", name="trigger"),
        CheckConstraint(f"publish_state IN ({_quoted(PUBLISH_STATES)})", name="publish_state"),
        CheckConstraint("status <> 'running' OR lease_expires_at IS NOT NULL", name="running_has_a_lease"),
        Index("learning_jobs_queued_by_age", "created_at", "id", postgresql_where=text("status = 'queued'")),
        Index("learning_jobs_running_by_lease", "lease_expires_at", "id", postgresql_where=text("status = 'running'")),
        Index("learning_jobs_by_investigation", "investigation_id"),
        Index("learning_jobs_newest_first", "tenant_id", text("created_at DESC"), text("id DESC")),
        {"schema": SCHEMA},
    )

    id: Mapped[LearningJobId] = mapped_column(IdColumn(LearningJobId), primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    alert_id: Mapped[AlertId] = mapped_column(IdColumn(AlertId))
    investigation_id: Mapped[InvestigationId] = mapped_column(IdColumn(InvestigationId))
    request_key: Mapped[str] = mapped_column(Text)
    attempt: Mapped[int] = mapped_column(Integer)
    trigger: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    #: The family step's progress, read-only (never resumed from).
    stage: Mapped[str | None] = mapped_column(Text, default=None)
    fork_message_id: Mapped[str | None] = mapped_column(Text, default=None)
    #: The siblings' own cost so far, then final: partial, without the questioner, oracle and judge (O13).
    sibling_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    publish_state: Mapped[str] = mapped_column(Text, default="none")
    started_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: Set at the end; on a `running` row, the mark of a hand-back, which no renewal covers.
    finished_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    reason: Mapped[str | None] = mapped_column(Text, default=None)
    message: Mapped[str | None] = mapped_column(Text, default=None)
    lease_expires_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


class LearningCheckRow(Base, kw_only=True):
    """A tenant's family-less check clock (#1344 amendment 3): when its last post-step ended (or
    when a queued job armed it), whether that post-step found nothing waiting, and which
    post-step holds it now, and until when. Times are the database's clock, as a lease's are."""

    __tablename__ = "learning_checks"
    __table_args__ = (
        # No ON DELETE action, as every jobs table (M10).
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), primary_key=True)
    checked_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    #: The last post-step found nothing waiting: no check is due until a job arms the row again.
    idle: Mapped[bool] = mapped_column(Boolean)
    #: A post-step of the tenant holds the row until then; renewed like a lease. NULL when none.
    checking_until: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: The hold's token, minted by the worker that took it: only it renews or lets go of the hold.
    holder: Mapped[str | None] = mapped_column(Text, default=None)


@model(frozen=True)
class StoredAlert:
    """An alert as read. `raw` is the exact bytes inserted."""

    alert_id: AlertId
    tenant_id: TenantId
    vendor: str
    vendor_ticket_id: str
    fired_at: _dt.datetime
    changed_at: _dt.datetime
    received_at: _dt.datetime
    title: str | None
    description: str | None
    raw: bytes


@model(frozen=True)
class InvestigationRecord:
    """An investigation as read: the wire model's fields, in the store's words."""

    investigation_id: InvestigationId
    tenant_id: TenantId
    alert_id: AlertId
    request_key: str
    attempt: int
    stage: str
    created_at: _dt.datetime
    started_at: _dt.datetime | None
    finished_at: _dt.datetime | None
    disposition: str | None
    cost_usd: float | None
    cost_is_lower_limit: bool
    knowledge: dict[str, Any] | None
    failure_reason: str | None
    failure_message: str | None


@dataclasses.dataclass(frozen=True)
class Claim:
    """A claimed investigation and its tenant's state, read in the claim's own transaction
    (#1342 r7 R7-1): the worker starts a job only for an `active` tenant."""

    record: InvestigationRecord
    tenant_state: str


@model(frozen=True)
class LearningJobRecord:
    """A learning job attempt as read."""

    learning_job_id: LearningJobId
    tenant_id: TenantId
    alert_id: AlertId
    investigation_id: InvestigationId
    request_key: str
    attempt: int
    trigger: str
    status: str
    stage: str | None
    fork_message_id: str | None
    sibling_cost_usd: float
    findings_count: int
    publish_state: str
    created_at: _dt.datetime
    started_at: _dt.datetime | None
    finished_at: _dt.datetime | None
    reason: str | None
    message: str | None


class LearningProgress(Protocol):
    """What the job entry's records say of a family step (its progress or end record, as
    `records.job_lane` reads them): the fork pick, the stage and the siblings' cost. The worker
    copies it onto the running row, and onto the row it ends."""

    @property
    def fork_message_id(self) -> str | None: ...

    @property
    def stage(self) -> str | None: ...

    @property
    def sibling_cost_usd(self) -> float: ...


@dataclasses.dataclass(frozen=True)
class LearningClaim:
    """A claimed learning job and its tenant's state, read in the claim's own transaction."""

    record: LearningJobRecord
    tenant_state: str


def learning_job_record(row: LearningJobRow) -> LearningJobRecord:
    return LearningJobRecord(
        learning_job_id=row.id, tenant_id=row.tenant_id, alert_id=row.alert_id, investigation_id=row.investigation_id,
        request_key=row.request_key, attempt=row.attempt, trigger=row.trigger, status=row.status, stage=row.stage,
        fork_message_id=row.fork_message_id, sibling_cost_usd=row.sibling_cost_usd,
        findings_count=row.findings_count, publish_state=row.publish_state, created_at=row.created_at,
        started_at=row.started_at, finished_at=row.finished_at, reason=row.reason, message=row.message)


def stored_alert(row: AlertRow) -> StoredAlert:
    return StoredAlert(
        alert_id=row.id, tenant_id=row.tenant_id, vendor=row.vendor, vendor_ticket_id=row.vendor_ticket_id,
        fired_at=row.fired_at, changed_at=row.changed_at, received_at=row.received_at, title=row.title,
        description=row.description, raw=bytes(row.raw))


def is_terminal(stage: str) -> bool:
    """Whether `stage` is one a row ends in (the one place that tests membership of `TERMINAL`)."""
    return stage in TERMINAL


def reads_at_least(row: InvestigationRow) -> bool:
    """Whether a record's cost reads "at least": the holder's stored mark, or a row that ended after it started with a cost
    and no final figure from its holder (cancelled or taken over mid-run, a copy that may be short). Derived on read, so
    ending a row never writes the mark and rows from before the column read the same way (#1377 B1, B2, B3)."""
    if row.cost_is_lower_limit:
        return True
    return (is_terminal(row.stage) and row.started_at is not None and row.accounting_written_at is None
            and row.cost_usd is not None)


def investigation_record(row: InvestigationRow) -> InvestigationRecord:
    return InvestigationRecord(
        investigation_id=row.id, tenant_id=row.tenant_id, alert_id=row.alert_id, request_key=row.request_key,
        attempt=row.attempt, stage=row.stage, created_at=row.created_at, started_at=row.started_at,
        finished_at=row.finished_at, disposition=row.disposition, cost_usd=row.cost_usd,
        cost_is_lower_limit=reads_at_least(row),
        knowledge=row.knowledge, failure_reason=row.failure_reason, failure_message=row.failure_message)
