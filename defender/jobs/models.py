"""The job store's tables and the records it hands out. Every value is set in Python (no server
defaults). The alerts and investigations tables carry exactly the lean constraints of #1081's
design; the migration `0004_jobs` creates them and `0005_uuid_ids` makes their ids `uuid` (#1382)."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKeyConstraint, Index, Integer, LargeBinary, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from defender._model import model
from defender.database import Base, IdColumn
from defender.records.formats import AlertId, InvestigationId, TenantId
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
        {"schema": SCHEMA},
    )

    id: Mapped[AlertId] = mapped_column(IdColumn(AlertId), primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    vendor: Mapped[str] = mapped_column(Text)
    vendor_ticket_id: Mapped[str] = mapped_column(Text)
    fired_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    changed_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    received_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    raw: Mapped[bytes] = mapped_column(LargeBinary)


class InvestigationRow(Base, kw_only=True):
    __tablename__ = "investigations"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "alert_id"], [f"{SCHEMA}.alerts.tenant_id", f"{SCHEMA}.alerts.id"]),
        UniqueConstraint("tenant_id", "alert_id", "request_key", "attempt"),
        CheckConstraint(f"stage IN ({_quoted(STAGES)})", name="stage"),
        CheckConstraint("stage <> 'running' OR lease_expires_at IS NOT NULL", name="running_has_a_lease"),
        Index("investigations_one_live_per_alert", "tenant_id", "alert_id", unique=True,
              postgresql_where=text(f"stage IN ({_quoted(LIVE)})")),
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
    #: The API's mapped shape (`status`, `commit`, `stale_kind`), or null.
    knowledge: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), default=None)
    failure_reason: Mapped[str | None] = mapped_column(Text, default=None)
    failure_message: Mapped[str | None] = mapped_column(Text, default=None)
    #: When the holder's claim lapses (by the database's clock); a running row always has one (#1343 B1).
    lease_expires_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: When the holder wrote its final cost and knowledge: internal, written once (#1343 B-P2).
    accounting_written_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


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
    title: str
    description: str
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
    knowledge: dict[str, Any] | None
    failure_reason: str | None
    failure_message: str | None


@dataclasses.dataclass(frozen=True)
class Claim:
    """A claimed investigation and its tenant's state, read in the claim's own transaction
    (#1342 r7 R7-1): the worker starts a job only for an `active` tenant."""

    record: InvestigationRecord
    tenant_state: str


def stored_alert(row: AlertRow) -> StoredAlert:
    return StoredAlert(
        alert_id=row.id, tenant_id=row.tenant_id, vendor=row.vendor, vendor_ticket_id=row.vendor_ticket_id,
        fired_at=row.fired_at, changed_at=row.changed_at, received_at=row.received_at, title=row.title,
        description=row.description, raw=bytes(row.raw))


def investigation_record(row: InvestigationRow) -> InvestigationRecord:
    return InvestigationRecord(
        investigation_id=row.id, tenant_id=row.tenant_id, alert_id=row.alert_id, request_key=row.request_key,
        attempt=row.attempt, stage=row.stage, created_at=row.created_at, started_at=row.started_at,
        finished_at=row.finished_at, disposition=row.disposition, cost_usd=row.cost_usd,
        knowledge=row.knowledge, failure_reason=row.failure_reason, failure_message=row.failure_message)
