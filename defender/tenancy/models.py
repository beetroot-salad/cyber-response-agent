"""The tenancy models (#1214): the tenant record and its lifecycle tables in the `tenancy` schema,
one declaration for the PostgreSQL tables and the records both repositories hand out.

Every value is set in Python (no server defaults), and a returned record is a detached copy:
changing it changes nothing stored. The rules the data holds on its own are constraints here, so
#1339's catalog comparison covers them: a state only with the pending actions it allows (a NULL
action included), at most one `live` generation per tenant, every lifecycle row belongs to a tenant.
Identity's memberships refer to `tenants`; nothing here refers to identity."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from pathlib import Path
from typing import Any, Literal, get_args

from sqlalchemy import ARRAY, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, Table, Text, select, text, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from defender.database import Base, IdColumn
from defender.records.formats import MAPPING_KEYS, AlertMapping, PeopleRequestId, TenantId, UserId
# The records' plain values live apart from the tables (no database library needed to hold them); re-exported here.
from defender.tenancy.record_values import CaseRecord as CaseRecord, SystemRecord as SystemRecord, TenantRecords as TenantRecords

SCHEMA = "tenancy"

TenantState = Literal["creating", "active", "offboarding", "offboarded"]
PendingAction = Literal["create", "rotate", "offboard", "delete_repo"]
StepActor = Literal["service", "host"]
GenerationStatus = Literal["pending", "live", "retiring", "destroyed"]

#: Each state with the pending actions it allows (`None`: nothing pending).
ALLOWED_ACTIONS: dict[str, frozenset[str | None]] = {
    "creating": frozenset({"create"}),
    "active": frozenset({None, "rotate"}),
    "offboarding": frozenset({"offboard"}),
    "offboarded": frozenset({None, "delete_repo"}),
}

_TIME = DateTime(timezone=True)


def _in(column: str, allowed: object) -> str:
    return f"{column} IN ({', '.join(repr(s) for s in get_args(allowed))})"


def _pairs() -> str:
    """The state/pending-action CHECK. NULL-safe: a plain `pending_action = 'create'` is NULL for a
    NULL action, and a CHECK lets NULL through, so `creating` with nothing pending would pass."""
    terms = []
    for state, actions in ALLOWED_ACTIONS.items():
        options = [("pending_action IS NULL" if a is None else f"pending_action IS NOT DISTINCT FROM '{a}'")
                   for a in sorted(actions, key=str)]
        terms.append(f"(state = '{state}' AND ({' OR '.join(options)}))")
    return " OR ".join(terms)


class _PathText(TypeDecorator[Path]):
    """A path stored as text and read back as a `Path`, so both repositories return the same value."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, _dialect: Any) -> str | None:
        return None if value is None else str(value)

    def process_result_value(self, value: Any, _dialect: Any) -> Path | None:
        return None if value is None else Path(value)


class TenantRecord(Base, kw_only=True):
    """A tenant and its one job: the pending action, the current step and whose step it is, and the
    last failure. Nothing pending means `step` and `step_actor` are None. After offboarding the
    row stays as a tombstone (memberships refer to it)."""

    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint(_in("state", TenantState), name="state"),
        CheckConstraint(_in("pending_action", PendingAction), name="pending_action"),
        CheckConstraint(_in("step_actor", StepActor), name="step_actor"),
        CheckConstraint(_pairs(), name="state_allows_pending_action"),
        {"schema": SCHEMA},
    )

    id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), primary_key=True)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    state: Mapped[str] = mapped_column(Text)
    pending_action: Mapped[str | None] = mapped_column(Text, default=None)
    step: Mapped[str | None] = mapped_column(Text, default=None)
    step_actor: Mapped[str | None] = mapped_column(Text, default=None)
    failure: Mapped[str | None] = mapped_column(Text, default=None)
    repo_url: Mapped[str | None] = mapped_column(Text, default=None)
    offboarded_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    repo_delete_after: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


#: What the offboard request writes: the tenant's job becomes the teardown, replacing any pending action.
_OFFBOARD_VALUES = {"state": "offboarding", "pending_action": "offboard", "step": "offboard", "step_actor": "service",
                    "failure": None}


async def offboard(executor: AsyncConnection | AsyncSession, tenant_id: TenantId) -> TenantRecord:
    """Move a `creating` or `active` tenant to `offboarding` (the teardown pending at its first step, any failure
    cleared) in the caller's transaction, on either a Core connection or the ORM session, and return the tenant as
    it now stands. `NotFound` for an absent tenant, `Conflict` for any other state: tenancy's own refusals, and the
    one place the transition's rules live (#1360 D1): the job store's combined offboard runs it (#1496: its one
    caller in production). Takes the tenant row's lock, held until the caller's transaction ends."""
    from defender.tenancy.repository import Conflict, NotFound  # here: the repository imports these models

    table: Table = TenantRecord.__table__  # type: ignore[assignment]
    done = (await executor.execute(
        update(table).where(table.c.id == tenant_id, table.c.state.in_(("creating", "active")))
        .values(**_OFFBOARD_VALUES).returning(*table.c))).first()
    if done is not None:
        return TenantRecord(**done._mapping)
    present = (await executor.execute(select(table.c.id).where(table.c.id == tenant_id))).first()
    if present is None:
        raise NotFound(f"no tenant {tenant_id}")
    raise Conflict("only a creating or active tenant can be offboarded")


async def share_tenant(executor: AsyncConnection | AsyncSession, tenant_id: TenantId) -> str | None:
    """The tenant's state, read with a share lock on its row, held until the caller's transaction ends (#1454 P-L,
    #1360 Flow 2). Take it before any other lock: a write that shares first makes `offboard` wait and then end the row
    it made; an offboard that wrote first makes the share wait and read the new state. `None` for an absent tenant.
    The one owner of this lock: the job store and the identity repositories both call it."""
    table: Table = TenantRecord.__table__  # type: ignore[assignment]
    return (await executor.execute(
        select(table.c.state).where(table.c.id == tenant_id).with_for_update(read=True))).scalar()


def knowledge_repo(tenant_id: str) -> str:
    """The tenant's repository on the forge (#1592): `t-<T>/knowledge`, the organisation `t-<T>` holding repository
    `knowledge`. The one owner of the name: the lifecycle's `names` records it, the wiring CHECK admits only it, and the
    memory twin's mirror of that CHECK compares with it."""
    return f"t-{tenant_id}/knowledge"


#: The wiring CHECK (#1592 OD-5): a tenant's wiring names its own knowledge repository, `knowledge_repo`'s spelling.
WIRING_IS_KNOWLEDGE_REPO = "repo = 't-' || tenant_id::text || '/knowledge'"


class ForgeWiring(Base, kw_only=True):
    """The tenant's repository on the forge: recorded by the lifecycle's `names` step, and only ever the tenant's own
    `knowledge_repo` (the CHECK; the memory twin refuses any other with `ValueError`)."""

    __tablename__ = "forge_wiring"
    __table_args__ = (CheckConstraint(WIRING_IS_KNOWLEDGE_REPO, name="repo_is_knowledge"), {"schema": SCHEMA})

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
    repo: Mapped[str] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(Text)


class Generation(Base, kw_only=True):
    """One credential chain of a tenant, sharing one salt: the bot, its integration, the OIDC role,
    the AppRole and its entity, and the host's secret file. The names are recorded before anything
    is created (P1); the rest as each step learns it. `wrapped_secret` is the single-use wrapping
    token handed to the host, cleared by install.

    The `sign_*` fields mirror the delivery chain's for the generation's sign-only AppRole (#1163
    A24'): its own entity, role id, wrapped and installed secret, and the host file beside the
    delivery one. A generation recorded before them reads back with them None.

    The `evidence_*` fields are the same chain for the generation's evidence login (#1546 r9): an AppRole on the
    evidence policy that takes a datakey of, and decrypts with, the tenant's own `evidence-<T>` key and nothing
    else, its own entity carrying the tenant, its role id, wrapped and installed secret and the host file."""

    __tablename__ = "generations"
    __table_args__ = (
        CheckConstraint(_in("status", GenerationStatus), name="status"),
        Index("generations_one_live", "tenant_id", unique=True, postgresql_where=text("status = 'live'")),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
    salt: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str] = mapped_column(Text, default="pending")
    bot_login: Mapped[str] = mapped_column(Text)
    oidc_role: Mapped[str] = mapped_column(Text)
    approle: Mapped[str] = mapped_column(Text)
    entity: Mapped[str] = mapped_column(Text)
    integration_args: Mapped[list[str] | None] = mapped_column(ARRAY(Text), default=None)
    role_id: Mapped[str | None] = mapped_column(Text, default=None)
    audience: Mapped[str | None] = mapped_column(Text, default=None)
    host_secret_file: Mapped[Path | None] = mapped_column(_PathText, default=None)
    wrapped_secret: Mapped[str | None] = mapped_column(Text, default=None)
    secret_accessor: Mapped[str | None] = mapped_column(Text, default=None)
    sign_approle: Mapped[str | None] = mapped_column(Text, default=None)
    sign_entity: Mapped[str | None] = mapped_column(Text, default=None)
    sign_role_id: Mapped[str | None] = mapped_column(Text, default=None)
    sign_secret_file: Mapped[Path | None] = mapped_column(_PathText, default=None)
    sign_wrapped_secret: Mapped[str | None] = mapped_column(Text, default=None)
    sign_secret_accessor: Mapped[str | None] = mapped_column(Text, default=None)
    evidence_approle: Mapped[str | None] = mapped_column(Text, default=None)
    evidence_entity: Mapped[str | None] = mapped_column(Text, default=None)
    evidence_role_id: Mapped[str | None] = mapped_column(Text, default=None)
    evidence_secret_file: Mapped[Path | None] = mapped_column(_PathText, default=None)
    evidence_wrapped_secret: Mapped[str | None] = mapped_column(Text, default=None)
    evidence_secret_accessor: Mapped[str | None] = mapped_column(Text, default=None)


#: The least and the most days an evidence retention value may be (#1546 A-O7, `0029_evidence_retention`).
RETENTION_LEAST, RETENTION_MOST = 30, 730


@dataclasses.dataclass(frozen=True)
class EvidenceRetention:
    """How long a tenant keeps the evidence of an ended investigation and of an ended learning job, in days from the
    acceptance of each object (#1546 A-O7)."""

    investigation_days: int
    learning_days: int


class EvidenceRetentionRow(Base, kw_only=True):
    """The tenant's retention (#1546 A-O7, D16): one row per tenant, written with the tenant at its creation and replaced
    whole by the API; no default exists, and an offboarded tenant keeps its row (investigations name it)."""

    __tablename__ = "evidence_retention"
    __table_args__ = (
        CheckConstraint(f"investigation_days BETWEEN {RETENTION_LEAST} AND {RETENTION_MOST}", name="investigation_days"),
        CheckConstraint(f"learning_days BETWEEN {RETENTION_LEAST} AND {RETENTION_MOST}", name="learning_days"),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
    investigation_days: Mapped[int] = mapped_column(Integer)
    learning_days: Mapped[int] = mapped_column(Integer)

    def as_record(self) -> EvidenceRetention:
        return EvidenceRetention(investigation_days=self.investigation_days, learning_days=self.learning_days)


class PublishStatus(Base, kw_only=True):
    """The tenant's last publish outcome (replaces `publish-status.json`): the commit published, or
    the refusal with its kind (`transient` | `operator`). Written by host processes."""

    __tablename__ = "publish_status"
    __table_args__ = {"schema": SCHEMA}

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
    recorded_by: Mapped[str] = mapped_column(Text)
    published: Mapped[str | None] = mapped_column(Text, default=None)
    refused: Mapped[str | None] = mapped_column(Text, default=None)
    kind: Mapped[str | None] = mapped_column(Text, default=None)

    def as_dict(self) -> dict[str, str]:
        """The keys of the old file: `by`, then `published`, or `refused` with `kind`."""
        out = {"by": self.recorded_by}
        if self.published is not None:
            out["published"] = self.published
        else:
            out.update(refused=self.refused or "", kind=self.kind or "")
        return out


class AlertMappingRow(Base, kw_only=True):
    """The tenant's alert mapping (#1345): at most one row, absent until the first save, replaced whole and never
    deleted. One nullable text column per entry, named as the entry (`records.formats.MAPPING_KEYS`); null is an
    unmapped entry. Declared with the tenant records and read through them; written only by the jobs store's replace (M1),
    which leaves stored alerts' title and description as they were (#1420)."""

    __tablename__ = "alert_mappings"
    __table_args__ = {"schema": SCHEMA}

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
    signature: Mapped[str | None] = mapped_column(Text, default=None)
    event_time: Mapped[str | None] = mapped_column(Text, default=None)
    summary: Mapped[str | None] = mapped_column(Text, default=None)
    case_key: Mapped[str | None] = mapped_column(Text, default=None)
    title: Mapped[str | None] = mapped_column(Text, default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)

    def as_mapping(self) -> AlertMapping:
        """The mapping the row holds: its mapped entries only."""
        return AlertMapping(paths={k: v for k in MAPPING_KEYS if (v := getattr(self, k)) is not None})

    @classmethod
    def of(cls, tenant_id: TenantId, mapping: AlertMapping) -> AlertMappingRow:
        """The row for `mapping` (entries it does not map are null)."""
        return cls(tenant_id=tenant_id, **{k: mapping.path_of(k) for k in MAPPING_KEYS})


# --- system and case records (#1366) -------------------------------------------------------------------------------------


class SystemVersionRow(Base, kw_only=True):
    """One version of one system: append-only, the highest version is current, a delete is a version with `deleted`."""

    __tablename__ = "system_versions"
    __table_args__ = {"schema": SCHEMA}

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
    system_id: Mapped[str] = mapped_column(Text, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    adapter_id: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean)
    settings: Mapped[dict[str, str]] = mapped_column(JSONB)
    access: Mapped[str] = mapped_column(Text)
    credential_generation: Mapped[int] = mapped_column(Integer)
    deleted: Mapped[bool] = mapped_column(Boolean)
    author: Mapped[str] = mapped_column(Text)
    written_at: Mapped[_dt.datetime] = mapped_column(_TIME)

    def as_record(self) -> SystemRecord:
        ref = None
        adapter = self.adapter_id
        if adapter.startswith(CUSTOM_PREFIX):
            path, _sep, revision = adapter[len(CUSTOM_PREFIX):].partition("@")
            ref, adapter = (path, revision), ""
        return SystemRecord(system_id=self.system_id, version=self.version, adapter_id=adapter, enabled=self.enabled,
                            settings=dict(self.settings), access=self.access,
                            credential_generation=self.credential_generation, custom_ref=ref)


#: A custom adapter reference is stored in `adapter_id` as `custom:<path>@<revision>`.
CUSTOM_PREFIX = "custom:"


def adapter_column(record: SystemRecord) -> str:
    """The `adapter_id` column's text for `record`."""
    return record.adapter_id if record.custom_ref is None else f"{CUSTOM_PREFIX}{record.custom_ref[0]}@{record.custom_ref[1]}"


class CaseVersionRow(Base, kw_only=True):
    """One version of the tenant's case record: append-only, the highest is current, a delete is a version."""

    __tablename__ = "case_versions"
    __table_args__ = {"schema": SCHEMA}

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[str] = mapped_column(Text)
    deleted: Mapped[bool] = mapped_column(Boolean)
    author: Mapped[str] = mapped_column(Text)
    written_at: Mapped[_dt.datetime] = mapped_column(_TIME)


# --- people requests (#1592) ---------------------------------------------------------------------------------------------


class PeopleRequest(Base, kw_only=True):
    """That something changed for a person (#1592 OD-10): (U, T) U's place in T, (U, none) U's account and sessions,
    (none, T) every person of T. Written by the database triggers on `identity.memberships.status`,
    `tenancy.tenants.state` and `identity.users.signed_out_at` in the changing transaction (the memory twins record
    where their stores write those columns), and deleted only by the request worker. Neither id has a foreign key: a
    request may name a user the product does not know, and it outlives a tenant row deleted under it. `requested_at` is
    the writing transaction's `now()` (the twin's process clock), which orders them; ties are expected."""

    __tablename__ = "forge_people_requests"
    __table_args__ = (
        CheckConstraint("user_id IS NOT NULL OR tenant_id IS NOT NULL", name="names_someone"),
        {"schema": SCHEMA},
    )

    id: Mapped[PeopleRequestId] = mapped_column(IdColumn(PeopleRequestId), primary_key=True)
    user_id: Mapped[UserId | None] = mapped_column(IdColumn(UserId), default=None)
    tenant_id: Mapped[TenantId | None] = mapped_column(IdColumn(TenantId), default=None)
    requested_at: Mapped[_dt.datetime] = mapped_column(_TIME)
