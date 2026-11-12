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
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal, get_args

from sqlalchemy import ARRAY, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, Table, Text, select, text, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from defender.database import Base, IdColumn
from defender.records.formats import MAPPING_KEYS, AlertMapping, TenantId

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
    one place the transition's rules live (#1360 D1): the repository's `request_offboard` and the job store's
    combined offboard both run it. Takes the tenant row's lock, held until the caller's transaction ends."""
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


class ForgeWiring(Base, kw_only=True):
    """The tenant's repository on the forge: recorded, never derived (the lab keeps `tenants/playground`)."""  # lint-shippable: ok — names the lab tenant that adoption keeps

    __tablename__ = "forge_wiring"
    __table_args__ = {"schema": SCHEMA}

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
    delivery one. A generation recorded before them reads back with them None."""

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


@dataclasses.dataclass(frozen=True, kw_only=True)
class SystemRecord:
    """One tenant system as a version of it stands: the adapter it names (a catalog id, or, until #1172 allows it,
    `custom_ref=(path, revision)` with an empty `adapter_id`), its prefixed settings, its access declaration's text and the
    credential generation its version carries."""

    system_id: str
    version: int
    adapter_id: str = ""
    enabled: bool = True
    settings: Mapping[str, str] = dataclasses.field(default_factory=dict)
    access: str = ""
    credential_generation: int = 1
    custom_ref: tuple[str, str] | None = None


@dataclasses.dataclass(frozen=True, kw_only=True)
class CaseRecord:
    """The tenant's case write-back record as a version of it stands."""

    version: int
    system_id: str
    comment_body: str


@dataclasses.dataclass(frozen=True, kw_only=True)
class TenantRecords:
    """What the tenant's records say now: whether its systems come from records at all (the mark), its current systems
    (a deleted one is absent, a disabled one present) and its current case record."""

    imported: bool = False
    systems: Mapping[str, SystemRecord] = dataclasses.field(default_factory=dict)
    case: CaseRecord | None = None

    def as_wire(self) -> dict[str, Any]:
        """These records as plain JSON data: how a job's host helper, which read them, hands them to its job container,
        which reads no database (#1170 A6, #1366 O6). `from_wire` reads it back."""
        return {
            "imported": self.imported,
            "systems": {sid: {"version": r.version, "adapter_id": r.adapter_id, "enabled": r.enabled,
                              "settings": dict(r.settings), "access": r.access,
                              "credential_generation": r.credential_generation,
                              "custom_ref": None if r.custom_ref is None else list(r.custom_ref)}
                        for sid, r in sorted(self.systems.items())},
            "case": None if self.case is None else {"version": self.case.version, "system_id": self.case.system_id,
                                                    "comment_body": self.case.comment_body},
        }

    @classmethod
    def from_wire(cls, wire: object) -> TenantRecords:
        """The records `as_wire` wrote, or `ValueError` naming the first field that is not as it wrote it."""
        def field(obj: object, key: str, kind: type | tuple[type, ...], where: str) -> Any:
            if not isinstance(obj, dict) or key not in obj:
                raise ValueError(f"{where}: no {key!r}")
            value = obj[key]
            if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
                raise ValueError(f"{where}: {key!r} is not {getattr(kind, '__name__', kind)}")
            return value

        systems: dict[str, SystemRecord] = {}
        for sid, r in field(wire, "systems", dict, "records").items():
            where = f"records: system {sid!r}"
            settings = field(r, "settings", dict, where)
            if not all(isinstance(k, str) and isinstance(v, str) for k, v in settings.items()):
                raise ValueError(f"{where}: 'settings' is not text to text")
            ref = field(r, "custom_ref", (list, type(None)), where)
            if ref is not None and (len(ref) != 2 or not all(isinstance(x, str) for x in ref)):  # noqa: PLR2004 — (path, revision)
                raise ValueError(f"{where}: 'custom_ref' is not [path, revision]")
            systems[str(sid)] = SystemRecord(
                system_id=str(sid), version=field(r, "version", int, where),
                adapter_id=field(r, "adapter_id", str, where), enabled=field(r, "enabled", bool, where),
                settings=dict(settings), access=field(r, "access", str, where),
                credential_generation=field(r, "credential_generation", int, where),
                custom_ref=None if ref is None else (ref[0], ref[1]))
        case_wire = field(wire, "case", (dict, type(None)), "records")
        case = None if case_wire is None else CaseRecord(
            version=field(case_wire, "version", int, "records: case"),
            system_id=field(case_wire, "system_id", str, "records: case"),
            comment_body=field(case_wire, "comment_body", str, "records: case"))
        return cls(imported=field(wire, "imported", bool, "records"), systems=systems, case=case)


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
    comment_body: Mapped[str] = mapped_column(Text)
    deleted: Mapped[bool] = mapped_column(Boolean)
    author: Mapped[str] = mapped_column(Text)
    written_at: Mapped[_dt.datetime] = mapped_column(_TIME)


class RecordsMark(Base, kw_only=True):
    """Present for a tenant whose systems come from records (R8, R11). Also the row a writer locks to serialize a tenant."""

    __tablename__ = "records_mark"
    __table_args__ = {"schema": SCHEMA}

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)


@dataclasses.dataclass(frozen=True)
class MergeEligibility:
    """Who may merge into the tenant's `main`, as of the management service's latest read (#1414 D13): the logins of the
    merge whitelist's users and its teams' members, no generation's bot among them, and the instant it was read."""

    logins: frozenset[str]
    read_at: _dt.datetime


class MergeEligibilityRow(Base, kw_only=True):
    """The tenant's latest merge-eligibility record (#1414 D13): at most one row, absent until the first successful read,
    replaced whole by each later one and never deleted. An empty `logins` is a record (a whitelist nobody is on)."""

    __tablename__ = "merge_eligibility"
    __table_args__ = {"schema": SCHEMA}

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
    logins: Mapped[list[str]] = mapped_column(ARRAY(Text))
    read_at: Mapped[_dt.datetime] = mapped_column(_TIME)

    def as_record(self) -> MergeEligibility:
        """The record the row holds, its time an instant in UTC."""
        return MergeEligibility(logins=frozenset(self.logins), read_at=self.read_at.astimezone(_dt.UTC))
