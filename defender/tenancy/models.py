"""The tenancy models (#1214): the tenant record and its lifecycle tables in the `tenancy` schema,
one declaration for the PostgreSQL tables and the records both repositories hand out.

Every value is set in Python (no server defaults), and a returned record is a detached copy:
changing it changes nothing stored. The rules the data holds on its own are constraints here, so
#1339's catalog comparison covers them: a state only with the pending actions it allows (a NULL
action included), at most one `live` generation per tenant, every lifecycle row belongs to a tenant.
Identity's memberships refer to `tenants`; nothing here refers to identity."""

from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Any, Literal, get_args

from sqlalchemy import ARRAY, CheckConstraint, DateTime, ForeignKey, Index, Text, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from defender.database import Base

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

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    state: Mapped[str] = mapped_column(Text)
    pending_action: Mapped[str | None] = mapped_column(Text, default=None)
    step: Mapped[str | None] = mapped_column(Text, default=None)
    step_actor: Mapped[str | None] = mapped_column(Text, default=None)
    failure: Mapped[str | None] = mapped_column(Text, default=None)
    repo_url: Mapped[str | None] = mapped_column(Text, default=None)
    offboarded_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    repo_delete_after: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


class ForgeWiring(Base, kw_only=True):
    """The tenant's repository on the forge: recorded, never derived (the lab keeps `tenants/playground`)."""

    __tablename__ = "forge_wiring"
    __table_args__ = {"schema": SCHEMA}

    tenant_id: Mapped[str] = mapped_column(Text, ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
    repo: Mapped[str] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(Text)


class Generation(Base, kw_only=True):
    """One credential chain of a tenant, sharing one salt: the bot, its integration, the OIDC role,
    the AppRole and its entity, and the host's secret file. The names are recorded before anything
    is created (P1); the rest as each step learns it. `wrapped_secret` is the single-use wrapping
    token handed to the host, cleared by install."""

    __tablename__ = "generations"
    __table_args__ = (
        CheckConstraint(_in("status", GenerationStatus), name="status"),
        Index("generations_one_live", "tenant_id", unique=True, postgresql_where=text("status = 'live'")),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[str] = mapped_column(Text, ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
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


class PublishStatus(Base, kw_only=True):
    """The tenant's last publish outcome (replaces `publish-status.json`): the commit published, or
    the refusal with its kind (`transient` | `operator`). Written by host processes."""

    __tablename__ = "publish_status"
    __table_args__ = {"schema": SCHEMA}

    tenant_id: Mapped[str] = mapped_column(Text, ForeignKey(f"{SCHEMA}.tenants.id"), primary_key=True)
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
