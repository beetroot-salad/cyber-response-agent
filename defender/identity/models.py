"""The identity models: the PostgreSQL tables and the records the repositories hand out, one
declaration. Every value is set in Python (no server defaults): a field's starting value is
declared on it, and a returned model is a detached copy: changing it changes nothing that is stored.
A status outside the model is refused as it is set, so both repositories refuse it alike.
Tenants are tenancy's (#1214): a membership refers to `tenancy.tenants`."""

from __future__ import annotations

import datetime as _dt
from typing import Annotated, Literal, get_args

from pydantic import AfterValidator
from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, Integer, Text, UniqueConstraint, text,
)
from sqlalchemy.orm import Mapped, mapped_column, validates

from defender._text import postgres_can_hold
from defender.database import Base, IdColumn
from defender.records.formats import CredentialId, MembershipId, TenantId, UserId
# The memberships' foreign key names `tenancy.tenants`: its table must be on the metadata too.
from defender.tenancy import models as _tenancy  # noqa: F401

from .errors import DataRuleViolation

SCHEMA = "identity"


def normalize_email(raw: str) -> str:
    """The one form an email is stored and compared in: trimmed of any whitespace, lower-cased.
    Refused when blank, or holding what PostgreSQL text cannot (NUL, or a lone surrogate, which is
    not valid text), so both repositories refuse alike rather than one failing in the database (#1349)."""
    email = raw.strip().lower()
    if not email:
        raise DataRuleViolation("an email address cannot be blank")
    if not postgres_can_hold(email):
        raise DataRuleViolation(f"{raw!r} is not an email address: it has a NUL or an invalid character")
    return email


def postgres_text(value: str, what: str) -> str:
    """`value` when PostgreSQL text can hold it, else `DataRuleViolation`: both repositories refuse a program's
    display name and a credential's name alike, rather than one failing in the database."""
    if not postgres_can_hold(value):
        raise DataRuleViolation(f"{what} has a NUL or an invalid character")
    return value


#: An email field normalized as it is built, so nothing after the boundary normalizes again.
Email = Annotated[str, AfterValidator(normalize_email)]

UserStatus = Literal["invited", "active"]
MembershipStatus = Literal["invited", "active", "ended", "revoked"]
UserKind = Literal["person", "program"]
Role = Literal["admin", "automation"]
CredentialKind = Literal["key", "oauth_client"]
CredentialState = Literal["pending", "live", "revoked"]

_TIME = DateTime(timezone=True)


def _status_check(allowed: object) -> CheckConstraint:
    """The table's CHECK on `status`, spelled from the same Literal the model validates against."""
    return CheckConstraint(f"status IN ({', '.join(repr(s) for s in get_args(allowed))})", name="status")


def _in_check(column: str, allowed: object, name: str) -> CheckConstraint:
    return CheckConstraint(f"{column} IN ({', '.join(repr(s) for s in get_args(allowed))})", name=name)


def _checked_status(model: str, allowed: object, value: str) -> str:
    if value not in get_args(allowed):
        raise DataRuleViolation(f"{value!r} is not a {model} status")
    return value


class User(Base, kw_only=True):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email"),
        UniqueConstraint("signin_account_id"),
        # The target of `program_credentials`' composite foreign key.
        UniqueConstraint("id", "kind"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        _status_check(UserStatus),
        CheckConstraint("status <> 'active' OR activated_at IS NOT NULL", name="active_is_activated"),
        _in_check("kind", UserKind, "kind"),
        CheckConstraint("(kind = 'program') = (email IS NULL)", name="email_iff_person"),
        CheckConstraint(
            "kind = 'person' OR (signin_account_id IS NULL AND NOT is_platform_admin AND status = 'active')",
            name="program_is_plain"),
        CheckConstraint("kind = 'program' OR created_by IS NULL", name="creator_is_for_programs"),
        {"schema": SCHEMA},
    )

    id: Mapped[UserId] = mapped_column(IdColumn(UserId), primary_key=True, default_factory=UserId.mint)
    #: Absent exactly for a program (CHECK).
    email: Mapped[str | None] = mapped_column(Text)
    display_name: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[UserStatus] = mapped_column(Text, default="invited")
    signin_account_id: Mapped[str | None] = mapped_column(Text, default=None)
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    set_password_requested_seq: Mapped[int] = mapped_column(Integer, default=0)
    set_password_sent_seq: Mapped[int] = mapped_column(Integer, default=0)
    set_password_requested_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    set_password_sent_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    set_password_attempts: Mapped[int] = mapped_column(Integer, default=0)
    set_password_next_try_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    updated_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    activated_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    kind: Mapped[UserKind] = mapped_column(Text, default="person")
    #: The admin who made a program; None for a person.
    created_by: Mapped[UserId | None] = mapped_column(IdColumn(UserId), ForeignKey(f"{SCHEMA}.users.id"), default=None)

    @classmethod
    def new(cls, email: str | None, *, created_at: _dt.datetime, status: UserStatus = "invited",
            display_name: str = "", signin_account_id: str | None = None,
            is_platform_admin: bool = False) -> User:
        """A person as first stored: updated and, when created active, activated at `created_at`.
        The email is required."""
        if email is None:
            raise DataRuleViolation("a person needs an email address")
        return cls(email=normalize_email(email), created_at=created_at, updated_at=created_at,
                   status=status, display_name=display_name, signin_account_id=signin_account_id,
                   is_platform_admin=is_platform_admin,
                   activated_at=created_at if status == "active" else None)

    @property
    def person_email(self) -> str:
        """The email of a user known to be a person (the CHECK gives every person one)."""
        assert self.email is not None, "a person has an email"
        return self.email

    @classmethod
    def new_program(cls, *, display_name: str, created_by: UserId, created_at: _dt.datetime) -> User:
        """A program as first stored: active, with no email, account or administrator flag. The display
        name must be text PostgreSQL can hold."""
        return cls(email=None, kind="program", created_by=created_by,
                   display_name=postgres_text(display_name, "a program's display name"),
                   status="active", created_at=created_at, updated_at=created_at, activated_at=created_at)

    @validates("status")
    def _status(self, _key: str, value: str) -> str:
        return _checked_status("user", UserStatus, value)


class Membership(Base, kw_only=True):
    __tablename__ = "memberships"
    __table_args__ = (
        _status_check(MembershipStatus),
        _in_check("role", Role, "role"),
        CheckConstraint("status <> 'active' OR accepted_at IS NOT NULL", name="active_is_accepted"),
        CheckConstraint("status <> 'ended' OR ended_at IS NOT NULL", name="ended_is_ended"),
        Index("memberships_one_live_row", "user_id", "tenant_id", unique=True,
              postgresql_where=text("status IN ('invited', 'active')")),
        Index("memberships_by_tenant", "tenant_id"),
        {"schema": SCHEMA},
    )

    id: Mapped[MembershipId] = mapped_column(IdColumn(MembershipId), primary_key=True, default_factory=MembershipId.mint)
    user_id: Mapped[UserId] = mapped_column(IdColumn(UserId), ForeignKey(f"{SCHEMA}.users.id"))
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), ForeignKey("tenancy.tenants.id"))
    status: Mapped[MembershipStatus] = mapped_column(Text)
    #: The user who invited, or None for the system (#1382: the actor columns hold user ids only).
    invited_by: Mapped[UserId | None] = mapped_column(IdColumn(UserId), ForeignKey(f"{SCHEMA}.users.id"))
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    notify_requested_seq: Mapped[int] = mapped_column(Integer, default=0)
    notify_sent_seq: Mapped[int] = mapped_column(Integer, default=0)
    notify_requested_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    notified_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    notify_attempts: Mapped[int] = mapped_column(Integer, default=0)
    notify_next_try_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    expires_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    accepted_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    ended_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: The user who ended it, or None for the system (or while not ended).
    ended_by: Mapped[UserId | None] = mapped_column(IdColumn(UserId), ForeignKey(f"{SCHEMA}.users.id"), default=None)
    #: `admin` for a person, `automation` for a program; the identity service and repositories are the only writers.
    role: Mapped[Role] = mapped_column(Text, default="admin")

    @validates("status")
    def _status(self, _key: str, value: str) -> str:
        return _checked_status("membership", MembershipStatus, value)


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("sessions_by_user", "user_id"), {"schema": SCHEMA})

    token_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[UserId] = mapped_column(IdColumn(UserId), ForeignKey(f"{SCHEMA}.users.id"))
    used_otp: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    last_seen_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    expires_at: Mapped[_dt.datetime] = mapped_column(_TIME)


class ProgramCredential(Base, kw_only=True):
    """A program's way in: an API key (its hash) or an OAuth client (the realm holds the secret). Whether it is
    usable is decided by this row alone: `live` and `expires_at > now`. Rows are never deleted (audit)."""

    __tablename__ = "program_credentials"
    __table_args__ = (
        # A credential's program is a user of kind program: `program_kind` is always 'program', and the pair
        # must exist in `users` (so no credential can ever authenticate a person by bearer, P-F).
        ForeignKeyConstraint(["program_id", "program_kind"], [f"{SCHEMA}.users.id", f"{SCHEMA}.users.kind"]),
        CheckConstraint("program_kind = 'program'", name="program_kind"),
        _in_check("kind", CredentialKind, "kind"),
        _in_check("state", CredentialState, "state"),
        CheckConstraint("(kind = 'key') = (key_hash IS NOT NULL)", name="key_iff_hash"),
        CheckConstraint("state <> 'pending' OR kind = 'oauth_client'", name="only_oauth_is_pending"),
        CheckConstraint("state <> 'revoked' OR revoked_at IS NOT NULL", name="revoked_is_revoked"),
        CheckConstraint("warn_threshold_days IN (14, 3)", name="warn_threshold"),
        CheckConstraint("(warn_threshold_days IS NULL) = (warn_next_at IS NULL)", name="warn_both_or_neither"),
        Index("program_credentials_by_program", "program_id"),
        # The warning sender's one-row claim: the earliest due warning.
        Index("program_credentials_warning_due", "warn_next_at", postgresql_where=text("warn_next_at IS NOT NULL")),
        Index("program_credentials_one_unrevoked_key", "key_hash", unique=True, postgresql_where=text("state <> 'revoked'")),
        {"schema": SCHEMA},
    )

    id: Mapped[CredentialId] = mapped_column(IdColumn(CredentialId), primary_key=True, default_factory=CredentialId.mint)
    program_id: Mapped[UserId] = mapped_column(IdColumn(UserId))
    #: Always `program`; see the foreign key above.
    program_kind: Mapped[Literal["program"]] = mapped_column(Text, default="program")
    kind: Mapped[CredentialKind] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    state: Mapped[CredentialState] = mapped_column(Text)
    created_by: Mapped[UserId] = mapped_column(IdColumn(UserId), ForeignKey(f"{SCHEMA}.users.id"))
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    expires_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    key_hash: Mapped[str | None] = mapped_column(Text, default=None)
    #: An OAuth credential's service-account user id (the token's `sub`), set when it goes live.
    service_account_id: Mapped[str | None] = mapped_column(Text, default=None)
    pending_deadline: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    last_used_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    revoked_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: The admin who revoked it, or None for the system (or while not revoked).
    revoked_by: Mapped[UserId | None] = mapped_column(IdColumn(UserId), ForeignKey(f"{SCHEMA}.users.id"), default=None)
    #: The next expiry warning: its threshold (days before expiry: 14, then 3) and when it may be claimed (the
    #: threshold's moment, or the end of a claim's hold or a deferral). Both unset once no warning is left.
    warn_threshold_days: Mapped[int | None] = mapped_column(Integer, default=None)
    warn_next_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)

    @validates("name")
    def _name(self, _key: str, value: str) -> str:
        return postgres_text(value, "a credential's name")

    @validates("kind")
    def _kind(self, _key: str, value: str) -> str:
        return _checked_status("credential kind", CredentialKind, value)

    @validates("state")
    def _state(self, _key: str, value: str) -> str:
        return _checked_status("credential state", CredentialState, value)


class CredentialWarningDelivery(Base, kw_only=True):
    """One admin told of one credential's expiry warning: a send is one (credential, threshold), and it is
    settled once every admin of the tenant at that moment has a row, so a retry mails only those still owed."""

    __tablename__ = "warning_deliveries"
    __table_args__ = (
        CheckConstraint("threshold_days IN (14, 3)", name="threshold"),
        {"schema": SCHEMA},
    )

    credential_id: Mapped[CredentialId] = mapped_column(
        IdColumn(CredentialId), ForeignKey(f"{SCHEMA}.program_credentials.id"), primary_key=True)
    threshold_days: Mapped[int] = mapped_column(Integer, primary_key=True)
    person_id: Mapped[UserId] = mapped_column(IdColumn(UserId), ForeignKey(f"{SCHEMA}.users.id"), primary_key=True)
    sent_at: Mapped[_dt.datetime] = mapped_column(_TIME)
