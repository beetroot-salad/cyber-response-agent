"""The identity models: the PostgreSQL tables and the records the repositories hand out, one
declaration. Every value is set in Python (no server defaults): a field's starting value is
declared on it, and a returned model is a detached copy: changing it changes nothing that is stored.
A status outside the model is refused as it is set, so both repositories refuse it alike."""

from __future__ import annotations

import datetime as _dt
import unicodedata
import uuid
from typing import Annotated, Literal, get_args

from pydantic import AfterValidator
from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, Text, UniqueConstraint, text,
)
from sqlalchemy.orm import Mapped, mapped_column, validates

from defender.database import Base

from .errors import DataRuleViolation

SCHEMA = "identity"


def normalize_email(raw: str) -> str:
    """The one form an email is stored and compared in: trimmed of any whitespace, lower-cased.
    Refused when blank, or holding what PostgreSQL text cannot (NUL, or a lone surrogate, which is
    not valid text), so both repositories refuse alike rather than one failing in the database (#1349)."""
    email = raw.strip().lower()
    if not email:
        raise DataRuleViolation("an email address cannot be blank")
    if any(c == "\x00" or unicodedata.category(c) == "Cs" for c in email):
        raise DataRuleViolation(f"{raw!r} is not an email address: it has a NUL or an invalid character")
    return email


#: An email field normalized as it is built, so nothing after the boundary normalizes again.
Email = Annotated[str, AfterValidator(normalize_email)]

UserStatus = Literal["invited", "active"]
MembershipStatus = Literal["invited", "active", "ended", "revoked"]

_TIME = DateTime(timezone=True)


def _new_id() -> str:
    return str(uuid.uuid4())


def _status_check(allowed: object) -> CheckConstraint:
    """The table's CHECK on `status`, spelled from the same Literal the model validates against."""
    return CheckConstraint(f"status IN ({', '.join(repr(s) for s in get_args(allowed))})", name="status")


def _checked_status(model: str, allowed: object, value: str) -> str:
    if value not in get_args(allowed):
        raise DataRuleViolation(f"{value!r} is not a {model} status")
    return value


class Tenant(Base):
    """For now identity's own table; #1214 moves it to the tenancy feature."""

    __tablename__ = "tenants"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)


class User(Base, kw_only=True):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email"),
        UniqueConstraint("signin_account_id"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        _status_check(UserStatus),
        CheckConstraint("status <> 'active' OR activated_at IS NOT NULL", name="active_is_activated"),
        {"schema": SCHEMA},
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True, default_factory=_new_id)
    email: Mapped[str] = mapped_column(Text)
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

    @classmethod
    def new(cls, email: str, *, created_at: _dt.datetime, status: UserStatus = "invited",
            display_name: str = "", signin_account_id: str | None = None,
            is_platform_admin: bool = False) -> User:
        """A user as first stored: updated and, when created active, activated at `created_at`."""
        return cls(email=normalize_email(email), created_at=created_at, updated_at=created_at,
                   status=status, display_name=display_name, signin_account_id=signin_account_id,
                   is_platform_admin=is_platform_admin,
                   activated_at=created_at if status == "active" else None)

    @validates("status")
    def _status(self, _key: str, value: str) -> str:
        return _checked_status("user", UserStatus, value)


class Membership(Base, kw_only=True):
    __tablename__ = "memberships"
    __table_args__ = (
        _status_check(MembershipStatus),
        CheckConstraint("status <> 'active' OR accepted_at IS NOT NULL", name="active_is_accepted"),
        CheckConstraint("status <> 'ended' OR (ended_at IS NOT NULL AND ended_by IS NOT NULL)",
                        name="ended_is_ended"),
        Index("memberships_one_live_row", "user_id", "tenant_id", unique=True,
              postgresql_where=text("status IN ('invited', 'active')")),
        Index("memberships_by_tenant", "tenant_id"),
        {"schema": SCHEMA},
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True, default_factory=_new_id)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey(f"{SCHEMA}.users.id"))
    tenant_id: Mapped[str] = mapped_column(Text, ForeignKey(f"{SCHEMA}.tenants.id"))
    status: Mapped[MembershipStatus] = mapped_column(Text)
    invited_by: Mapped[str] = mapped_column(Text)
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
    ended_by: Mapped[str | None] = mapped_column(Text, default=None)

    @validates("status")
    def _status(self, _key: str, value: str) -> str:
        return _checked_status("membership", MembershipStatus, value)


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("sessions_by_user", "user_id"), {"schema": SCHEMA})

    token_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey(f"{SCHEMA}.users.id"))
    used_otp: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    last_seen_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    expires_at: Mapped[_dt.datetime] = mapped_column(_TIME)
