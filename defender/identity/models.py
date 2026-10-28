"""The identity models: the PostgreSQL tables and the records the repositories hand out, one
declaration. Fields are all supplied by the repository in Python (no server defaults), and a
returned model is a detached copy: changing it changes nothing that is stored."""

from __future__ import annotations

import datetime as _dt
from typing import Annotated, Literal

from pydantic import AfterValidator
from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, Text, UniqueConstraint, text,
)
from sqlalchemy.orm import Mapped, mapped_column

from defender.database import Base

SCHEMA = "identity"


def normalize_email(raw: str) -> str:
    """The one form an email is stored and compared in."""
    return raw.strip().lower()


#: An email field normalized as it is built, so nothing after the boundary normalizes again.
Email = Annotated[str, AfterValidator(normalize_email)]

UserStatus = Literal["invited", "active"]
MembershipStatus = Literal["invited", "active", "ended", "revoked"]

_TIME = DateTime(timezone=True)


class Tenant(Base):
    """For now identity's own table; #1214 moves it to the tenancy feature."""

    __tablename__ = "tenants"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email"),
        UniqueConstraint("signin_account_id"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint("status IN ('invited', 'active')", name="status"),
        CheckConstraint("status <> 'active' OR activated_at IS NOT NULL", name="active_is_activated"),
        {"schema": SCHEMA},
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    email: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str] = mapped_column(Text)
    status: Mapped[UserStatus] = mapped_column(Text)
    signin_account_id: Mapped[str | None] = mapped_column(Text)
    is_platform_admin: Mapped[bool] = mapped_column(Boolean)
    set_password_requested_seq: Mapped[int] = mapped_column(Integer)
    set_password_sent_seq: Mapped[int] = mapped_column(Integer)
    set_password_requested_at: Mapped[_dt.datetime | None] = mapped_column(_TIME)
    set_password_sent_at: Mapped[_dt.datetime | None] = mapped_column(_TIME)
    set_password_attempts: Mapped[int] = mapped_column(Integer)
    set_password_next_try_at: Mapped[_dt.datetime | None] = mapped_column(_TIME)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    updated_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    activated_at: Mapped[_dt.datetime | None] = mapped_column(_TIME)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        CheckConstraint("status IN ('invited', 'active', 'ended', 'revoked')", name="status"),
        CheckConstraint("status <> 'active' OR accepted_at IS NOT NULL", name="active_is_accepted"),
        CheckConstraint("status <> 'ended' OR (ended_at IS NOT NULL AND ended_by IS NOT NULL)",
                        name="ended_is_ended"),
        Index("memberships_one_live_row", "user_id", "tenant_id", unique=True,
              postgresql_where=text("status IN ('invited', 'active')")),
        Index("memberships_by_tenant", "tenant_id"),
        {"schema": SCHEMA},
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey(f"{SCHEMA}.users.id"))
    tenant_id: Mapped[str] = mapped_column(Text, ForeignKey(f"{SCHEMA}.tenants.id"))
    status: Mapped[MembershipStatus] = mapped_column(Text)
    invited_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    notify_requested_seq: Mapped[int] = mapped_column(Integer)
    notify_sent_seq: Mapped[int] = mapped_column(Integer)
    notify_requested_at: Mapped[_dt.datetime | None] = mapped_column(_TIME)
    notified_at: Mapped[_dt.datetime | None] = mapped_column(_TIME)
    notify_attempts: Mapped[int] = mapped_column(Integer)
    notify_next_try_at: Mapped[_dt.datetime | None] = mapped_column(_TIME)
    expires_at: Mapped[_dt.datetime | None] = mapped_column(_TIME)
    accepted_at: Mapped[_dt.datetime | None] = mapped_column(_TIME)
    ended_at: Mapped[_dt.datetime | None] = mapped_column(_TIME)
    ended_by: Mapped[str | None] = mapped_column(Text)


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("sessions_by_user", "user_id"), {"schema": SCHEMA})

    token_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey(f"{SCHEMA}.users.id"))
    used_otp: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    last_seen_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    expires_at: Mapped[_dt.datetime] = mapped_column(_TIME)
