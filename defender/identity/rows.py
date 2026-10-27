"""The identity records, as the repository hands them out: frozen snapshots."""

from __future__ import annotations

import datetime as _dt
from typing import Annotated, Literal

from pydantic import AfterValidator

from defender._model import model

def normalize_email(raw: str) -> str:
    """The one form an email is stored and compared in."""
    return raw.strip().lower()


#: An email field normalized as it is built, so nothing after the boundary normalizes again.
Email = Annotated[str, AfterValidator(normalize_email)]

UserStatus = Literal["invited", "active"]
MembershipStatus = Literal["invited", "active", "ended", "revoked"]


@model(frozen=True)
class User:
    id: str
    email: str
    display_name: str
    status: UserStatus
    signin_account_id: str | None
    is_platform_admin: bool
    set_password_requested_seq: int
    set_password_sent_seq: int
    set_password_requested_at: _dt.datetime | None
    set_password_sent_at: _dt.datetime | None
    set_password_attempts: int
    set_password_next_try_at: _dt.datetime | None
    created_at: _dt.datetime
    updated_at: _dt.datetime
    activated_at: _dt.datetime | None


@model(frozen=True)
class Membership:
    id: str
    user_id: str
    tenant_id: str
    status: MembershipStatus
    invited_by: str
    created_at: _dt.datetime
    notify_requested_seq: int
    notify_sent_seq: int
    notify_requested_at: _dt.datetime | None
    notified_at: _dt.datetime | None
    notify_attempts: int
    notify_next_try_at: _dt.datetime | None
    expires_at: _dt.datetime | None
    accepted_at: _dt.datetime | None
    ended_at: _dt.datetime | None
    ended_by: str | None


@model(frozen=True)
class Session:
    token_hash: str
    user_id: str
    used_otp: bool
    created_at: _dt.datetime
    last_seen_at: _dt.datetime
    expires_at: _dt.datetime
