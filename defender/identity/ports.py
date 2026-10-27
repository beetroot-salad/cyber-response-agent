"""What the identity service needs from outside: the stored records, the sign-in provider and
mail. Structural, so the in-memory and PostgreSQL repositories and the test fakes all fit."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Collection
from contextlib import AbstractContextManager
from typing import Protocol

from defender._model import model
from defender.tenancy._tenant import TenantId

from .rows import Membership, MembershipStatus, Session, User


@model(frozen=True)
class VerifiedSignIn:
    """What a verified login says: the provider's account id, the display name, and the
    authentication methods used (`amr`). The provider's tokens never leave the adapter."""

    account_id: str
    name: str
    amr: tuple[str, ...]


class IdentityRepository(Protocol):
    """Users, memberships and sessions, with the rules the data must hold on its own:

    - emails are unique and stored lower-cased;
    - at most one `invited`-or-`active` membership per (user, tenant);
    - a membership refers to a registered tenant and an existing user;
    - every status change is conditional on the expected status and reports whether it applied;
    - `active` carries `accepted_at`, `ended` carries `ended_at` and `ended_by`;
    - a session is found by the hash of its value, and the value itself is never kept.

    Time is an explicit aware-UTC argument; the repository holds no clock. Rows are frozen
    snapshots. A refused write raises `DataRuleViolation`."""

    # --- tenants
    def register_tenant(self, tenant_id: TenantId) -> None:
        """Idempotent."""
        ...
    def tenant_exists(self, tenant_id: str) -> bool: ...
    def tenants(self) -> list[str]: ...
    def tenant_has_ever_had_membership(self, tenant_id: str) -> bool: ...
    def tenant_has_active_members(self, tenant_id: str) -> bool: ...

    # --- users
    def ensure_user(self, email: str, *, now: _dt.datetime) -> User:
        """The user with this email, or a new `invited` one. Concurrent calls converge."""
        ...
    def user(self, user_id: str) -> User | None: ...
    def user_by_email(self, email: str) -> User | None: ...
    def user_by_signin_account(self, account_id: str) -> User | None: ...
    def platform_admins(self) -> list[User]: ...
    def record_signin_account(self, user_id: str, account_id: str) -> bool:
        """Once per user, and unique across users; `False` when refused."""
        ...
    def activate_user(self, user_id: str, *, display_name: str, now: _dt.datetime) -> bool:
        """`invited` -> `active`, conditional."""
        ...
    def set_display_name(self, user_id: str, display_name: str, *, now: _dt.datetime) -> None: ...
    def set_platform_admin(self, user_id: str, flag: bool) -> None: ...

    # --- memberships
    def ensure_invitation(
        self, user_id: str, tenant_id: str, *, invited_by: str, now: _dt.datetime,
        expires_at: _dt.datetime | None = None,
    ) -> Membership | None:
        """The user's `invited` row for the tenant, or a new one; `None` when the user is
        already an active member. Finished rows are never reopened."""
        ...
    def accept_invitation(self, membership_id: str, *, now: _dt.datetime) -> bool:
        """`invited` -> `active` while unexpired (`expires_at` unset or after `now`)."""
        ...
    def end_membership(self, membership_id: str, *, ended_by: str, now: _dt.datetime) -> bool: ...
    def revoke_invitation(self, membership_id: str) -> bool: ...
    def membership(self, membership_id: str) -> Membership | None: ...
    def memberships_of_user(self, user_id: str) -> list[Membership]: ...
    def memberships_of_tenant(self, tenant_id: str) -> list[Membership]: ...
    def people_of_tenant(
        self, tenant_id: str, status: MembershipStatus,
    ) -> list[tuple[Membership, User]]:
        """The tenant's rows in `status`, each with its user, in one read."""
        ...
    def active_membership(self, user_id: str, tenant_id: str) -> Membership | None: ...

    # --- sends: a send is pending while requested_seq > sent_seq
    def request_set_password(self, user_id: str, *, now: _dt.datetime) -> int: ...
    def request_notification(self, membership_id: str, *, now: _dt.datetime) -> int: ...
    def claim_pending_set_password(
        self, skip: Collection[str] = (),
    ) -> AbstractContextManager[User | None]:
        """Yields an `invited` user with a pending set-password send that no other claim holds
        and that is not in `skip`, or `None`. The claim is held for the block."""
        ...
    def claim_pending_notification(
        self, skip: Collection[str] = (),
    ) -> AbstractContextManager[Membership | None]:
        """As `claim_pending_set_password`, for an `invited` row with a pending notification."""
        ...
    def settle_set_password(
        self, user_id: str, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        """Move `sent_seq` to `read_seq`, only while `sent_seq < read_seq <= requested_seq`.
        `sent_at=None` means the send was dropped. `expires_at` goes on the user's `invited`
        rows."""
        ...
    def settle_notification(
        self, membership_id: str, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        """As `settle_set_password`; `expires_at` goes on that one row."""
        ...

    # --- sessions
    def add_session(
        self, value: str, user_id: str, *, now: _dt.datetime, expires_at: _dt.datetime,
        used_otp: bool = False,
    ) -> Session: ...
    def session_by_value(self, value: str) -> Session | None: ...
    def delete_session(self, value: str) -> bool: ...
    def touch_session(self, value: str, *, now: _dt.datetime) -> bool:
        """Move `last_seen_at` to `now` only when it is more than five minutes old."""
        ...


class SignInPort(Protocol):
    """The sign-in provider. Failures: `SignInRefused` for a login that does not
    verify, `SignInUnavailable` for anything else that went wrong."""

    def create_account(self, *, username: str, email: str, required_actions: frozenset[str]) -> str:
        """Create the account, or find the one with this username. Required actions are
        `set_password` and `set_up_otp`. Returns the provider's account id."""
        ...
    def send_set_password_email(self, account_id: str, *, lifespan: _dt.timedelta) -> None: ...
    def has_otp(self, account_id: str) -> bool: ...
    def require_otp_setup(self, account_id: str) -> None: ...
    def begin_signin(self, *, state: str, nonce: str, code_challenge: str) -> str:
        """The URL to send the person to."""
        ...
    def finish_signin(self, *, code: str, code_verifier: str, nonce: str) -> VerifiedSignIn: ...


class MailPort(Protocol):
    def notify_invitation(self, to: str, tenant_id: str, invitation_id: str) -> None: ...
