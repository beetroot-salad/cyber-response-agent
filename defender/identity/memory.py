"""The in-memory identity repository: the demo's and the tests' store. Unlike the API's other
fakes it holds the data rules itself (`ports.IdentityRepository`), because the contract suite
is written against them and the PostgreSQL repository answers the same suite."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import threading
import uuid
from collections.abc import Collection, Iterator
from contextlib import contextmanager
from typing import Any

from defender.tenancy._tenant import TenantId

from .errors import DataRuleViolation
from .rows import Membership, MembershipStatus, Session, User, UserStatus

#: How stale `last_seen_at` must be before a request writes it again.
TOUCH_AFTER = _dt.timedelta(minutes=5)
_LIVE = ("invited", "active")


def session_hash(value: str) -> str:
    """The lowercase hex SHA-256 of a session value: the only form in which one is stored."""
    return hashlib.sha256(value.encode()).hexdigest()


def _email(raw: str) -> str:
    return raw.strip().lower()


def check_membership_fields(
    status: MembershipStatus, *, accepted_at: _dt.datetime | None, ended_at: _dt.datetime | None,
    ended_by: str | None,
) -> None:
    """The rule that ties a status to its timestamps (the SQL schema carries it as a CHECK)."""
    if status == "active" and accepted_at is None:
        raise DataRuleViolation("an active membership needs accepted_at")
    if status == "ended" and (ended_at is None or ended_by is None):
        raise DataRuleViolation("an ended membership needs ended_at and ended_by")


class InMemoryIdentityRepository:
    """Every operation takes one lock, so a sender thread and request threads can share it.
    A claim is a held id, not a held lock: the lock is never kept across a claim's block."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tenants: dict[str, None] = {}
        self._users: dict[str, User] = {}
        self._by_email: dict[str, str] = {}
        self._by_account: dict[str, str] = {}
        self._memberships: dict[str, Membership] = {}
        self._sessions: dict[str, Session] = {}
        self._held_users: set[str] = set()
        self._held_memberships: set[str] = set()

    # --- tenants -----------------------------------------------------------------------------
    def register_tenant(self, tenant_id: TenantId) -> None:
        with self._lock:
            self._tenants.setdefault(str(TenantId(tenant_id)))

    def tenant_exists(self, tenant_id: str) -> bool:
        with self._lock:
            return str(tenant_id) in self._tenants

    def tenants(self) -> list[str]:
        with self._lock:
            return sorted(self._tenants)

    def tenant_has_ever_had_membership(self, tenant_id: str) -> bool:
        with self._lock:
            return any(m.tenant_id == str(tenant_id) for m in self._memberships.values())

    def tenant_has_active_members(self, tenant_id: str) -> bool:
        with self._lock:
            return any(m.tenant_id == str(tenant_id) and m.status == "active"
                       for m in self._memberships.values())

    # --- users -------------------------------------------------------------------------------
    def _new_user(
        self, email: str, *, created_at: _dt.datetime, status: UserStatus = "invited",
        display_name: str = "", signin_account_id: str | None = None, is_platform_admin: bool = False,
    ) -> User:
        email = _email(email)
        if email in self._by_email:
            raise DataRuleViolation(f"the email {email!r} already belongs to a user")
        if signin_account_id is not None and signin_account_id in self._by_account:
            raise DataRuleViolation(f"the sign-in account {signin_account_id!r} is already recorded")
        user = User(
            id=str(uuid.uuid4()), email=email, display_name=display_name, status=status,
            signin_account_id=signin_account_id, is_platform_admin=is_platform_admin,
            set_password_requested_seq=0, set_password_sent_seq=0,
            set_password_requested_at=None, set_password_sent_at=None,
            created_at=created_at, updated_at=created_at,
            activated_at=created_at if status == "active" else None,
        )
        self._users[user.id] = user
        self._by_email[email] = user.id
        if signin_account_id is not None:
            self._by_account[signin_account_id] = user.id
        return user

    def add_user(
        self, email: str, *, created_at: _dt.datetime, status: UserStatus = "invited",
        display_name: str = "", signin_account_id: str | None = None, is_platform_admin: bool = False,
    ) -> User:
        """Seeder."""
        with self._lock:
            return self._new_user(
                email, created_at=created_at, status=status, display_name=display_name,
                signin_account_id=signin_account_id, is_platform_admin=is_platform_admin)

    def ensure_user(self, email: str, *, now: _dt.datetime) -> User:
        with self._lock:
            existing = self._by_email.get(_email(email))
            return self._users[existing] if existing else self._new_user(email, created_at=now)

    def user(self, user_id: str) -> User | None:
        with self._lock:
            return self._users.get(user_id)

    def user_by_email(self, email: str) -> User | None:
        with self._lock:
            found = self._by_email.get(_email(email))
            return self._users[found] if found else None

    def user_by_signin_account(self, account_id: str) -> User | None:
        with self._lock:
            found = self._by_account.get(account_id)
            return self._users[found] if found else None

    def platform_admins(self) -> list[User]:
        with self._lock:
            return [u for u in self._users.values() if u.is_platform_admin]

    def _update_user(self, user_id: str, **changes: Any) -> None:
        self._users[user_id] = dataclasses.replace(self._users[user_id], **changes)

    def record_signin_account(self, user_id: str, account_id: str) -> bool:
        with self._lock:
            user = self._users.get(user_id)
            if user is None or user.signin_account_id is not None or account_id in self._by_account:
                return False
            self._update_user(user_id, signin_account_id=account_id)
            self._by_account[account_id] = user_id
            return True

    def activate_user(self, user_id: str, *, display_name: str, now: _dt.datetime) -> bool:
        with self._lock:
            user = self._users.get(user_id)
            if user is None or user.status != "invited":
                return False
            self._update_user(user_id, status="active", activated_at=now, display_name=display_name,
                              updated_at=now)
            return True

    def set_display_name(self, user_id: str, display_name: str, *, now: _dt.datetime) -> None:
        with self._lock:
            if user_id in self._users and self._users[user_id].display_name != display_name:
                self._update_user(user_id, display_name=display_name, updated_at=now)

    def set_platform_admin(self, user_id: str, flag: bool) -> None:
        with self._lock:
            if user_id in self._users:
                self._update_user(user_id, is_platform_admin=flag)

    # --- memberships -------------------------------------------------------------------------
    def _live_row(self, user_id: str, tenant_id: str) -> Membership | None:
        return next((m for m in self._memberships.values()
                     if m.user_id == user_id and m.tenant_id == tenant_id and m.status in _LIVE), None)

    def _refuse_dangling(self, user_id: str, tenant_id: str) -> None:
        if user_id not in self._users:
            raise DataRuleViolation(f"no user {user_id!r}")
        if tenant_id not in self._tenants:
            raise DataRuleViolation(f"no registered tenant {tenant_id!r}")

    def _insert_membership(self, **fields: object) -> Membership:
        row = Membership(
            id=str(uuid.uuid4()), notify_requested_seq=0, notify_sent_seq=0,
            notify_requested_at=None, notified_at=None, **fields)  # type: ignore[arg-type]
        self._memberships[row.id] = row
        return row

    def add_membership(  # noqa: PLR0913 — the pinned seeder signature
        self, user_id: str, tenant_id: str, *, status: MembershipStatus, invited_by: str,
        created_at: _dt.datetime, expires_at: _dt.datetime | None = None,
        accepted_at: _dt.datetime | None = None, ended_at: _dt.datetime | None = None,
        ended_by: str | None = None,
    ) -> Membership:
        """Seeder."""
        tenant_id = str(tenant_id)
        with self._lock:
            self._refuse_dangling(user_id, tenant_id)
            check_membership_fields(status, accepted_at=accepted_at, ended_at=ended_at, ended_by=ended_by)
            if status in _LIVE and self._live_row(user_id, tenant_id) is not None:
                raise DataRuleViolation("the user already has a live membership in this tenant")
            return self._insert_membership(
                user_id=user_id, tenant_id=tenant_id, status=status, invited_by=invited_by,
                created_at=created_at, expires_at=expires_at, accepted_at=accepted_at,
                ended_at=ended_at, ended_by=ended_by)

    def ensure_invitation(
        self, user_id: str, tenant_id: str, *, invited_by: str, now: _dt.datetime,
        expires_at: _dt.datetime | None = None,
    ) -> Membership | None:
        tenant_id = str(tenant_id)
        with self._lock:
            self._refuse_dangling(user_id, tenant_id)
            live = self._live_row(user_id, tenant_id)
            if live is not None:
                return None if live.status == "active" else live
            return self._insert_membership(
                user_id=user_id, tenant_id=tenant_id, status="invited", invited_by=invited_by,
                created_at=now, expires_at=expires_at, accepted_at=None, ended_at=None, ended_by=None)

    def _update_membership(self, membership_id: str, **changes: Any) -> None:
        self._memberships[membership_id] = dataclasses.replace(self._memberships[membership_id], **changes)

    def accept_invitation(self, membership_id: str, *, now: _dt.datetime) -> bool:
        with self._lock:
            row = self._memberships.get(membership_id)
            if row is None or row.status != "invited" or (row.expires_at is not None and row.expires_at <= now):
                return False
            self._update_membership(membership_id, status="active", accepted_at=now)
            return True

    def end_membership(self, membership_id: str, *, ended_by: str, now: _dt.datetime) -> bool:
        with self._lock:
            row = self._memberships.get(membership_id)
            if row is None or row.status != "active":
                return False
            self._update_membership(membership_id, status="ended", ended_at=now, ended_by=ended_by)
            return True

    def revoke_invitation(self, membership_id: str) -> bool:
        with self._lock:
            row = self._memberships.get(membership_id)
            if row is None or row.status != "invited":
                return False
            self._update_membership(membership_id, status="revoked")
            return True

    def membership(self, membership_id: str) -> Membership | None:
        with self._lock:
            return self._memberships.get(membership_id)

    def memberships_of_user(self, user_id: str) -> list[Membership]:
        with self._lock:
            return [m for m in self._memberships.values() if m.user_id == user_id]

    def memberships_of_tenant(self, tenant_id: str) -> list[Membership]:
        with self._lock:
            return [m for m in self._memberships.values() if m.tenant_id == str(tenant_id)]

    def active_membership(self, user_id: str, tenant_id: str) -> Membership | None:
        with self._lock:
            row = self._live_row(user_id, str(tenant_id))
            return row if row is not None and row.status == "active" else None

    # --- sends -------------------------------------------------------------------------------
    def request_set_password(self, user_id: str, *, now: _dt.datetime) -> int:
        with self._lock:
            seq = self._users[user_id].set_password_requested_seq + 1
            self._update_user(user_id, set_password_requested_seq=seq, set_password_requested_at=now)
            return seq

    def request_notification(self, membership_id: str, *, now: _dt.datetime) -> int:
        with self._lock:
            seq = self._memberships[membership_id].notify_requested_seq + 1
            self._update_membership(membership_id, notify_requested_seq=seq, notify_requested_at=now)
            return seq

    @contextmanager
    def claim_pending_set_password(self, skip: Collection[str] = ()) -> Iterator[User | None]:
        with self._lock:
            found = next((u for u in self._users.values()
                          if u.status == "invited" and u.set_password_requested_seq > u.set_password_sent_seq
                          and u.id not in self._held_users and u.id not in skip), None)
            if found is not None:
                self._held_users.add(found.id)
        try:
            yield found
        finally:
            if found is not None:
                with self._lock:
                    self._held_users.discard(found.id)

    @contextmanager
    def claim_pending_notification(self, skip: Collection[str] = ()) -> Iterator[Membership | None]:
        with self._lock:
            found = next((m for m in self._memberships.values()
                          if m.status == "invited" and m.notify_requested_seq > m.notify_sent_seq
                          and m.id not in self._held_memberships and m.id not in skip), None)
            if found is not None:
                self._held_memberships.add(found.id)
        try:
            yield found
        finally:
            if found is not None:
                with self._lock:
                    self._held_memberships.discard(found.id)

    def settle_set_password(
        self, user_id: str, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        with self._lock:
            user = self._users.get(user_id)
            if user is None or not user.set_password_sent_seq < read_seq <= user.set_password_requested_seq:
                return False
            changes: dict[str, object] = {"set_password_sent_seq": read_seq}
            if sent_at is not None:
                changes["set_password_sent_at"] = sent_at
            self._update_user(user_id, **changes)
            if sent_at is not None and expires_at is not None:
                for row in self.memberships_of_user(user_id):
                    if row.status == "invited":
                        self._update_membership(row.id, expires_at=expires_at)
            return True

    def settle_notification(
        self, membership_id: str, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        with self._lock:
            row = self._memberships.get(membership_id)
            if row is None or not row.notify_sent_seq < read_seq <= row.notify_requested_seq:
                return False
            changes: dict[str, object] = {"notify_sent_seq": read_seq}
            if sent_at is not None:
                changes["notified_at"] = sent_at
                if row.status == "invited" and expires_at is not None:
                    changes["expires_at"] = expires_at
            self._update_membership(membership_id, **changes)
            return True

    # --- sessions ----------------------------------------------------------------------------
    def add_session(
        self, value: str, user_id: str, *, now: _dt.datetime, expires_at: _dt.datetime,
        used_otp: bool = False,
    ) -> Session:
        with self._lock:
            if user_id not in self._users:
                raise DataRuleViolation(f"no user {user_id!r}")
            row = Session(token_hash=session_hash(value), user_id=user_id, used_otp=used_otp,
                          created_at=now, last_seen_at=now, expires_at=expires_at)
            self._sessions[row.token_hash] = row
            return row

    def session_by_value(self, value: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_hash(value))

    def delete_session(self, value: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_hash(value), None) is not None

    def touch_session(self, value: str, *, now: _dt.datetime) -> bool:
        with self._lock:
            key = session_hash(value)
            row = self._sessions.get(key)
            if row is None or now - row.last_seen_at <= TOUCH_AFTER:
                return False
            self._sessions[key] = dataclasses.replace(row, last_seen_at=now)
            return True
