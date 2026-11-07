"""The in-memory identity repository: the demo's and the tests' store. Unlike the API's other
fakes it holds the data rules itself (`ports.IdentityRepository`), because the contract suite
is written against them and the PostgreSQL repository answers the same suite."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
from collections.abc import Collection
from typing import Any, TypeVar, overload

from defender.tenancy import InMemoryTenantRepository

from defender.records.formats import CredentialId, MembershipId, TenantId, UserId

from .errors import DataRuleViolation
from .models import (
    CredentialKind, Membership, MembershipStatus, ProgramCredential, Role, Session, User, UserStatus,
    normalize_email,
)
from .ports import ExpiryWarning

#: How stale `last_seen_at` must be before a request writes it again.
TOUCH_AFTER = _dt.timedelta(minutes=5)
_LIVE = ("invited", "active")
#: How long an OAuth credential may stay `pending`: well past the realm admin calls (10 s each).
PENDING_DEADLINE = _dt.timedelta(minutes=10)
#: How many credentials a program may have that are usable or still pending.
CREDENTIAL_CAP = 2
#: The expiry-warning thresholds, loosest first.
WARNING_THRESHOLDS = (_dt.timedelta(days=14), _dt.timedelta(days=3))


def is_warning_threshold(threshold: _dt.timedelta) -> bool:
    return threshold in WARNING_THRESHOLDS


def session_hash(value: str) -> str:
    """The lowercase hex SHA-256 of a session value: the only form in which one is stored."""
    return hashlib.sha256(value.encode()).hexdigest()


_Row = TypeVar("_Row", User, Membership, Session, ProgramCredential)


@overload
def _copy(row: _Row) -> _Row: ...
@overload
def _copy(row: None) -> None: ...
def _copy(row: _Row | None) -> _Row | None:
    """What a repository hands out: a copy, so the caller's changes never reach what is stored."""
    return row if row is None else dataclasses.replace(row)


def _due(next_try_at: _dt.datetime | None, now: _dt.datetime) -> bool:
    return next_try_at is None or next_try_at <= now


def usable(row: ProgramCredential, now: _dt.datetime) -> bool:
    """`live` and not yet expired (expiry is computed, never a state)."""
    return row.state == "live" and row.expires_at > now


def holds_slot(row: ProgramCredential, now: _dt.datetime) -> bool:
    """Counts toward the cap: usable, or `pending` within its deadline."""
    return usable(row, now) or (
        row.state == "pending" and row.pending_deadline is not None and row.pending_deadline > now)


def check_credential_fields(*, kind: str, key_hash: str | None) -> None:
    """A key has its hash and an OAuth client has none (the SQL schema carries it as a CHECK)."""
    if kind not in ("key", "oauth_client"):
        raise DataRuleViolation(f"{kind!r} is not a credential kind")
    if (kind == "key") != (key_hash is not None):
        raise DataRuleViolation("a key has its hash, an OAuth client has none")


def check_role(kind: str, role: str) -> None:
    """A person is `admin`, a program `automation`."""
    if role not in ("admin", "automation"):
        raise DataRuleViolation(f"{role!r} is not a membership role")
    if (kind == "program") != (role == "automation"):
        raise DataRuleViolation(f"a {kind} cannot hold the {role!r} role")


def warning_due(row: ProgramCredential, threshold: _dt.timedelta, now: _dt.datetime) -> bool:
    """The threshold is due, was still ahead when the credential was made, and is not settled."""
    return (row.expires_at - threshold <= now and row.expires_at - threshold >= row.created_at
            and getattr(row, settled_column(threshold)) is None)


def settled_column(threshold: _dt.timedelta) -> str:
    return f"warn_{threshold.days}d_settled_at"


def next_try_column(threshold: _dt.timedelta) -> str:
    return f"warn_{threshold.days}d_next_try_at"


def check_membership_fields(
    status: MembershipStatus, *, accepted_at: _dt.datetime | None, ended_at: _dt.datetime | None,
) -> None:
    """The rule that ties a status to its timestamps (the SQL schema carries it as a CHECK)."""
    if status == "active" and accepted_at is None:
        raise DataRuleViolation("an active membership needs accepted_at")
    if status == "ended" and ended_at is None:
        raise DataRuleViolation("an ended membership needs ended_at")


def _with(row: ProgramCredential, **fields: Any) -> ProgramCredential:
    """The row with `fields` changed; the names come from the column helpers, so they are not typed."""
    return dataclasses.replace(row, **fields)


class InMemoryIdentityRepository:
    """For one event loop: an operation never yields partway, so each applies whole. Tenants are
    read from the in-memory tenant repository given as `tenants` (its store, shared, never copied),
    or from one of its own; this repository writes none."""

    def __init__(self, tenants: InMemoryTenantRepository | None = None) -> None:
        self._tenants = tenants if tenants is not None else InMemoryTenantRepository()
        self._users: dict[str, User] = {}
        self._by_email: dict[str, str] = {}
        self._by_account: dict[str, str] = {}
        self._memberships: dict[str, Membership] = {}
        self._sessions: dict[str, Session] = {}
        self._credentials: dict[str, ProgramCredential] = {}

    # --- tenants -----------------------------------------------------------------------------
    async def close(self) -> None:
        """Nothing is held outside this object."""

    def _active(self, tenant_id: TenantId) -> bool:
        return self._tenants.state_of(tenant_id) == "active"

    async def tenant_exists(self, tenant_id: TenantId) -> bool:
        return self._active(tenant_id)

    async def active_tenants(self, tenant_ids: Collection[TenantId]) -> set[TenantId]:
        return {t for t in tenant_ids if self._active(t)}

    async def tenant_has_active_members(self, tenant_id: TenantId) -> bool:
        return any(m.tenant_id == tenant_id and m.status == "active" and self._users[m.user_id].kind == "person"
                   for m in self._memberships.values())

    # --- users -------------------------------------------------------------------------------
    def _new_user(
        self, email: str | None, *, created_at: _dt.datetime, status: UserStatus = "invited",
        display_name: str = "", signin_account_id: str | None = None, is_platform_admin: bool = False,
    ) -> User:
        if email is None:
            raise DataRuleViolation("a person needs an email address")
        email = normalize_email(email)
        if email in self._by_email:
            raise DataRuleViolation(f"the email {email!r} already belongs to a user")
        if signin_account_id is not None and signin_account_id in self._by_account:
            raise DataRuleViolation(f"the sign-in account {signin_account_id!r} is already recorded")
        user = User.new(
            email, created_at=created_at, status=status, display_name=display_name,
            signin_account_id=signin_account_id, is_platform_admin=is_platform_admin)
        self._users[user.id] = user
        self._by_email[email] = user.id
        if signin_account_id is not None:
            self._by_account[signin_account_id] = user.id
        return user

    async def add_user(
        self, email: str | None, *, created_at: _dt.datetime, status: UserStatus = "invited",
        display_name: str = "", signin_account_id: str | None = None, is_platform_admin: bool = False,
    ) -> User:
        """Seeder."""
        return _copy(self._new_user(
            email, created_at=created_at, status=status, display_name=display_name,
            signin_account_id=signin_account_id, is_platform_admin=is_platform_admin))

    async def ensure_user(self, email: str, *, now: _dt.datetime) -> User:
        existing = self._by_email.get(normalize_email(email))
        return _copy(self._users[existing] if existing else self._new_user(email, created_at=now))

    async def user(self, user_id: UserId) -> User | None:
        return _copy(self._users.get(user_id))

    async def user_by_email(self, email: str) -> User | None:
        found = self._by_email.get(normalize_email(email))
        return _copy(self._users[found]) if found else None

    async def user_by_signin_account(self, account_id: str) -> User | None:
        found = self._by_account.get(account_id)
        return _copy(self._users[found]) if found else None

    async def platform_admins(self) -> list[User]:
        return [_copy(u) for u in self._users.values() if u.is_platform_admin]

    def _update_user(self, user_id: UserId, **changes: Any) -> None:
        self._users[user_id] = dataclasses.replace(self._users[user_id], **changes)

    async def record_signin_account(self, user_id: UserId, account_id: str) -> bool:
        user = self._users.get(user_id)
        if user is None or user.signin_account_id is not None or account_id in self._by_account:
            return False
        self._update_user(user_id, signin_account_id=account_id)
        self._by_account[account_id] = user_id
        return True

    async def activate_user(self, user_id: UserId, *, display_name: str, now: _dt.datetime) -> bool:
        user = self._users.get(user_id)
        if user is None or user.status != "invited":
            return False
        self._update_user(user_id, status="active", activated_at=now, display_name=display_name,
                          updated_at=now)
        return True

    async def set_display_name(self, user_id: UserId, display_name: str, *, now: _dt.datetime) -> None:
        if user_id in self._users and self._users[user_id].display_name != display_name:
            self._update_user(user_id, display_name=display_name, updated_at=now)

    async def set_platform_admin(self, user_id: UserId, flag: bool) -> None:
        if flag and user_id in self._users and self._users[user_id].kind == "program":
            raise DataRuleViolation("a program cannot be a platform administrator")
        if user_id in self._users:
            self._update_user(user_id, is_platform_admin=flag)

    # --- memberships -------------------------------------------------------------------------
    def _live_row(self, user_id: UserId, tenant_id: TenantId) -> Membership | None:
        return next((m for m in self._memberships.values()
                     if m.user_id == user_id and m.tenant_id == tenant_id and m.status in _LIVE), None)

    def _refuse_dangling(self, user_id: UserId, tenant_id: TenantId) -> None:
        if user_id not in self._users:
            raise DataRuleViolation(f"no user {user_id!r}")
        if self._tenants.state_of(tenant_id) is None:
            raise DataRuleViolation(f"no tenant {tenant_id!r}")

    def _refuse_unknown_actor(self, *actors: UserId | None) -> None:
        """An actor (`invited_by`, `ended_by`) is a user or None for the system: the foreign key #1382 gave them."""
        for actor in actors:
            if actor is not None and actor not in self._users:
                raise DataRuleViolation(f"no user {actor!r} to act")

    def _insert_membership(self, **fields: object) -> Membership:
        row = Membership(**fields)  # type: ignore[arg-type]
        self._memberships[row.id] = row
        return row

    async def add_membership(  # noqa: PLR0913 — the pinned seeder signature
        self, user_id: UserId, tenant_id: TenantId, *, status: MembershipStatus, invited_by: UserId | None,
        created_at: _dt.datetime, expires_at: _dt.datetime | None = None,
        accepted_at: _dt.datetime | None = None, ended_at: _dt.datetime | None = None,
        ended_by: UserId | None = None, role: Role = "admin",
    ) -> Membership:
        """Seeder."""
        self._refuse_dangling(user_id, tenant_id)
        check_role(self._users[user_id].kind, role)
        self._refuse_unknown_actor(invited_by, ended_by)
        check_membership_fields(status, accepted_at=accepted_at, ended_at=ended_at)
        if status in _LIVE and self._live_row(user_id, tenant_id) is not None:
            raise DataRuleViolation("the user already has a live membership in this tenant")
        return _copy(self._insert_membership(
            user_id=user_id, tenant_id=tenant_id, status=status, invited_by=invited_by,
            created_at=created_at, expires_at=expires_at, accepted_at=accepted_at,
            ended_at=ended_at, ended_by=ended_by, role=role))

    async def ensure_invitation(
        self, user_id: UserId, tenant_id: TenantId, *, invited_by: UserId | None, now: _dt.datetime,
        expires_at: _dt.datetime | None = None,
    ) -> Membership | None:
        self._refuse_dangling(user_id, tenant_id)
        if self._users[user_id].kind == "program":
            raise DataRuleViolation("a program is never invited")
        live = self._live_row(user_id, tenant_id)
        if live is not None:
            return None if live.status == "active" else _copy(live)
        self._refuse_unknown_actor(invited_by)
        return _copy(self._insert_membership(
            user_id=user_id, tenant_id=tenant_id, status="invited", invited_by=invited_by,
            created_at=now, expires_at=expires_at, accepted_at=None, ended_at=None, ended_by=None))

    def _update_membership(self, membership_id: MembershipId, **changes: Any) -> None:
        self._memberships[membership_id] = dataclasses.replace(self._memberships[membership_id], **changes)

    async def accept_invitation(self, membership_id: MembershipId, *, now: _dt.datetime) -> bool:
        row = self._memberships.get(membership_id)
        if row is None or row.status != "invited" or (row.expires_at is not None and row.expires_at <= now) \
                or not self._active(row.tenant_id):
            return False
        self._update_membership(membership_id, status="active", accepted_at=now)
        return True

    async def end_membership(self, membership_id: MembershipId, *, ended_by: UserId | None, now: _dt.datetime) -> bool:
        row = self._memberships.get(membership_id)
        if row is None or row.status != "active":
            return False
        self._refuse_unknown_actor(ended_by)
        self._update_membership(membership_id, status="ended", ended_at=now, ended_by=ended_by)
        return True

    async def revoke_invitation(self, membership_id: MembershipId) -> bool:
        row = self._memberships.get(membership_id)
        if row is None or row.status != "invited":
            return False
        self._update_membership(membership_id, status="revoked")
        return True

    async def membership(self, membership_id: MembershipId) -> Membership | None:
        return _copy(self._memberships.get(membership_id))

    async def memberships_of_user(self, user_id: UserId) -> list[Membership]:
        return [_copy(m) for m in self._memberships.values() if m.user_id == user_id]

    async def memberships_of_tenant(self, tenant_id: TenantId) -> list[Membership]:
        return [_copy(m) for m in self._memberships.values() if m.tenant_id == tenant_id]

    async def people_of_tenant(
        self, tenant_id: TenantId, status: MembershipStatus,
    ) -> list[tuple[Membership, User]]:
        return [(m, _copy(self._users[m.user_id]))
                for m in await self.memberships_of_tenant(tenant_id)
                if m.status == status and self._users[m.user_id].kind == "person"]

    async def active_membership(self, user_id: UserId, tenant_id: TenantId) -> Membership | None:
        row = self._live_row(user_id, tenant_id)
        return _copy(row) if row is not None and row.status == "active" else None

    # --- programs and their credentials ---------------------------------------------------------
    async def add_program(
        self, tenant_id: TenantId, *, display_name: str, created_by: UserId, now: _dt.datetime,
    ) -> User:
        creator = self._users.get(created_by)
        if creator is None or creator.kind != "person":
            raise DataRuleViolation(f"no person {created_by!r} to create a program")
        if self._tenants.state_of(tenant_id) is None:
            raise DataRuleViolation(f"no tenant {tenant_id!r}")
        program = User.new_program(display_name=display_name, created_by=created_by, created_at=now)
        self._users[program.id] = program
        self._insert_membership(
            user_id=program.id, tenant_id=tenant_id, status="active", invited_by=created_by, created_at=now,
            accepted_at=now, role="automation")
        return _copy(program)

    async def programs_of_tenant(self, tenant_id: TenantId) -> list[User]:
        rows = [m for m in self._memberships.values()
                if m.tenant_id == tenant_id and m.status == "active" and self._users[m.user_id].kind == "program"]
        return [_copy(self._users[m.user_id]) for m in sorted(rows, key=lambda m: (m.created_at, m.id))]

    def _revoke(self, row: ProgramCredential, *, by: UserId | None, now: _dt.datetime) -> None:
        self._credentials[row.id] = dataclasses.replace(row, state="revoked", revoked_at=now, revoked_by=by)

    async def remove_program(self, program_id: UserId, *, removed_by: UserId | None, now: _dt.datetime) -> bool:
        program = self._users.get(program_id)
        membership = next((m for m in self._memberships.values() if m.user_id == program_id and m.status == "active"), None)
        if program is None or program.kind != "program" or membership is None:
            return False
        self._refuse_unknown_actor(removed_by)
        self._update_membership(membership.id, status="ended", ended_at=now, ended_by=removed_by)
        for row in list(self._credentials.values()):
            if row.program_id == program_id and row.state in ("pending", "live"):
                self._revoke(row, by=removed_by, now=now)
        return True

    async def add_credential(
        self, program_id: UserId, *, kind: CredentialKind, name: str, created_by: UserId,
        expires_at: _dt.datetime, now: _dt.datetime, key_hash: str | None = None,
        credential_id: CredentialId | None = None,
    ) -> ProgramCredential:
        program = self._users.get(program_id)
        if program is None or program.kind != "program":
            raise DataRuleViolation(f"{program_id!r} is no program")
        if not any(m.user_id == program_id and m.status == "active" for m in self._memberships.values()):
            raise DataRuleViolation("the program has no active membership")
        check_credential_fields(kind=kind, key_hash=key_hash)
        self._refuse_unknown_actor(created_by)
        if sum(holds_slot(r, now) for r in self._credentials.values() if r.program_id == program_id) >= CREDENTIAL_CAP:
            raise DataRuleViolation("the program already has two credentials in use or being made")
        if key_hash is not None and any(r.key_hash == key_hash and r.state != "revoked" for r in self._credentials.values()):
            raise DataRuleViolation("a credential with this key hash exists")
        row = ProgramCredential(
            id=credential_id or CredentialId.mint(),
            program_id=program_id, kind=kind, name=name, state="live" if kind == "key" else "pending",
            created_by=created_by, created_at=now, expires_at=expires_at, key_hash=key_hash,
            pending_deadline=now + PENDING_DEADLINE if kind == "oauth_client" else None)
        self._credentials[row.id] = row
        return _copy(row)

    async def go_live(self, credential_id: CredentialId, *, service_account_id: str, now: _dt.datetime) -> bool:
        row = self._credentials.get(credential_id)
        if (row is None or row.state != "pending" or row.pending_deadline is None or row.pending_deadline <= now
                or not any(m.user_id == row.program_id and m.status == "active" for m in self._memberships.values())):
            return False
        self._credentials[row.id] = dataclasses.replace(row, state="live", service_account_id=service_account_id)
        return True

    async def revoke_credential(self, credential_id: CredentialId, *, revoked_by: UserId | None, now: _dt.datetime) -> bool:
        row = self._credentials.get(credential_id)
        if row is None or row.state == "revoked":
            return False
        self._refuse_unknown_actor(revoked_by)
        self._revoke(row, by=revoked_by, now=now)
        return True

    async def credential_by_id(self, credential_id: CredentialId) -> ProgramCredential | None:
        return _copy(self._credentials.get(credential_id))

    async def credential_by_hash(self, key_hash: str) -> ProgramCredential | None:
        return _copy(next((r for r in self._credentials.values() if r.key_hash == key_hash), None))

    async def credentials_of_program(self, program_id: UserId) -> list[ProgramCredential]:
        rows = [r for r in self._credentials.values() if r.program_id == program_id]
        return [_copy(r) for r in sorted(rows, key=lambda r: (r.created_at, r.id))]

    async def touch_credential(self, credential_id: CredentialId, *, now: _dt.datetime) -> bool:
        row = self._credentials.get(credential_id)
        if row is None or (row.last_used_at is not None and now - row.last_used_at <= TOUCH_AFTER):
            return False
        self._credentials[row.id] = dataclasses.replace(row, last_used_at=now)
        return True

    async def revoke_stale_pending(self, *, now: _dt.datetime) -> list[CredentialId]:
        stale = [r for r in self._credentials.values()
                 if r.state == "pending" and r.pending_deadline is not None and r.pending_deadline <= now]
        for row in stale:
            self._revoke(row, by=None, now=now)
        return [r.id for r in stale]

    async def oauth_credentials_to_keep(self, *, now: _dt.datetime) -> set[CredentialId]:
        return {r.id for r in self._credentials.values() if r.kind == "oauth_client" and holds_slot(r, now)}

    async def claim_expiry_warning(self, *, now: _dt.datetime, hold_until: _dt.datetime) -> ExpiryWarning | None:
        for row in sorted(self._credentials.values(), key=lambda r: (r.expires_at, r.id)):
            if not usable(row, now):
                continue
            due = [t for t in WARNING_THRESHOLDS if warning_due(row, t, now)]
            if not due:
                continue
            tightest = due[-1]
            for looser in due[:-1]:
                row = _with(row, **{settled_column(looser): now, next_try_column(looser): None})
            self._credentials[row.id] = row
            if not _due(getattr(row, next_try_column(tightest)), now):
                continue
            self._credentials[row.id] = _with(row, **{next_try_column(tightest): hold_until})
            return ExpiryWarning(credential_id=row.id, threshold=tightest)
        return None

    async def settle_expiry_warning(
        self, credential_id: CredentialId, threshold: _dt.timedelta, *, sent_at: _dt.datetime,
    ) -> bool:
        row = self._credentials.get(credential_id)
        if row is None or not is_warning_threshold(threshold) or getattr(row, settled_column(threshold)) is not None:
            return False
        self._credentials[row.id] = _with(
            row, **{settled_column(threshold): sent_at, next_try_column(threshold): None})
        return True

    async def defer_expiry_warning(
        self, credential_id: CredentialId, threshold: _dt.timedelta, *, until: _dt.datetime,
    ) -> None:
        row = self._credentials.get(credential_id)
        if row is not None and is_warning_threshold(threshold):
            self._credentials[row.id] = _with(row, **{next_try_column(threshold): until})

    # --- sends -------------------------------------------------------------------------------
    async def request_set_password(self, user_id: UserId, *, now: _dt.datetime) -> int:
        if user_id not in self._users:
            raise DataRuleViolation(f"no user {user_id!r}")
        seq = self._users[user_id].set_password_requested_seq + 1
        self._update_user(user_id, set_password_requested_seq=seq, set_password_requested_at=now)
        return seq

    async def request_notification(self, membership_id: MembershipId, *, now: _dt.datetime) -> int:
        if membership_id not in self._memberships:
            raise DataRuleViolation(f"no membership {membership_id!r}")
        seq = self._memberships[membership_id].notify_requested_seq + 1
        self._update_membership(membership_id, notify_requested_seq=seq, notify_requested_at=now)
        return seq

    async def claim_set_password(
        self, *, now: _dt.datetime, hold_until: _dt.datetime, skip: Collection[UserId] = (),
    ) -> User | None:
        found = next((u for u in self._users.values()
                      if u.status == "invited" and u.set_password_requested_seq > u.set_password_sent_seq
                      and _due(u.set_password_next_try_at, now) and u.id not in skip), None)
        if found is None:
            return None
        self._update_user(found.id, set_password_next_try_at=hold_until)
        return _copy(self._users[found.id])

    async def claim_notification(
        self, *, now: _dt.datetime, hold_until: _dt.datetime, skip: Collection[MembershipId] = (),
    ) -> Membership | None:
        found = next((m for m in self._memberships.values()
                      if m.status == "invited" and m.notify_requested_seq > m.notify_sent_seq
                      and _due(m.notify_next_try_at, now) and m.id not in skip), None)
        if found is None:
            return None
        self._update_membership(found.id, notify_next_try_at=hold_until)
        return _copy(self._memberships[found.id])

    async def defer_set_password(self, user_id: UserId, *, until: _dt.datetime) -> None:
        if user_id not in self._users:
            return
        attempts = self._users[user_id].set_password_attempts + 1
        self._update_user(user_id, set_password_attempts=attempts, set_password_next_try_at=until)

    async def defer_notification(self, membership_id: MembershipId, *, until: _dt.datetime) -> None:
        if membership_id not in self._memberships:
            return
        attempts = self._memberships[membership_id].notify_attempts + 1
        self._update_membership(membership_id, notify_attempts=attempts, notify_next_try_at=until)

    async def settle_set_password(
        self, user_id: UserId, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        user = self._users.get(user_id)
        if user is None or not user.set_password_sent_seq < read_seq <= user.set_password_requested_seq:
            return False
        changes: dict[str, object] = {
            "set_password_sent_seq": read_seq, "set_password_attempts": 0, "set_password_next_try_at": None}
        if sent_at is not None:
            changes["set_password_sent_at"] = sent_at
        self._update_user(user_id, **changes)
        if sent_at is not None and expires_at is not None:
            for row in list(self._memberships.values()):
                if row.user_id == user_id and row.status == "invited":
                    self._update_membership(row.id, expires_at=expires_at)
        return True

    async def settle_notification(
        self, membership_id: MembershipId, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        row = self._memberships.get(membership_id)
        if row is None or not row.notify_sent_seq < read_seq <= row.notify_requested_seq:
            return False
        changes: dict[str, object] = {
            "notify_sent_seq": read_seq, "notify_attempts": 0, "notify_next_try_at": None}
        if sent_at is not None:
            changes["notified_at"] = sent_at
            if row.status == "invited" and expires_at is not None:
                changes["expires_at"] = expires_at
        self._update_membership(membership_id, **changes)
        return True

    # --- sessions ----------------------------------------------------------------------------
    async def add_session(
        self, value: str, user_id: UserId, *, now: _dt.datetime, expires_at: _dt.datetime,
        used_otp: bool = False,
    ) -> Session:
        if user_id not in self._users:
            raise DataRuleViolation(f"no user {user_id!r}")
        if session_hash(value) in self._sessions:
            raise DataRuleViolation("a session with this value already exists")
        row = Session(token_hash=session_hash(value), user_id=user_id, used_otp=used_otp,
                      created_at=now, last_seen_at=now, expires_at=expires_at)
        self._sessions[row.token_hash] = row
        return _copy(row)

    async def session_by_value(self, value: str) -> Session | None:
        return _copy(self._sessions.get(session_hash(value)))

    async def delete_session(self, value: str) -> bool:
        return self._sessions.pop(session_hash(value), None) is not None

    async def touch_session(self, value: str, *, now: _dt.datetime) -> bool:
        key = session_hash(value)
        row = self._sessions.get(key)
        if row is None or now - row.last_seen_at <= TOUCH_AFTER:
            return False
        self._sessions[key] = dataclasses.replace(row, last_seen_at=now)
        return True

    async def purge_expired_sessions(self, *, now: _dt.datetime, idle_since: _dt.datetime) -> int:
        expired = [key for key, row in self._sessions.items()
                   if row.expires_at <= now or row.last_seen_at < idle_since]
        for key in expired:
            del self._sessions[key]
        return len(expired)
