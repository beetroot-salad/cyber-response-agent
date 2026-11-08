"""The PostgreSQL identity repository: the same rules as `InMemoryIdentityRepository`, held by the
schema the migrations create (unique indexes, CHECKs, foreign keys) and by conditional updates, and
answering the same contract suite. Needs `psycopg` and SQLAlchemy (the `database` extra); nothing else
imports this module.

Each operation is one transaction on a pooled async connection. Concurrency-sensitive writes are
explicit statements (a user-row lock, `FOR UPDATE SKIP LOCKED` claims, conditional updates that
report whether they applied); the rest are ORM queries. A returned model is a detached copy with
every field loaded. The tables come from `defender.migrations`, never from this module."""

from __future__ import annotations

import datetime as _dt
from collections.abc import AsyncIterator, Collection
from contextlib import asynccontextmanager
from typing import Any, cast

from sqlalchemy import case, delete, exists, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from defender.database import async_engine, sessions
from defender.records.formats import CredentialId, MembershipId, TenantId, UserId
from defender.tenancy.models import TenantRecord

from .errors import DataRuleViolation
from .memory import (
    CREDENTIAL_CAP, PENDING_DEADLINE, TOUCH_AFTER, check_credential_fields, check_membership_fields, check_role,
    first_warning, is_warning_threshold, secret_hash, tightest_due, warning_after,
)
from .models import (
    CredentialKind, CredentialWarningDelivery, Membership, MembershipStatus, ProgramCredential, Role, Session, User,
    UserStatus, normalize_email,
)
from .ports import ExpiryWarning

_LIVE = ("invited", "active")


def _active_tenant(tenant_id: Any) -> Any:
    """`tenant_id` names an `active` tenant: a condition to put inside the statement that needs it."""
    return (TenantRecord.id == tenant_id) & (TenantRecord.state == "active")


class PostgresIdentityRepository:
    def __init__(self, dsn: str, *, max_connections: int = 10) -> None:
        self._engine = async_engine(dsn, max_connections=max_connections)
        self._sessions = sessions(self._engine)

    async def close(self) -> None:
        await self._engine.dispose()

    # --- plumbing ----------------------------------------------------------------------------
    @asynccontextmanager
    async def _tx(self) -> AsyncIterator[AsyncSession]:
        """One transaction; a write the schema refuses is the port's `DataRuleViolation`."""
        try:
            async with self._sessions() as session, session.begin():
                yield session
        except IntegrityError as e:
            raise DataRuleViolation(str(e.orig).splitlines()[0]) from e

    async def _one(self, statement: Any) -> Any:
        async with self._tx() as s:
            return (await s.execute(statement)).scalars().first()

    async def _all(self, statement: Any) -> list[Any]:
        async with self._tx() as s:
            return list((await s.execute(statement)).scalars())

    async def _applied(self, statement: Any) -> bool:
        """Whether a conditional `UPDATE ... RETURNING` changed a row."""
        async with self._tx() as s:
            return (await s.execute(statement)).first() is not None

    # --- tenants: read from `tenancy.tenants`, never written here (#1214) ----------------------
    async def tenant_exists(self, tenant_id: TenantId) -> bool:
        return await self._one(select(exists().where(_active_tenant(tenant_id)))) is True

    async def active_tenants(self, tenant_ids: Collection[TenantId]) -> set[TenantId]:
        wanted = set(tenant_ids)
        if not wanted:
            return set()
        return set(await self._all(select(TenantRecord.id).where(
            TenantRecord.id.in_(wanted), TenantRecord.state == "active")))

    async def tenant_has_active_members(self, tenant_id: TenantId) -> bool:
        return await self._one(select(exists().where(
            Membership.tenant_id == tenant_id, Membership.status == "active",
            Membership.user_id == User.id, User.kind == "person"))) is True

    # --- users -------------------------------------------------------------------------------
    async def add_user(
        self, email: str | None, *, created_at: _dt.datetime, status: UserStatus = "invited",
        display_name: str = "", signin_account_id: str | None = None, is_platform_admin: bool = False,
    ) -> User:
        """Seeder."""
        user = User.new(
            email, created_at=created_at, status=status, display_name=display_name,
            signin_account_id=signin_account_id, is_platform_admin=is_platform_admin)
        async with self._tx() as s:
            s.add(user)
        return user

    async def ensure_user(self, email: str, *, now: _dt.datetime) -> User:
        email = normalize_email(email)
        new = User.new(email, created_at=now)
        async with self._tx() as s:
            columns = {c.name: getattr(new, c.name) for c in User.__table__.columns}
            inserted = (await s.execute(
                insert(User).values(**columns).on_conflict_do_nothing(index_elements=["email"])
                .returning(User.id))).first()
            if inserted is not None:
                return new
            existing = (await s.execute(select(User).where(User.email == email))).scalars().first()
        assert existing is not None
        return existing

    async def user(self, user_id: UserId) -> User | None:
        return await self._one(select(User).where(User.id == user_id))

    async def user_by_email(self, email: str) -> User | None:
        return await self._one(select(User).where(User.email == normalize_email(email)))

    async def user_by_signin_account(self, account_id: str) -> User | None:
        return await self._one(select(User).where(User.signin_account_id == account_id))

    async def platform_admins(self) -> list[User]:
        return await self._all(select(User).where(User.is_platform_admin).order_by(User.created_at, User.id))

    async def record_signin_account(self, user_id: UserId, account_id: str) -> bool:
        try:
            return await self._applied(
                update(User).where(User.id == user_id, User.signin_account_id.is_(None))
                .values(signin_account_id=account_id).returning(User.id))
        except DataRuleViolation:
            return False

    async def activate_user(self, user_id: UserId, *, display_name: str, now: _dt.datetime) -> bool:
        return await self._applied(
            update(User).where(User.id == user_id, User.status == "invited")
            .values(status="active", activated_at=now, display_name=display_name, updated_at=now)
            .returning(User.id))

    async def set_display_name(self, user_id: UserId, display_name: str, *, now: _dt.datetime) -> None:
        async with self._tx() as s:
            await s.execute(update(User).where(User.id == user_id, User.display_name != display_name)
                            .values(display_name=display_name, updated_at=now))

    async def set_platform_admin(self, user_id: UserId, flag: bool) -> None:
        async with self._tx() as s:
            await s.execute(update(User).where(User.id == user_id).values(is_platform_admin=flag))

    # --- memberships -------------------------------------------------------------------------
    async def add_membership(  # noqa: PLR0913 — the pinned seeder signature
        self, user_id: UserId, tenant_id: TenantId, *, status: MembershipStatus, invited_by: UserId | None,
        created_at: _dt.datetime, expires_at: _dt.datetime | None = None,
        accepted_at: _dt.datetime | None = None, ended_at: _dt.datetime | None = None,
        ended_by: UserId | None = None, role: Role = "admin",
    ) -> Membership:
        """Seeder."""
        check_membership_fields(status, accepted_at=accepted_at, ended_at=ended_at)
        row = Membership(
            user_id=user_id, tenant_id=tenant_id, status=status, invited_by=invited_by, created_at=created_at,
            expires_at=expires_at, accepted_at=accepted_at, ended_at=ended_at, ended_by=ended_by, role=role)
        async with self._tx() as s:
            kind = (await s.execute(select(User.kind).where(User.id == user_id))).scalars().first()
            if kind is not None:
                check_role(kind, role)
            s.add(row)
        return row

    async def ensure_invitation(
        self, user_id: UserId, tenant_id: TenantId, *, invited_by: UserId | None, now: _dt.datetime,
        expires_at: _dt.datetime | None = None,
    ) -> Membership | None:
        async with self._tx() as s:
            locked = (await s.execute(select(User.kind).where(User.id == user_id).with_for_update())).first()
            if locked is None:
                raise DataRuleViolation(f"no user {user_id!r}")
            if locked[0] == "program":
                raise DataRuleViolation("a program is never invited")
            live = (await s.execute(select(Membership).where(
                Membership.user_id == user_id, Membership.tenant_id == tenant_id,
                Membership.status.in_(_LIVE)))).scalars().first()
            if live is not None:
                return None if live.status == "active" else live
            row = Membership(
                user_id=user_id, tenant_id=tenant_id, status="invited", invited_by=invited_by, created_at=now,
                expires_at=expires_at)
            s.add(row)
        return row

    async def accept_invitation(self, membership_id: MembershipId, *, now: _dt.datetime) -> bool:
        return await self._applied(
            update(Membership).where(
                Membership.id == membership_id, Membership.status == "invited",
                (Membership.expires_at.is_(None)) | (Membership.expires_at > now),
                exists().where(_active_tenant(Membership.tenant_id)))
            .values(status="active", accepted_at=now).returning(Membership.id))

    async def end_membership(self, membership_id: MembershipId, *, ended_by: UserId | None, now: _dt.datetime) -> bool:
        return await self._applied(
            update(Membership).where(Membership.id == membership_id, Membership.status == "active")
            .values(status="ended", ended_at=now, ended_by=ended_by).returning(Membership.id))

    async def revoke_invitation(self, membership_id: MembershipId) -> bool:
        return await self._applied(
            update(Membership).where(Membership.id == membership_id, Membership.status == "invited")
            .values(status="revoked").returning(Membership.id))

    async def membership(self, membership_id: MembershipId) -> Membership | None:
        return await self._one(select(Membership).where(Membership.id == membership_id))

    async def memberships_of_user(self, user_id: UserId) -> list[Membership]:
        return await self._all(select(Membership).where(Membership.user_id == user_id)
                               .order_by(Membership.created_at, Membership.id))

    async def memberships_of_tenant(self, tenant_id: TenantId) -> list[Membership]:
        return await self._all(select(Membership).where(Membership.tenant_id == tenant_id)
                               .order_by(Membership.created_at, Membership.id))

    async def people_of_tenant(
        self, tenant_id: TenantId, status: MembershipStatus,
    ) -> list[tuple[Membership, User]]:
        async with self._tx() as s:
            rows = (await s.execute(
                select(Membership, User).join(User, User.id == Membership.user_id)
                .where(Membership.tenant_id == tenant_id, Membership.status == status, User.kind == "person")
                .order_by(Membership.created_at, Membership.id))).all()
        return [(m, u) for m, u in rows]

    async def active_membership(self, user_id: UserId, tenant_id: TenantId) -> Membership | None:
        return await self._one(select(Membership).where(
            Membership.user_id == user_id, Membership.tenant_id == tenant_id,
            Membership.status == "active"))

    # --- programs and their credentials -------------------------------------------------------
    @staticmethod
    async def _lock_program(s: AsyncSession, program_id: UserId) -> str | None:
        """The program's user row, locked until the transaction ends (the one lock per program); its kind."""
        found = (await s.execute(select(User.kind).where(User.id == program_id).with_for_update())).first()
        return None if found is None else str(found[0])

    async def add_program(
        self, tenant_id: TenantId, *, display_name: str, created_by: UserId, now: _dt.datetime,
    ) -> User:
        program = User.new_program(display_name=display_name, created_by=created_by, created_at=now)
        membership = Membership(
            user_id=program.id, tenant_id=tenant_id, status="active", invited_by=created_by, created_at=now,
            accepted_at=now, role="automation")
        async with self._tx() as s:
            creator = (await s.execute(select(User.kind).where(User.id == created_by))).scalars().first()
            if creator != "person":
                raise DataRuleViolation(f"no person {created_by!r} to create a program")
            s.add(program)
            await s.flush()
            s.add(membership)
        return program

    async def programs_of_tenant(self, tenant_id: TenantId) -> list[User]:
        async with self._tx() as s:
            return list((await s.execute(
                select(User).join(Membership, Membership.user_id == User.id)
                .where(Membership.tenant_id == tenant_id, Membership.status == "active", User.kind == "program")
                .order_by(Membership.created_at, Membership.id))).scalars())

    async def remove_program(
        self, program_id: UserId, *, removed_by: UserId | None, now: _dt.datetime,
    ) -> list[CredentialId] | None:
        async with self._tx() as s:
            if await self._lock_program(s, program_id) != "program":
                return None
            ended = (await s.execute(
                update(Membership).where(Membership.user_id == program_id, Membership.status == "active")
                .values(status="ended", ended_at=now, ended_by=removed_by).returning(Membership.id))).first()
            if ended is None:
                return None
            revoked = (await s.execute(
                update(ProgramCredential).where(
                    ProgramCredential.program_id == program_id, ProgramCredential.state.in_(("pending", "live")))
                .values(state="revoked", revoked_at=now, revoked_by=removed_by)
                .returning(ProgramCredential.id, ProgramCredential.created_at))).all()
            return [r.id for r in sorted(revoked, key=lambda r: (r.created_at, r.id))]

    async def add_credential(
        self, program_id: UserId, *, kind: CredentialKind, name: str, created_by: UserId,
        expires_at: _dt.datetime, now: _dt.datetime, key_hash: str | None = None,
        credential_id: CredentialId | None = None,
    ) -> ProgramCredential | None:
        check_credential_fields(kind=kind, key_hash=key_hash)
        row = ProgramCredential(
            id=credential_id or CredentialId.mint(),
            program_id=program_id, kind=kind, name=name, state="live" if kind == "key" else "pending",
            created_by=created_by, created_at=now, expires_at=expires_at, key_hash=key_hash,
            pending_deadline=now + PENDING_DEADLINE if kind == "oauth_client" else None)
        row.warn_threshold_days, row.warn_next_at = first_warning(now, expires_at)
        async with self._tx() as s:
            if await self._lock_program(s, program_id) != "program":
                raise DataRuleViolation(f"{program_id!r} is no program")
            if not (await s.execute(select(exists().where(
                    Membership.user_id == program_id, Membership.status == "active")))).scalar():
                return None
            slots = (await s.execute(select(func.count()).select_from(ProgramCredential).where(
                ProgramCredential.program_id == program_id,
                or_((ProgramCredential.state == "live") & (ProgramCredential.expires_at > now),
                    (ProgramCredential.state == "pending") & (ProgramCredential.pending_deadline > now))))).scalar_one()
            if slots >= CREDENTIAL_CAP:
                raise DataRuleViolation("the program already has two credentials in use or being made")
            s.add(row)
        return row

    async def go_live(self, credential_id: CredentialId, *, service_account_id: str, now: _dt.datetime) -> bool:
        async with self._tx() as s:
            program_id = (await s.execute(
                select(ProgramCredential.program_id).where(ProgramCredential.id == credential_id))).scalars().first()
            if program_id is None:
                return False
            await self._lock_program(s, program_id)
            return (await s.execute(
                update(ProgramCredential).where(
                    ProgramCredential.id == credential_id, ProgramCredential.state == "pending",
                    ProgramCredential.pending_deadline > now,
                    exists().where(Membership.user_id == ProgramCredential.program_id, Membership.status == "active"))
                .values(state="live", service_account_id=service_account_id)
                .returning(ProgramCredential.id))).first() is not None

    async def revoke_credential(self, credential_id: CredentialId, *, revoked_by: UserId | None, now: _dt.datetime) -> bool:
        async with self._tx() as s:
            program_id = (await s.execute(
                select(ProgramCredential.program_id).where(ProgramCredential.id == credential_id))).scalars().first()
            if program_id is None:
                return False
            await self._lock_program(s, program_id)
            return (await s.execute(
                update(ProgramCredential).where(
                    ProgramCredential.id == credential_id, ProgramCredential.state.in_(("pending", "live")))
                .values(state="revoked", revoked_at=now, revoked_by=revoked_by)
                .returning(ProgramCredential.id))).first() is not None

    async def credential_by_id(self, credential_id: CredentialId) -> ProgramCredential | None:
        return await self._one(select(ProgramCredential).where(ProgramCredential.id == credential_id))

    async def credential_by_hash(self, key_hash: str) -> ProgramCredential | None:
        return await self._one(select(ProgramCredential).where(ProgramCredential.key_hash == key_hash))

    async def credentials_of_program(self, program_id: UserId) -> list[ProgramCredential]:
        return await self._all(select(ProgramCredential).where(ProgramCredential.program_id == program_id)
                               .order_by(ProgramCredential.created_at, ProgramCredential.id))

    async def touch_credential(self, credential_id: CredentialId, *, now: _dt.datetime) -> bool:
        return await self._applied(
            update(ProgramCredential).where(
                ProgramCredential.id == credential_id,
                or_(ProgramCredential.last_used_at.is_(None), now - ProgramCredential.last_used_at > TOUCH_AFTER))
            .values(last_used_at=now).returning(ProgramCredential.id))

    async def revoke_stale_pending(self, *, now: _dt.datetime) -> list[CredentialId]:
        async with self._tx() as s:
            return [row[0] for row in (await s.execute(
                update(ProgramCredential).where(
                    ProgramCredential.state == "pending", ProgramCredential.pending_deadline <= now)
                .values(state="revoked", revoked_at=now, revoked_by=None)
                .returning(ProgramCredential.id))).all()]

    async def oauth_credentials_to_keep(self, *, now: _dt.datetime) -> set[CredentialId]:
        return set(await self._all(select(ProgramCredential.id).where(
            ProgramCredential.kind == "oauth_client",
            or_((ProgramCredential.state == "live") & (ProgramCredential.expires_at > now),
                (ProgramCredential.state == "pending") & (ProgramCredential.pending_deadline > now)))))

    async def claim_expiry_warning(self, *, now: _dt.datetime, hold_until: _dt.datetime) -> ExpiryWarning | None:
        async with self._tx() as s:
            row = (await s.execute(
                select(ProgramCredential).where(
                    ProgramCredential.state == "live", ProgramCredential.expires_at > now,
                    ProgramCredential.warn_next_at <= now)
                .order_by(ProgramCredential.warn_next_at, ProgramCredential.id)
                .limit(1).with_for_update(skip_locked=True))).scalars().first()
            if row is None:
                return None
            threshold = tightest_due(row, now)
            row.warn_threshold_days, row.warn_next_at = threshold.days, hold_until
            return ExpiryWarning(credential_id=row.id, threshold=threshold)

    async def settle_expiry_warning(self, credential_id: CredentialId, threshold: _dt.timedelta) -> bool:
        if not is_warning_threshold(threshold):
            return False
        async with self._tx() as s:
            row = (await s.execute(select(ProgramCredential).where(
                ProgramCredential.id == credential_id, ProgramCredential.warn_threshold_days == threshold.days)
                .with_for_update())).scalars().first()
            if row is None:
                return False
            row.warn_threshold_days, row.warn_next_at = warning_after(threshold, row.expires_at)
            return True

    async def defer_expiry_warning(
        self, credential_id: CredentialId, threshold: _dt.timedelta, *, until: _dt.datetime,
    ) -> None:
        if not is_warning_threshold(threshold):
            return
        async with self._tx() as s:
            await s.execute(update(ProgramCredential).where(
                ProgramCredential.id == credential_id, ProgramCredential.warn_threshold_days == threshold.days)
                .values(warn_next_at=until))

    async def warning_deliveries(self, credential_id: CredentialId, threshold: _dt.timedelta) -> set[UserId]:
        return set(await self._all(select(CredentialWarningDelivery.person_id).where(
            CredentialWarningDelivery.credential_id == credential_id,
            CredentialWarningDelivery.threshold_days == threshold.days)))

    async def record_warning_delivery(
        self, credential_id: CredentialId, threshold: _dt.timedelta, person_id: UserId, *, sent_at: _dt.datetime,
    ) -> None:
        if not is_warning_threshold(threshold):
            raise DataRuleViolation(f"{threshold} is no warning threshold")
        async with self._tx() as s:
            await s.execute(insert(CredentialWarningDelivery).values(
                credential_id=credential_id, threshold_days=threshold.days, person_id=person_id, sent_at=sent_at)
                .on_conflict_do_nothing())

    # --- sends -------------------------------------------------------------------------------
    async def request_set_password(self, user_id: UserId, *, now: _dt.datetime) -> int:
        seq = await self._one(
            update(User).where(User.id == user_id)
            .values(set_password_requested_seq=User.set_password_requested_seq + 1, set_password_requested_at=now)
            .returning(User.set_password_requested_seq))
        if seq is None:
            raise DataRuleViolation(f"no user {user_id!r}")
        return int(seq)

    async def request_notification(self, membership_id: MembershipId, *, now: _dt.datetime) -> int:
        seq = await self._one(
            update(Membership).where(Membership.id == membership_id)
            .values(notify_requested_seq=Membership.notify_requested_seq + 1, notify_requested_at=now)
            .returning(Membership.notify_requested_seq))
        if seq is None:
            raise DataRuleViolation(f"no membership {membership_id!r}")
        return int(seq)

    async def claim_set_password(
        self, *, now: _dt.datetime, hold_until: _dt.datetime, skip: Collection[UserId] = (),
    ) -> User | None:
        due = (select(User.id).where(
            User.status == "invited", User.set_password_requested_seq > User.set_password_sent_seq,
            (User.set_password_next_try_at.is_(None)) | (User.set_password_next_try_at <= now),
            User.id.not_in(list(skip)))
            .order_by(User.created_at, User.id).limit(1).with_for_update(skip_locked=True))
        return await self._one(
            update(User).where(User.id == due.scalar_subquery()).values(set_password_next_try_at=hold_until)
            .returning(User).execution_options(synchronize_session=False))

    async def claim_notification(
        self, *, now: _dt.datetime, hold_until: _dt.datetime, skip: Collection[MembershipId] = (),
    ) -> Membership | None:
        due = (select(Membership.id).where(
            Membership.status == "invited", Membership.notify_requested_seq > Membership.notify_sent_seq,
            (Membership.notify_next_try_at.is_(None)) | (Membership.notify_next_try_at <= now),
            Membership.id.not_in(list(skip)))
            .order_by(Membership.created_at, Membership.id).limit(1).with_for_update(skip_locked=True))
        return await self._one(
            update(Membership).where(Membership.id == due.scalar_subquery())
            .values(notify_next_try_at=hold_until)
            .returning(Membership).execution_options(synchronize_session=False))

    async def defer_set_password(self, user_id: UserId, *, until: _dt.datetime) -> None:
        async with self._tx() as s:
            await s.execute(update(User).where(User.id == user_id).values(
                set_password_attempts=User.set_password_attempts + 1, set_password_next_try_at=until))

    async def defer_notification(self, membership_id: MembershipId, *, until: _dt.datetime) -> None:
        async with self._tx() as s:
            await s.execute(update(Membership).where(Membership.id == membership_id).values(
                notify_attempts=Membership.notify_attempts + 1, notify_next_try_at=until))

    async def settle_set_password(
        self, user_id: UserId, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        values: dict[str, Any] = {
            "set_password_sent_seq": read_seq, "set_password_attempts": 0, "set_password_next_try_at": None}
        if sent_at is not None:
            values["set_password_sent_at"] = sent_at
        async with self._tx() as s:
            applied = (await s.execute(
                update(User).where(
                    User.id == user_id, User.set_password_sent_seq < read_seq,
                    read_seq <= User.set_password_requested_seq)
                .values(**values).returning(User.id))).first() is not None
            if applied and sent_at is not None and expires_at is not None:
                await s.execute(update(Membership).where(
                    Membership.user_id == user_id, Membership.status == "invited")
                    .values(expires_at=expires_at))
            return applied

    async def settle_notification(
        self, membership_id: MembershipId, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        values: dict[str, Any] = {
            "notify_sent_seq": read_seq, "notify_attempts": 0, "notify_next_try_at": None}
        if sent_at is not None:
            values["notified_at"] = sent_at
            if expires_at is not None:
                values["expires_at"] = case(
                    (Membership.status == "invited", expires_at), else_=Membership.expires_at)
        return await self._applied(
            update(Membership).where(
                Membership.id == membership_id, Membership.notify_sent_seq < read_seq,
                read_seq <= Membership.notify_requested_seq)
            .values(**values).returning(Membership.id))

    # --- sessions ----------------------------------------------------------------------------
    async def add_session(
        self, value: str, user_id: UserId, *, now: _dt.datetime, expires_at: _dt.datetime,
        used_otp: bool = False,
    ) -> Session:
        row = Session(token_hash=secret_hash(value), user_id=user_id, used_otp=used_otp,
                      created_at=now, last_seen_at=now, expires_at=expires_at)
        async with self._tx() as s:
            s.add(row)
        return row

    async def session_by_value(self, value: str) -> Session | None:
        return await self._one(select(Session).where(Session.token_hash == secret_hash(value)))

    async def delete_session(self, value: str) -> bool:
        return await self._applied(
            delete(Session).where(Session.token_hash == secret_hash(value)).returning(Session.token_hash))

    async def touch_session(self, value: str, *, now: _dt.datetime) -> bool:
        return await self._applied(
            update(Session).where(
                Session.token_hash == secret_hash(value), now - Session.last_seen_at > TOUCH_AFTER)
            .values(last_seen_at=now).returning(Session.token_hash))

    async def purge_expired_sessions(self, *, now: _dt.datetime, idle_since: _dt.datetime) -> int:
        async with self._tx() as s:
            deleted = await s.execute(delete(Session).where(
                or_(Session.expires_at <= now, Session.last_seen_at < idle_since)))
            return cast(CursorResult[Any], deleted).rowcount  # a DML statement's result is a CursorResult
