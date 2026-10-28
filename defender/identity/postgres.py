"""The PostgreSQL identity repository: the same rules as `InMemoryIdentityRepository`, held by the
schema the migrations create (unique indexes, CHECKs, foreign keys) and by conditional updates, and
answering the same contract suite. Needs `psycopg` and SQLAlchemy (the `api` extra); nothing else
imports this module.

Each operation is one transaction on a pooled async connection. Concurrency-sensitive writes are
explicit statements (a user-row lock, `FOR UPDATE SKIP LOCKED` claims, conditional updates that
report whether they applied); the rest are ORM queries. A returned model is a detached copy with
every field loaded. The tables come from `defender.migrations`, never from this module."""

from __future__ import annotations

import datetime as _dt
import uuid
from collections.abc import AsyncIterator, Collection
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import case, delete, exists, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from defender.database import async_engine, sessions
from defender.records._tenant_id import TenantId

from .errors import DataRuleViolation
from .memory import TOUCH_AFTER, check_membership_fields, session_hash
from .models import Membership, MembershipStatus, Session, Tenant, User, UserStatus, normalize_email

_LIVE = ("invited", "active")


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

    # --- tenants -----------------------------------------------------------------------------
    async def register_tenant(self, tenant_id: TenantId, *, now: _dt.datetime) -> None:
        async with self._tx() as s:
            await s.execute(insert(Tenant).values(id=str(TenantId(tenant_id)), created_at=now)
                            .on_conflict_do_nothing())

    async def tenant_exists(self, tenant_id: str) -> bool:
        return await self._one(select(Tenant.id).where(Tenant.id == str(tenant_id))) is not None

    async def tenants(self) -> list[str]:
        return await self._all(select(Tenant.id).order_by(Tenant.id))

    async def tenant_has_ever_had_membership(self, tenant_id: str) -> bool:
        return await self._one(select(exists().where(Membership.tenant_id == str(tenant_id)))) is True

    async def tenant_has_active_members(self, tenant_id: str) -> bool:
        return await self._one(select(exists().where(
            Membership.tenant_id == str(tenant_id), Membership.status == "active"))) is True

    # --- users -------------------------------------------------------------------------------
    @staticmethod
    def _new_user(
        email: str, *, created_at: _dt.datetime, status: UserStatus = "invited", display_name: str = "",
        signin_account_id: str | None = None, is_platform_admin: bool = False,
    ) -> User:
        return User(
            id=str(uuid.uuid4()), email=normalize_email(email), display_name=display_name, status=status,
            signin_account_id=signin_account_id, is_platform_admin=is_platform_admin,
            set_password_requested_seq=0, set_password_sent_seq=0, set_password_requested_at=None,
            set_password_sent_at=None, set_password_attempts=0, set_password_next_try_at=None,
            created_at=created_at, updated_at=created_at,
            activated_at=created_at if status == "active" else None)

    async def add_user(
        self, email: str, *, created_at: _dt.datetime, status: UserStatus = "invited",
        display_name: str = "", signin_account_id: str | None = None, is_platform_admin: bool = False,
    ) -> User:
        """Seeder."""
        user = self._new_user(
            email, created_at=created_at, status=status, display_name=display_name,
            signin_account_id=signin_account_id, is_platform_admin=is_platform_admin)
        async with self._tx() as s:
            s.add(user)
        return user

    async def ensure_user(self, email: str, *, now: _dt.datetime) -> User:
        email = normalize_email(email)
        new = self._new_user(email, created_at=now)
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

    async def user(self, user_id: str) -> User | None:
        return await self._one(select(User).where(User.id == user_id))

    async def user_by_email(self, email: str) -> User | None:
        return await self._one(select(User).where(User.email == normalize_email(email)))

    async def user_by_signin_account(self, account_id: str) -> User | None:
        return await self._one(select(User).where(User.signin_account_id == account_id))

    async def platform_admins(self) -> list[User]:
        return await self._all(select(User).where(User.is_platform_admin).order_by(User.created_at, User.id))

    async def record_signin_account(self, user_id: str, account_id: str) -> bool:
        try:
            return await self._applied(
                update(User).where(User.id == user_id, User.signin_account_id.is_(None))
                .values(signin_account_id=account_id).returning(User.id))
        except DataRuleViolation:
            return False

    async def activate_user(self, user_id: str, *, display_name: str, now: _dt.datetime) -> bool:
        return await self._applied(
            update(User).where(User.id == user_id, User.status == "invited")
            .values(status="active", activated_at=now, display_name=display_name, updated_at=now)
            .returning(User.id))

    async def set_display_name(self, user_id: str, display_name: str, *, now: _dt.datetime) -> None:
        async with self._tx() as s:
            await s.execute(update(User).where(User.id == user_id, User.display_name != display_name)
                            .values(display_name=display_name, updated_at=now))

    async def set_platform_admin(self, user_id: str, flag: bool) -> None:
        async with self._tx() as s:
            await s.execute(update(User).where(User.id == user_id).values(is_platform_admin=flag))

    # --- memberships -------------------------------------------------------------------------
    @staticmethod
    def _new_membership(  # noqa: PLR0913 — every column, supplied here
        user_id: str, tenant_id: str, *, status: MembershipStatus, invited_by: str, created_at: _dt.datetime,
        expires_at: _dt.datetime | None = None, accepted_at: _dt.datetime | None = None,
        ended_at: _dt.datetime | None = None, ended_by: str | None = None,
    ) -> Membership:
        return Membership(
            id=str(uuid.uuid4()), user_id=user_id, tenant_id=str(tenant_id), status=status,
            invited_by=invited_by, created_at=created_at, notify_requested_seq=0, notify_sent_seq=0,
            notify_requested_at=None, notified_at=None, notify_attempts=0, notify_next_try_at=None,
            expires_at=expires_at, accepted_at=accepted_at, ended_at=ended_at, ended_by=ended_by)

    async def add_membership(  # noqa: PLR0913 — the pinned seeder signature
        self, user_id: str, tenant_id: str, *, status: MembershipStatus, invited_by: str,
        created_at: _dt.datetime, expires_at: _dt.datetime | None = None,
        accepted_at: _dt.datetime | None = None, ended_at: _dt.datetime | None = None,
        ended_by: str | None = None,
    ) -> Membership:
        """Seeder."""
        check_membership_fields(status, accepted_at=accepted_at, ended_at=ended_at, ended_by=ended_by)
        row = self._new_membership(
            user_id, tenant_id, status=status, invited_by=invited_by, created_at=created_at,
            expires_at=expires_at, accepted_at=accepted_at, ended_at=ended_at, ended_by=ended_by)
        async with self._tx() as s:
            s.add(row)
        return row

    async def ensure_invitation(
        self, user_id: str, tenant_id: str, *, invited_by: str, now: _dt.datetime,
        expires_at: _dt.datetime | None = None,
    ) -> Membership | None:
        tenant_id = str(tenant_id)
        async with self._tx() as s:
            locked = (await s.execute(select(User.id).where(User.id == user_id).with_for_update())).first()
            if locked is None:
                raise DataRuleViolation(f"no user {user_id!r}")
            live = (await s.execute(select(Membership).where(
                Membership.user_id == user_id, Membership.tenant_id == tenant_id,
                Membership.status.in_(_LIVE)))).scalars().first()
            if live is not None:
                return None if live.status == "active" else live
            row = self._new_membership(
                user_id, tenant_id, status="invited", invited_by=invited_by, created_at=now,
                expires_at=expires_at)
            s.add(row)
        return row

    async def accept_invitation(self, membership_id: str, *, now: _dt.datetime) -> bool:
        return await self._applied(
            update(Membership).where(
                Membership.id == membership_id, Membership.status == "invited",
                (Membership.expires_at.is_(None)) | (Membership.expires_at > now))
            .values(status="active", accepted_at=now).returning(Membership.id))

    async def end_membership(self, membership_id: str, *, ended_by: str, now: _dt.datetime) -> bool:
        return await self._applied(
            update(Membership).where(Membership.id == membership_id, Membership.status == "active")
            .values(status="ended", ended_at=now, ended_by=ended_by).returning(Membership.id))

    async def revoke_invitation(self, membership_id: str) -> bool:
        return await self._applied(
            update(Membership).where(Membership.id == membership_id, Membership.status == "invited")
            .values(status="revoked").returning(Membership.id))

    async def membership(self, membership_id: str) -> Membership | None:
        return await self._one(select(Membership).where(Membership.id == membership_id))

    async def memberships_of_user(self, user_id: str) -> list[Membership]:
        return await self._all(select(Membership).where(Membership.user_id == user_id)
                               .order_by(Membership.created_at, Membership.id))

    async def memberships_of_tenant(self, tenant_id: str) -> list[Membership]:
        return await self._all(select(Membership).where(Membership.tenant_id == str(tenant_id))
                               .order_by(Membership.created_at, Membership.id))

    async def people_of_tenant(
        self, tenant_id: str, status: MembershipStatus,
    ) -> list[tuple[Membership, User]]:
        async with self._tx() as s:
            rows = (await s.execute(
                select(Membership, User).join(User, User.id == Membership.user_id)
                .where(Membership.tenant_id == str(tenant_id), Membership.status == status)
                .order_by(Membership.created_at, Membership.id))).all()
        return [(m, u) for m, u in rows]

    async def active_membership(self, user_id: str, tenant_id: str) -> Membership | None:
        return await self._one(select(Membership).where(
            Membership.user_id == user_id, Membership.tenant_id == str(tenant_id),
            Membership.status == "active"))

    # --- sends -------------------------------------------------------------------------------
    async def request_set_password(self, user_id: str, *, now: _dt.datetime) -> int:
        seq = await self._one(
            update(User).where(User.id == user_id)
            .values(set_password_requested_seq=User.set_password_requested_seq + 1, set_password_requested_at=now)
            .returning(User.set_password_requested_seq))
        if seq is None:
            raise DataRuleViolation(f"no user {user_id!r}")
        return int(seq)

    async def request_notification(self, membership_id: str, *, now: _dt.datetime) -> int:
        seq = await self._one(
            update(Membership).where(Membership.id == membership_id)
            .values(notify_requested_seq=Membership.notify_requested_seq + 1, notify_requested_at=now)
            .returning(Membership.notify_requested_seq))
        if seq is None:
            raise DataRuleViolation(f"no membership {membership_id!r}")
        return int(seq)

    async def claim_set_password(
        self, *, now: _dt.datetime, hold_until: _dt.datetime, skip: Collection[str] = (),
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
        self, *, now: _dt.datetime, hold_until: _dt.datetime, skip: Collection[str] = (),
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

    async def defer_set_password(self, user_id: str, *, until: _dt.datetime) -> None:
        async with self._tx() as s:
            await s.execute(update(User).where(User.id == user_id).values(
                set_password_attempts=User.set_password_attempts + 1, set_password_next_try_at=until))

    async def defer_notification(self, membership_id: str, *, until: _dt.datetime) -> None:
        async with self._tx() as s:
            await s.execute(update(Membership).where(Membership.id == membership_id).values(
                notify_attempts=Membership.notify_attempts + 1, notify_next_try_at=until))

    async def settle_set_password(
        self, user_id: str, read_seq: int, *, sent_at: _dt.datetime | None = None,
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
        self, membership_id: str, read_seq: int, *, sent_at: _dt.datetime | None = None,
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
        self, value: str, user_id: str, *, now: _dt.datetime, expires_at: _dt.datetime,
        used_otp: bool = False,
    ) -> Session:
        row = Session(token_hash=session_hash(value), user_id=user_id, used_otp=used_otp,
                      created_at=now, last_seen_at=now, expires_at=expires_at)
        async with self._tx() as s:
            s.add(row)
        return row

    async def session_by_value(self, value: str) -> Session | None:
        return await self._one(select(Session).where(Session.token_hash == session_hash(value)))

    async def delete_session(self, value: str) -> bool:
        return await self._applied(
            delete(Session).where(Session.token_hash == session_hash(value)).returning(Session.token_hash))

    async def touch_session(self, value: str, *, now: _dt.datetime) -> bool:
        return await self._applied(
            update(Session).where(
                Session.token_hash == session_hash(value), now - Session.last_seen_at > TOUCH_AFTER)
            .values(last_seen_at=now).returning(Session.token_hash))
