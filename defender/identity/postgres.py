"""The PostgreSQL identity repository: the same rules as `InMemoryIdentityRepository`, held by
the schema (unique indexes, CHECKs, foreign keys) and by conditional updates, and answering the
same contract suite. Needs `psycopg` and its pool (the `api` extra); nothing else imports this module.

Each operation borrows a connection from a pool for its one transaction, so the sender thread and
request threads never share one at the same time and none pays for a new connection."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import re
import uuid
from collections.abc import Collection, Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg import errors as pg_errors
from psycopg import sql
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from defender.records._tenant_id import TenantId

from .errors import DataRuleViolation
from .memory import TOUCH_AFTER, check_membership_fields, session_hash
from .rows import Membership, MembershipStatus, Session, User, UserStatus

_SCHEMA_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
#: Held while migrations apply, so two processes starting together do not race.
_MIGRATION_LOCK = 1306_0001

#: Ordered, append-only. A migration that has run is never edited.
MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("0001_identity", """
CREATE TABLE tenants (
    id text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE users (
    id text PRIMARY KEY,
    email text NOT NULL UNIQUE CHECK (email = lower(email)),
    display_name text NOT NULL DEFAULT '',
    status text NOT NULL CHECK (status IN ('invited', 'active')),
    signin_account_id text UNIQUE,
    is_platform_admin boolean NOT NULL DEFAULT false,
    set_password_requested_seq integer NOT NULL DEFAULT 0,
    set_password_sent_seq integer NOT NULL DEFAULT 0,
    set_password_requested_at timestamptz,
    set_password_sent_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    activated_at timestamptz,
    CHECK (status <> 'active' OR activated_at IS NOT NULL)
);
CREATE TABLE memberships (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users (id),
    tenant_id text NOT NULL REFERENCES tenants (id),
    status text NOT NULL CHECK (status IN ('invited', 'active', 'ended', 'revoked')),
    invited_by text NOT NULL,
    created_at timestamptz NOT NULL,
    notify_requested_seq integer NOT NULL DEFAULT 0,
    notify_sent_seq integer NOT NULL DEFAULT 0,
    notify_requested_at timestamptz,
    notified_at timestamptz,
    expires_at timestamptz,
    accepted_at timestamptz,
    ended_at timestamptz,
    ended_by text,
    CHECK (status <> 'active' OR accepted_at IS NOT NULL),
    CHECK (status <> 'ended' OR (ended_at IS NOT NULL AND ended_by IS NOT NULL))
);
CREATE UNIQUE INDEX memberships_one_live_row ON memberships (user_id, tenant_id)
    WHERE status IN ('invited', 'active');
CREATE INDEX memberships_by_tenant ON memberships (tenant_id);
CREATE TABLE sessions (
    token_hash text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users (id),
    used_otp boolean NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_by_user ON sessions (user_id);
"""),
)

_NO_TIME: Any = None


@contextmanager
def _data_rules() -> Iterator[None]:
    """A write the schema refuses, as the port's `DataRuleViolation`."""
    try:
        yield
    except (pg_errors.UniqueViolation, pg_errors.ForeignKeyViolation, pg_errors.CheckViolation) as e:
        raise DataRuleViolation(str(e).splitlines()[0]) from e


#: The user's columns renamed `u_<column>`, so one row can carry a membership and its user.
_USER_AS_U = ", ".join(f"u.{f.name} AS u_{f.name}" for f in dataclasses.fields(User))


class PostgresIdentityRepository:
    def __init__(self, dsn: str, *, schema: str, max_connections: int = 10) -> None:
        if not _SCHEMA_NAME.match(schema):
            raise ValueError(f"not a schema name: {schema!r}")
        self._dsn = dsn
        self._schema = schema
        self._migrate()
        self._pool: ConnectionPool[psycopg.Connection[dict[str, Any]]] = ConnectionPool(
            dsn, min_size=1, max_size=max_connections, open=True,
            kwargs={"row_factory": dict_row, "options": f"-c timezone=UTC -c search_path={schema}"})

    def close(self) -> None:
        self._pool.close()

    # --- plumbing ----------------------------------------------------------------------------
    @contextmanager
    def _conn(self) -> Iterator[psycopg.Connection[dict[str, Any]]]:
        with self._pool.connection() as conn, _data_rules(), conn.transaction():
            yield conn

    def _migrate(self) -> None:
        """On a connection of its own, before the pool opens: the schema may not exist yet."""
        with psycopg.connect(self._dsn, row_factory=dict_row, options="-c timezone=UTC") as conn, \
                _data_rules(), conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_LOCK,))
            conn.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self._schema)))
            conn.execute(sql.SQL("SET LOCAL search_path TO {}").format(sql.Identifier(self._schema)))
            conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY)")
            done = {r["name"] for r in conn.execute("SELECT name FROM schema_migrations")}
            for name, script in MIGRATIONS:
                if name not in done:
                    conn.execute(script)
                    conn.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (name,))

    @staticmethod
    def _user(row: dict[str, Any] | None) -> User | None:
        return None if row is None else User(**row)

    @staticmethod
    def _membership(row: dict[str, Any] | None) -> Membership | None:
        return None if row is None else Membership(**row)

    # --- tenants -----------------------------------------------------------------------------
    def register_tenant(self, tenant_id: TenantId) -> None:
        with self._conn() as conn:
            conn.execute("INSERT INTO tenants (id) VALUES (%s) ON CONFLICT DO NOTHING",
                         (str(TenantId(tenant_id)),))

    def tenant_exists(self, tenant_id: str) -> bool:
        with self._conn() as conn:
            return conn.execute("SELECT 1 FROM tenants WHERE id = %s", (str(tenant_id),)).fetchone() is not None

    def tenants(self) -> list[str]:
        with self._conn() as conn:
            return [r["id"] for r in conn.execute("SELECT id FROM tenants ORDER BY id")]

    def tenant_has_ever_had_membership(self, tenant_id: str) -> bool:
        with self._conn() as conn:
            return conn.execute("SELECT 1 FROM memberships WHERE tenant_id = %s LIMIT 1",
                                (str(tenant_id),)).fetchone() is not None

    def tenant_has_active_members(self, tenant_id: str) -> bool:
        with self._conn() as conn:
            return conn.execute("SELECT 1 FROM memberships WHERE tenant_id = %s AND status = 'active' LIMIT 1",
                                (str(tenant_id),)).fetchone() is not None

    # --- users -------------------------------------------------------------------------------
    def add_user(
        self, email: str, *, created_at: _dt.datetime, status: UserStatus = "invited",
        display_name: str = "", signin_account_id: str | None = None, is_platform_admin: bool = False,
    ) -> User:
        """Seeder."""
        with self._conn() as conn:
            row = conn.execute(
                "INSERT INTO users (id, email, display_name, status, signin_account_id, is_platform_admin,"
                " created_at, updated_at, activated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *",
                (str(uuid.uuid4()), email.strip().lower(), display_name, status, signin_account_id,
                 is_platform_admin, created_at, created_at, created_at if status == "active" else None),
            ).fetchone()
        user = self._user(row)
        assert user is not None
        return user

    def ensure_user(self, email: str, *, now: _dt.datetime) -> User:
        email = email.strip().lower()
        with self._conn() as conn:
            row = conn.execute(
                "INSERT INTO users (id, email, status, created_at, updated_at)"
                " VALUES (%s, %s, 'invited', %s, %s) ON CONFLICT (email) DO NOTHING RETURNING *",
                (str(uuid.uuid4()), email, now, now)).fetchone()
            if row is None:
                row = conn.execute("SELECT * FROM users WHERE email = %s", (email,)).fetchone()
        user = self._user(row)
        assert user is not None
        return user

    def user(self, user_id: str) -> User | None:
        with self._conn() as conn:
            return self._user(conn.execute("SELECT * FROM users WHERE id = %s", (user_id,)).fetchone())

    def user_by_email(self, email: str) -> User | None:
        with self._conn() as conn:
            return self._user(conn.execute(
                "SELECT * FROM users WHERE email = %s", (email.strip().lower(),)).fetchone())

    def user_by_signin_account(self, account_id: str) -> User | None:
        with self._conn() as conn:
            return self._user(conn.execute(
                "SELECT * FROM users WHERE signin_account_id = %s", (account_id,)).fetchone())

    def platform_admins(self) -> list[User]:
        with self._conn() as conn:
            return [User(**r) for r in conn.execute(
                "SELECT * FROM users WHERE is_platform_admin ORDER BY created_at, id")]

    def record_signin_account(self, user_id: str, account_id: str) -> bool:
        try:
            with self._conn() as conn:
                return conn.execute(
                    "UPDATE users SET signin_account_id = %s WHERE id = %s AND signin_account_id IS NULL"
                    " RETURNING 1", (account_id, user_id)).fetchone() is not None
        except DataRuleViolation:
            return False

    def activate_user(self, user_id: str, *, display_name: str, now: _dt.datetime) -> bool:
        with self._conn() as conn:
            return conn.execute(
                "UPDATE users SET status = 'active', activated_at = %s, display_name = %s, updated_at = %s"
                " WHERE id = %s AND status = 'invited' RETURNING 1",
                (now, display_name, now, user_id)).fetchone() is not None

    def set_display_name(self, user_id: str, display_name: str, *, now: _dt.datetime) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE users SET display_name = %s, updated_at = %s WHERE id = %s AND display_name <> %s",
                (display_name, now, user_id, display_name))

    def set_platform_admin(self, user_id: str, flag: bool) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE users SET is_platform_admin = %s WHERE id = %s", (flag, user_id))

    # --- memberships -------------------------------------------------------------------------
    def add_membership(  # noqa: PLR0913 — the pinned seeder signature
        self, user_id: str, tenant_id: str, *, status: MembershipStatus, invited_by: str,
        created_at: _dt.datetime, expires_at: _dt.datetime | None = None,
        accepted_at: _dt.datetime | None = None, ended_at: _dt.datetime | None = None,
        ended_by: str | None = None,
    ) -> Membership:
        """Seeder."""
        check_membership_fields(status, accepted_at=accepted_at, ended_at=ended_at, ended_by=ended_by)
        with self._conn() as conn:
            row = conn.execute(
                "INSERT INTO memberships (id, user_id, tenant_id, status, invited_by, created_at, expires_at,"
                " accepted_at, ended_at, ended_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *",
                (str(uuid.uuid4()), user_id, str(tenant_id), status, invited_by, created_at, expires_at,
                 accepted_at, ended_at, ended_by)).fetchone()
        membership = self._membership(row)
        assert membership is not None
        return membership

    def ensure_invitation(
        self, user_id: str, tenant_id: str, *, invited_by: str, now: _dt.datetime,
        expires_at: _dt.datetime | None = None,
    ) -> Membership | None:
        tenant_id = str(tenant_id)
        with self._conn() as conn:
            if conn.execute("SELECT 1 FROM users WHERE id = %s FOR UPDATE", (user_id,)).fetchone() is None:
                raise DataRuleViolation(f"no user {user_id!r}")
            live = self._membership(conn.execute(
                "SELECT * FROM memberships WHERE user_id = %s AND tenant_id = %s"
                " AND status IN ('invited', 'active')", (user_id, tenant_id)).fetchone())
            if live is not None:
                return None if live.status == "active" else live
            row = conn.execute(
                "INSERT INTO memberships (id, user_id, tenant_id, status, invited_by, created_at, expires_at)"
                " VALUES (%s, %s, %s, 'invited', %s, %s, %s) RETURNING *",
                (str(uuid.uuid4()), user_id, tenant_id, invited_by, now, expires_at)).fetchone()
        return self._membership(row)

    def accept_invitation(self, membership_id: str, *, now: _dt.datetime) -> bool:
        with self._conn() as conn:
            return conn.execute(
                "UPDATE memberships SET status = 'active', accepted_at = %s WHERE id = %s AND status = 'invited'"
                " AND (expires_at IS NULL OR expires_at > %s) RETURNING 1",
                (now, membership_id, now)).fetchone() is not None

    def end_membership(self, membership_id: str, *, ended_by: str, now: _dt.datetime) -> bool:
        with self._conn() as conn:
            return conn.execute(
                "UPDATE memberships SET status = 'ended', ended_at = %s, ended_by = %s"
                " WHERE id = %s AND status = 'active' RETURNING 1",
                (now, ended_by, membership_id)).fetchone() is not None

    def revoke_invitation(self, membership_id: str) -> bool:
        with self._conn() as conn:
            return conn.execute(
                "UPDATE memberships SET status = 'revoked' WHERE id = %s AND status = 'invited' RETURNING 1",
                (membership_id,)).fetchone() is not None

    def membership(self, membership_id: str) -> Membership | None:
        with self._conn() as conn:
            return self._membership(conn.execute(
                "SELECT * FROM memberships WHERE id = %s", (membership_id,)).fetchone())

    def memberships_of_user(self, user_id: str) -> list[Membership]:
        with self._conn() as conn:
            return [Membership(**r) for r in conn.execute(
                "SELECT * FROM memberships WHERE user_id = %s ORDER BY created_at, id", (user_id,))]

    def memberships_of_tenant(self, tenant_id: str) -> list[Membership]:
        with self._conn() as conn:
            return [Membership(**r) for r in conn.execute(
                "SELECT * FROM memberships WHERE tenant_id = %s ORDER BY created_at, id", (str(tenant_id),))]

    def people_of_tenant(
        self, tenant_id: str, status: MembershipStatus,
    ) -> list[tuple[Membership, User]]:
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT m.*, {_USER_AS_U} FROM memberships m JOIN users u ON u.id = m.user_id"
                " WHERE m.tenant_id = %s AND m.status = %s ORDER BY m.created_at, m.id",
                (str(tenant_id), status)).fetchall()
        return [(Membership(**{k: v for k, v in r.items() if not k.startswith("u_")}),
                 User(**{k[2:]: v for k, v in r.items() if k.startswith("u_")})) for r in rows]

    def active_membership(self, user_id: str, tenant_id: str) -> Membership | None:
        with self._conn() as conn:
            return self._membership(conn.execute(
                "SELECT * FROM memberships WHERE user_id = %s AND tenant_id = %s AND status = 'active'",
                (user_id, str(tenant_id))).fetchone())

    # --- sends -------------------------------------------------------------------------------
    def request_set_password(self, user_id: str, *, now: _dt.datetime) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "UPDATE users SET set_password_requested_seq = set_password_requested_seq + 1,"
                " set_password_requested_at = %s WHERE id = %s RETURNING set_password_requested_seq",
                (now, user_id)).fetchone()
        if row is None:
            raise DataRuleViolation(f"no user {user_id!r}")
        return int(row["set_password_requested_seq"])

    def request_notification(self, membership_id: str, *, now: _dt.datetime) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "UPDATE memberships SET notify_requested_seq = notify_requested_seq + 1,"
                " notify_requested_at = %s WHERE id = %s RETURNING notify_requested_seq",
                (now, membership_id)).fetchone()
        if row is None:
            raise DataRuleViolation(f"no membership {membership_id!r}")
        return int(row["notify_requested_seq"])

    @contextmanager
    def claim_pending_set_password(self, skip: Collection[str] = ()) -> Iterator[User | None]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE status = 'invited'"
                " AND set_password_requested_seq > set_password_sent_seq AND id <> ALL(%s)"
                " ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED", (list(skip),)).fetchone()
            yield self._user(row)

    @contextmanager
    def claim_pending_notification(self, skip: Collection[str] = ()) -> Iterator[Membership | None]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM memberships WHERE status = 'invited'"
                " AND notify_requested_seq > notify_sent_seq AND id <> ALL(%s)"
                " ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED", (list(skip),)).fetchone()
            yield self._membership(row)

    def settle_set_password(
        self, user_id: str, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        with self._conn() as conn:
            applied = conn.execute(
                "UPDATE users SET set_password_sent_seq = %s,"
                " set_password_sent_at = COALESCE(%s, set_password_sent_at)"
                " WHERE id = %s AND set_password_sent_seq < %s AND %s <= set_password_requested_seq"
                " RETURNING 1", (read_seq, sent_at, user_id, read_seq, read_seq)).fetchone() is not None
            if applied and sent_at is not None and expires_at is not None:
                conn.execute("UPDATE memberships SET expires_at = %s WHERE user_id = %s AND status = 'invited'",
                             (expires_at, user_id))
            return applied

    def settle_notification(
        self, membership_id: str, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        with self._conn() as conn:
            return conn.execute(
                "UPDATE memberships SET notify_sent_seq = %s, notified_at = COALESCE(%s, notified_at),"
                " expires_at = CASE WHEN %s::timestamptz IS NOT NULL AND %s::timestamptz IS NOT NULL"
                " AND status = 'invited' THEN %s ELSE expires_at END"
                " WHERE id = %s AND notify_sent_seq < %s AND %s <= notify_requested_seq RETURNING 1",
                (read_seq, sent_at, sent_at, expires_at, expires_at, membership_id, read_seq, read_seq),
            ).fetchone() is not None

    # --- sessions ----------------------------------------------------------------------------
    def add_session(
        self, value: str, user_id: str, *, now: _dt.datetime, expires_at: _dt.datetime,
        used_otp: bool = False,
    ) -> Session:
        with self._conn() as conn:
            row = conn.execute(
                "INSERT INTO sessions (token_hash, user_id, used_otp, created_at, last_seen_at, expires_at)"
                " VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                (session_hash(value), user_id, used_otp, now, now, expires_at)).fetchone()
        assert row is not None
        return Session(**row)

    def session_by_value(self, value: str) -> Session | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE token_hash = %s", (session_hash(value),)).fetchone()
        return None if row is None else Session(**row)

    def delete_session(self, value: str) -> bool:
        with self._conn() as conn:
            return conn.execute("DELETE FROM sessions WHERE token_hash = %s RETURNING 1",
                                (session_hash(value),)).fetchone() is not None

    def touch_session(self, value: str, *, now: _dt.datetime) -> bool:
        with self._conn() as conn:
            return conn.execute(
                "UPDATE sessions SET last_seen_at = %s WHERE token_hash = %s AND %s - last_seen_at > %s"
                " RETURNING 1", (now, session_hash(value), now, TOUCH_AFTER)).fetchone() is not None
