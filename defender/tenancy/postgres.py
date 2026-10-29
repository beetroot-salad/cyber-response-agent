"""The PostgreSQL tenant repository: the port of `repository.py` over the `tenancy` tables the
migrations create. Needs `psycopg` and SQLAlchemy (the `database` extra); nothing imports this
module but the code that builds a repository, so importing `tenancy` loads no driver.

Requests and reads run on a pooled engine, one transaction each; a request is one conditional
`UPDATE ... WHERE <precondition> RETURNING` (no row: `NotFound` if the tenant is absent, else
`Conflict`). They never take a tenant lock, so a running step never blocks them.

A tenant lock is `pg_try_advisory_lock(LOCK_NAMESPACE, hashtext(T))` on a connection of its own,
from an engine with no pool, opened with server-side TCP keepalives and a user timeout so the
database drops the lock of a dead or cut-off worker within about `lock_keepalive` seconds (RC-2).
Everything the worker reads and writes for the tenant goes over that connection. Each write is one
statement: a fenced `UPDATE` of the tenant row as a CTE, with the generation, wiring and publish
status changes as further CTEs that act only on the fenced row, so they land together or not at
all. The fence (RC-1): the pending action, step and actor as read at the step's start, the
expected failure (none), and this session still holding the lock (`pg_locks`). A miss or any error
on that connection spends the hold: the connection is closed, never reused or reconnected."""

from __future__ import annotations

import contextlib
import datetime as _dt
import logging
import uuid
from collections.abc import AsyncIterator, Collection, Mapping
from typing import Any, Literal

from sqlalchemy import ARRAY, ColumnElement, Text, Table, bindparam, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from defender.database import async_engine, url
from defender.tenancy.models import SCHEMA, ForgeWiring, Generation, PublishStatus, TenantRecord
from defender.tenancy.repository import (
    ADOPT_STEP,
    ALL,
    KEEP,
    LOCK_NAMESPACE,
    SERVICE,
    Conflict,
    FenceMissed,
    NotFound,
    publish_outcome,
)

_logger = logging.getLogger(__name__)

_T: Table = TenantRecord.__table__  # type: ignore[assignment]
_G: Table = Generation.__table__  # type: ignore[assignment]
_W: Table = ForgeWiring.__table__  # type: ignore[assignment]
_P: Table = PublishStatus.__table__  # type: ignore[assignment]

#: The lock connection's keepalive bound, in seconds, when the caller states none.
LOCK_KEEPALIVE = 30
#: This session holds T's lock: the advisory lock's two keys as `pg_locks` shows them.
_HOLDS_LOCK = (
    "EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted AND pid = pg_backend_pid()"
    " AND objsubid = 2 AND classid = CAST(CAST(:ns AS integer) AS oid)"
    " AND objid = CAST(CAST(hashtext(CAST(:tid AS text)) AS bigint) & 4294967295 AS oid))")


def lock_options(keepalive: int) -> str:
    """The lock connection's startup `options`: sessions in UTC, and server-side keepalives that end
    a silent connection (and so its lock) after about `keepalive` seconds."""
    idle, interval, count = max(1, keepalive // 2), max(1, keepalive // 6), 3
    return (f"-c timezone=UTC -c tcp_keepalives_idle={idle} -c tcp_keepalives_interval={interval}"
            f" -c tcp_keepalives_count={count} -c tcp_user_timeout={keepalive * 1000}")


def _record(row: Any) -> TenantRecord:
    return TenantRecord(**row._mapping)


def _cannot_exist(tenant_id: object) -> bool:
    """A NUL byte cannot be stored in a PostgreSQL text value: such an id names no tenant, and asking the database
    would raise a data error instead of answering "unknown"."""
    return "\x00" in str(tenant_id)


class PostgresTenantRepository:
    def __init__(self, dsn: str, *, max_connections: int = 10, lock_keepalive: int = LOCK_KEEPALIVE) -> None:
        if lock_keepalive <= 0:
            raise ValueError("lock_keepalive is a positive number of seconds")
        self._engine = async_engine(dsn, max_connections=max_connections)
        self._lock_engine = create_async_engine(
            url(dsn), connect_args={"options": lock_options(lock_keepalive)}, poolclass=NullPool)

    async def close(self) -> None:
        try:
            await self._engine.dispose()
        finally:
            await self._lock_engine.dispose()

    # --- reads ---------------------------------------------------------------------------------
    async def _rows(self, statement: Any) -> list[Any]:
        async with self._engine.connect() as conn:
            return list(await conn.execute(statement))

    async def tenant(self, tenant_id: str) -> TenantRecord | None:
        if _cannot_exist(tenant_id):
            return None
        rows = await self._rows(select(_T).where(_T.c.id == str(tenant_id)))
        return _record(rows[0]) if rows else None

    async def tenants(self) -> list[TenantRecord]:
        return [_record(r) for r in await self._rows(select(_T).order_by(_T.c.created_at, _T.c.id))]

    async def generations(self, tenant_id: str) -> list[Generation]:
        if _cannot_exist(tenant_id):
            return []
        rows = await self._rows(select(_G).where(_G.c.tenant_id == str(tenant_id)).order_by(_G.c.salt))
        return [Generation(**r._mapping) for r in rows]

    async def forge_wiring(self, tenant_id: str) -> ForgeWiring | None:
        if _cannot_exist(tenant_id):
            return None
        rows = await self._rows(select(_W).where(_W.c.tenant_id == str(tenant_id)))
        return ForgeWiring(**rows[0]._mapping) if rows else None

    async def publish_status(self, tenant_id: str) -> dict[str, str] | None:
        if _cannot_exist(tenant_id):
            return None
        rows = await self._rows(select(_P).where(_P.c.tenant_id == str(tenant_id)))
        return PublishStatus(**rows[0]._mapping).as_dict() if rows else None

    # --- requests (the API) ----------------------------------------------------------------------
    async def request_create(self, *, now: _dt.datetime) -> TenantRecord:
        values = dict(id=str(uuid.uuid4()), created_at=now, state="creating", pending_action="create",
                      step="names", step_actor=SERVICE)
        async with self._engine.begin() as conn:
            return _record((await conn.execute(insert(_T).values(**values).returning(*_T.c))).one())

    async def _request(self, tenant_id: str, precondition: ColumnElement[bool], refusal: str,
                       **values: Any) -> TenantRecord:
        """One conditional update; no row is `NotFound` for an absent tenant, else `Conflict`."""
        tenant_id = str(tenant_id)
        if _cannot_exist(tenant_id):
            raise NotFound(f"no tenant {tenant_id!r}")
        async with self._engine.begin() as conn:
            done = (await conn.execute(update(_T).where(_T.c.id == tenant_id, precondition)
                                       .values(**values).returning(*_T.c))).first()
            if done is not None:
                return _record(done)
            present = (await conn.execute(select(_T.c.id).where(_T.c.id == tenant_id))).first()
        if present is None:
            raise NotFound(f"no tenant {tenant_id}")
        raise Conflict(refusal)

    async def request_resume(self, tenant_id: str) -> TenantRecord:
        return await self._request(
            tenant_id, _T.c.failure.is_not(None) & _T.c.step.is_distinct_from(ADOPT_STEP),
            "nothing to resume, or a failure only adoption clears", failure=None)

    async def request_offboard(self, tenant_id: str, *, now: _dt.datetime) -> TenantRecord:
        return await self._request(
            tenant_id, _T.c.state.in_(("creating", "active")), "only a creating or active tenant can be offboarded",
            state="offboarding", pending_action="offboard", step="offboard", step_actor=SERVICE, failure=None)

    async def request_rotate(self, tenant_id: str) -> TenantRecord:
        return await self._request(
            tenant_id, (_T.c.state == "active") & _T.c.pending_action.is_(None),
            "only an active tenant with nothing pending can rotate",
            pending_action="rotate", step="names", step_actor=SERVICE)

    # --- host processes --------------------------------------------------------------------------
    async def record_publish_status(self, tenant_id: str, line: str, *, by: str) -> None:
        published, refused, kind = publish_outcome(line)
        values = dict(recorded_by=by, published=published, refused=refused, kind=kind)
        try:
            async with self._engine.begin() as conn:
                await conn.execute(insert(_P).values(tenant_id=str(tenant_id), **values)
                                   .on_conflict_do_update(index_elements=[_P.c.tenant_id], set_=values))
        except IntegrityError as e:
            raise ValueError(f"no tenant {tenant_id}") from e

    # --- workers ---------------------------------------------------------------------------------
    async def claimable(self, actor: str, *, now: _dt.datetime) -> list[str]:
        due = (_T.c.pending_action != "delete_repo") | (_T.c.repo_delete_after <= now)
        rows = await self._rows(
            select(_T.c.id).where(_T.c.pending_action.is_not(None), _T.c.step_actor == actor,
                                  _T.c.failure.is_(None), due)
            .order_by(_T.c.created_at, _T.c.id))
        return [r[0] for r in rows]

    @contextlib.asynccontextmanager
    async def lock(self, tenant_id: str) -> AsyncIterator[_Held | None]:
        tenant_id = str(tenant_id)
        conn = await self._lock_engine.connect()
        held: _Held | None = None
        try:
            got = await conn.scalar(text("SELECT pg_try_advisory_lock(CAST(:ns AS integer), hashtext(CAST(:tid AS text)))"),
                                    {"ns": LOCK_NAMESPACE, "tid": tenant_id})
            await conn.commit()
            if not got:
                yield None
                return
            row = (await conn.execute(select(_T).where(_T.c.id == tenant_id))).first()
            await conn.commit()
            if row is not None:
                held = _Held(conn, _record(row))
            yield held
            if held is None or not held.spent:
                await conn.execute(text("SELECT pg_advisory_unlock(CAST(:ns AS integer), hashtext(CAST(:tid AS text)))"),
                                   {"ns": LOCK_NAMESPACE, "tid": tenant_id})
                await conn.commit()
        finally:
            if held is not None:
                held.spent = True
            with contextlib.suppress(Exception):  # closing a broken connection may fail; it is gone either way
                await conn.close()


def _typed(name: str, value: Any, table: Table, column: str) -> Any:
    return bindparam(name, value, type_=table.c[column].type)


class _Held:
    """A tenant under its lock, on the lock's own connection (see the module doc)."""

    def __init__(self, conn: AsyncConnection, record: TenantRecord) -> None:
        self._conn = conn
        self.tenant_id = record.id
        self.record = record
        self.spent = False

    async def _run(self, statement: Any) -> list[Any]:
        """One statement and its commit on the lock connection; any error spends the hold."""
        if self.spent:
            raise FenceMissed(f"the hold on tenant {self.tenant_id} is spent")
        try:
            rows = list(await self._conn.execute(statement))
            await self._conn.commit()
        except DBAPIError as e:
            self.spent = True
            why = str(e.orig).splitlines()[0] if e.orig is not None else type(e).__name__
            _logger.warning("tenant %s: the lock connection failed (%s: %s); the step stops",
                            self.tenant_id, type(e.orig).__name__, why)
            raise FenceMissed(f"the lock connection of tenant {self.tenant_id} failed") from e
        return rows

    async def generations(self) -> list[Generation]:
        rows = await self._run(select(_G).where(_G.c.tenant_id == self.tenant_id).order_by(_G.c.salt))
        return [Generation(**r._mapping) for r in rows]

    async def forge_wiring(self) -> ForgeWiring | None:
        rows = await self._run(select(_W).where(_W.c.tenant_id == self.tenant_id))
        return ForgeWiring(**rows[0]._mapping) if rows else None

    async def commit(  # noqa: PLR0913 — `HeldTenant.commit`
        self, *, step: str | None, actor: str | None, state: str = KEEP, pending_action: str | None = KEEP,
        repo_url: str | None = KEEP, offboarded_at: _dt.datetime | None = KEEP,
        repo_delete_after: _dt.datetime | None = KEEP,
        add_generation: Generation | None = None,
        update_generations: Mapping[str, Mapping[str, Any]] | None = None,
        go_live: str | None = None, destroy: Collection[str] | Literal["all"] = (),
        wiring: ForgeWiring | None = None, drop_wiring: bool = False, drop_publish_status: bool = False,
        expect_failure: str | None = None,
    ) -> TenantRecord:
        columns = {k: v for k, v in dict(state=state, pending_action=pending_action, repo_url=repo_url,
                                         offboarded_at=offboarded_at, repo_delete_after=repo_delete_after).items()
                   if v is not KEEP}
        statement = _Statement(self.record, expect_failure)
        statement.tenant(step=step, step_actor=actor, failure=None, **columns)
        statement.generations(add_generation, update_generations, go_live, destroy)
        if wiring is not None:
            statement.cte("wiring", f"INSERT INTO {SCHEMA}.forge_wiring (tenant_id, repo, origin)"
                          " SELECT id, :w_repo, :w_origin FROM fence ON CONFLICT (tenant_id) DO NOTHING RETURNING tenant_id",
                          w_repo=wiring.repo, w_origin=wiring.origin)
        if drop_wiring:
            statement.cte("drop_wiring", f"DELETE FROM {SCHEMA}.forge_wiring"
                          " WHERE tenant_id IN (SELECT id FROM fence) RETURNING tenant_id")
        if drop_publish_status:
            statement.cte("drop_status", f"DELETE FROM {SCHEMA}.publish_status"
                          " WHERE tenant_id IN (SELECT id FROM fence) RETURNING tenant_id")
        return await self._land(statement)

    async def fail(self, failure: str, *, step: str, actor: str) -> TenantRecord:
        statement = _Statement(self.record, None)
        statement.tenant(step=step, step_actor=actor, failure=failure)
        return await self._land(statement)

    async def _land(self, statement: _Statement) -> TenantRecord:
        rows = await self._run(statement.compile())
        if not rows:
            self.spent = True
            raise FenceMissed(f"tenant {self.tenant_id}'s job moved since the step started, or its lock is lost")
        self.record = _record(rows[0])
        return _record(rows[0])


class _Statement:
    """One fenced write: the tenant row's `UPDATE` as the CTE `fence`, other tables' changes as CTEs
    that act only on what `fence` returned, and `fence`'s row as the result."""

    def __init__(self, seen: TenantRecord, expect_failure: str | None) -> None:
        self._seen = seen
        self._ctes: list[str] = []
        self._params: list[Any] = [
            bindparam("ns", LOCK_NAMESPACE), bindparam("tid", seen.id),
            bindparam("was_action", seen.pending_action, type_=_T.c.pending_action.type),
            bindparam("was_step", seen.step, type_=_T.c.step.type),
            bindparam("was_actor", seen.step_actor, type_=_T.c.step_actor.type),
            bindparam("was_failure", expect_failure, type_=_T.c.failure.type)]

    def cte(self, name: str, sql: str, **params: Any) -> None:
        self._ctes.append(f"{name} AS ({sql})")
        self._params += [bindparam(k, v) for k, v in params.items()]

    def tenant(self, **values: Any) -> None:
        sets = ", ".join(f"{k} = :t_{k}" for k in values)
        self._params += [_typed(f"t_{k}", v, _T, k) for k, v in values.items()]
        self._ctes.insert(0, f"""fence AS (UPDATE {SCHEMA}.tenants SET {sets}
            WHERE id = :tid AND pending_action IS NOT DISTINCT FROM :was_action
              AND step IS NOT DISTINCT FROM :was_step AND step_actor IS NOT DISTINCT FROM :was_actor
              AND failure IS NOT DISTINCT FROM :was_failure AND {_HOLDS_LOCK}
            RETURNING *)""")

    def generations(self, add: Generation | None, updates: Mapping[str, Mapping[str, Any]] | None,
                    go_live: str | None, destroy: Collection[str] | Literal["all"]) -> None:
        """Each generation row is changed by one CTE only (PostgreSQL applies one change per row per
        statement). The live slot is freed first: the generation going live waits for `retire`."""
        changes: dict[str, dict[str, Any]] = {salt: dict(fields) for salt, fields in (updates or {}).items()}
        if go_live is not None:
            if destroy == ALL:
                raise ValueError("a commit cannot both make a generation live and destroy every one")
            changes.setdefault(go_live, {})["status"] = "live"
        if destroy != ALL:
            for salt in destroy:
                changes.setdefault(salt, {})["status"] = "destroyed"
        named = sorted(changes)
        if add is not None:
            fields = {c.name: getattr(add, c.name) for c in _G.columns} | changes.pop(add.salt, {})
            fields["tenant_id"] = self._seen.id
            cols = [c for c in fields if c != "tenant_id"]
            self._params += [_typed(f"n_{c}", fields[c], _G, c) for c in cols]
            self.cte("new_generation", f"INSERT INTO {SCHEMA}.generations (tenant_id, {', '.join(cols)})"
                     f" SELECT id, {', '.join(f':n_{c}' for c in cols)} FROM fence RETURNING salt")
        mine = "tenant_id IN (SELECT id FROM fence)"
        waits = ""
        if go_live is not None:
            self._params.append(bindparam("named", named, type_=ARRAY(Text)))
            self.cte("retire", f"UPDATE {SCHEMA}.generations SET status = 'retiring'"
                     f" WHERE {mine} AND status = 'live' AND salt <> ALL(:named) RETURNING salt")
            waits = " AND (SELECT count(*) FROM retire) >= 0"
        if destroy == ALL:
            self._params.append(bindparam("kept", named, type_=ARRAY(Text)))
            self.cte("destroy", f"UPDATE {SCHEMA}.generations SET status = 'destroyed'"
                     f" WHERE {mine} AND status <> 'destroyed' AND salt <> ALL(:kept) RETURNING salt")
        for number, (salt, fields) in enumerate(sorted(changes.items())):
            sets = ", ".join(f"{c} = :g{number}_{c}" for c in fields)
            self._params += [_typed(f"g{number}_{c}", v, _G, c) for c, v in fields.items()]
            self._params.append(bindparam(f"g{number}_salt", salt))
            self.cte(f"generation_{number}", f"UPDATE {SCHEMA}.generations SET {sets}"
                     f" WHERE {mine} AND salt = :g{number}_salt{waits if salt == go_live else ''} RETURNING salt")

    def compile(self) -> Any:
        return (text(f"WITH {', '.join(self._ctes)} SELECT * FROM fence")
                .bindparams(*self._params).columns(*_T.c))
