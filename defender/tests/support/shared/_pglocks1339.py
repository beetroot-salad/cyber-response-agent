"""#1339 deterministic PostgreSQL interleavings: a raw connection holds a row lock or an uncommitted
insert, the operation under test is started, and the test waits until the server reports it blocked.
No sleeps decide an outcome; the only wait is for a stated server-side condition, with a timeout.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

TIMEOUT = 10.0


async def fetch(dsn: str, statement: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    """One autocommit statement on its own connection; the rows it returned, if any."""
    import psycopg

    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
        cur = await conn.execute(statement, params or None)  # type: ignore[arg-type]
        return await cur.fetchall() if cur.description else []


async def blocked(dsn: str) -> int:
    """How many backends of this database are waiting for a lock right now."""
    [(count,)] = await fetch(
        dsn, "SELECT count(*) FROM pg_stat_activity "
             "WHERE datname = current_database() AND wait_event_type = 'Lock'")
    return count


async def connections(dsn: str) -> int:
    """How many other backends are connected to this database."""
    [(count,)] = await fetch(
        dsn, "SELECT count(*) FROM pg_stat_activity "
             "WHERE datname = current_database() AND pid <> pg_backend_pid()")
    return count


async def until(condition, *, timeout: float = TIMEOUT) -> None:
    """Wait for an async `condition()` to hold; fail when it does not within `timeout`."""
    deadline = time.monotonic() + timeout
    while not await condition():
        if time.monotonic() > deadline:
            raise AssertionError("the awaited database state never came")
        await asyncio.sleep(0.01)


async def until_blocked(dsn: str, count: int) -> None:
    """Wait until exactly `count` backends of this database wait for a lock."""
    async def condition() -> bool:
        return await blocked(dsn) == count
    await until(condition)


@asynccontextmanager
async def holding_row(dsn: str, table: str, row_id: str) -> AsyncIterator[None]:
    """`SELECT ... FOR UPDATE` on one row (`identity.<table>`) in an open transaction, released on exit."""
    import psycopg

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        cur = await conn.execute(f"SELECT id FROM identity.{table} WHERE id = %s FOR UPDATE", (row_id,))  # noqa: S608
        assert await cur.fetchall() == [(row_id,)], "the row to hold does not exist"
        try:
            yield
        finally:
            await conn.commit()


@asynccontextmanager
async def holding_user_insert(dsn: str, *, like_email: str, email: str, user_id: str) -> AsyncIterator[None]:
    """An uncommitted `identity.users` row for `email` (a copy of the user with `like_email`), held
    in an open transaction; it is committed on exit. A concurrent insert of `email` waits for it."""
    import psycopg

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        cur = await conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'identity' AND table_name = 'users' ORDER BY ordinal_position")
        columns = [name for (name,) in await cur.fetchall()]
        values = {"id": "%s", "email": "%s", "signin_account_id": "NULL"}
        select = ", ".join(values.get(c, f'"{c}"') for c in columns)
        given = {"id": user_id, "email": email}
        params = (*(given[c] for c in columns if c in given), like_email)
        names = ", ".join(f'"{c}"' for c in columns)
        await conn.execute(
            f"INSERT INTO identity.users ({names}) "  # noqa: S608
            f"SELECT {select} FROM identity.users WHERE email = %s",
            params)
        try:
            yield
        finally:
            await conn.commit()
