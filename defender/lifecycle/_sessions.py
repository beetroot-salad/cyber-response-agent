"""Forgejo's sessions (#1592 OD-4, OD-11): the reader of a session row's signed-in user, and the sessions port the
request worker and the cap job read and delete through, on PostgreSQL and as a memory twin.

Forgejo keeps each session as one row of `session(key, data, expiry, signed_in_at)` in its own database; `data` is
Go's `encoding/gob` of the session's values, and a signed-in session holds the entry `uid` (P31). The port reads only
rows holding `UID_ENTRY`, and never sends a key or a row's data to a log."""
from __future__ import annotations

import datetime as _dt
from collections.abc import Collection
from typing import Any, NamedTuple

#: The gob bytes that open a session's `uid` entry: the string `uid`, then the interface type name `int64` and its
#: type id (P31). The one prefilter of the worker's select and the cap job's second rule.
UID_ENTRY = b"\x03uid\x05int64\x04"
#: The largest number of bytes a gob unsigned integer of 64 bits takes after its count byte.
_UINT_BYTES = 8


class UnreadableSession(ValueError):
    """A session row holding the `uid` key bytes in any shape but the anchored entry (OD-11). The message names
    neither the row's key nor its data."""


class SessionRow(NamedTuple):
    """A stamped session row holding `UID_ENTRY`: its key (the cookie's value), its data and its sign-in time."""

    key: str
    data: bytes
    signed_in_at: _dt.datetime


def session_uid(data: bytes) -> int:
    """The Forgejo user id a session row is signed in as. The row must hold `UID_ENTRY` exactly once, followed by a
    length byte L, a field delta of 0, and a gob unsigned integer of exactly L-1 bytes whose value is even and greater
    than 0 (a gob int is its value shifted left by one): the id is that value halved. Any other row is
    `UnreadableSession`."""
    if data.count(UID_ENTRY) != 1:
        raise UnreadableSession("the session row does not hold the uid entry exactly once")
    at = data.index(UID_ENTRY) + len(UID_ENTRY)
    head = data[at:at + 3]
    if len(head) < 3 or head[1] != 0:
        raise UnreadableSession("the session row's uid entry has no value of the expected shape")
    length, first = head[0], head[2]
    count = 1 if first < 128 else 256 - first
    if count > _UINT_BYTES or length - 1 != (count if first < 128 else count + 1):
        raise UnreadableSession("the session row's uid value has the wrong length")
    body = data[at + 2:at + 1 + length]
    if len(body) != length - 1:
        raise UnreadableSession("the session row ends inside its uid value")
    value = first if first < 128 else int.from_bytes(body[1:], "big")
    if value == 0 or value % 2:
        raise UnreadableSession("the session row's uid value is not a positive int")
    return value >> 1


class PostgresForgeSessions:
    """The sessions port over the Forgejo sessions database at `dsn` (a login of `fs_lifecycle`: select and delete
    only). Each call is one statement on a connection of its own, bounded by `statement_timeout` (seconds) for the
    connect and the statement alike; an unreachable database raises the driver's error."""

    def __init__(self, dsn: str, *, statement_timeout: float) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import NullPool

        from defender.database import url

        millis = max(1, int(statement_timeout * 1000))
        self._engine = create_async_engine(
            url(dsn), poolclass=NullPool,
            connect_args={"options": f"-c timezone=UTC -c statement_timeout={millis}",
                          "connect_timeout": max(1, round(statement_timeout))})

    async def _run(self, sql: str, params: dict[str, Any]) -> Any:
        from sqlalchemy import text

        async with self._engine.begin() as conn:
            return await conn.execute(text(sql), params)

    async def signed_in_rows(self) -> list[SessionRow]:
        """The prefilter select: every stamped row whose data holds `UID_ENTRY`."""
        result = await self._run("SELECT key, data, signed_in_at FROM session"
                                 " WHERE signed_in_at IS NOT NULL AND position(CAST(:entry AS bytea) IN data) > 0",
                                 {"entry": UID_ENTRY})
        return [SessionRow(str(key), bytes(data), at) for key, data, at in result.all()]

    async def delete(self, keys: Collection[str]) -> None:
        if keys:
            await self._run("DELETE FROM session WHERE key = ANY(CAST(:keys AS text[]))", {"keys": list(keys)})

    async def cap(self, older_than: float) -> int:
        """The cap job's two deletes, against the database's clock and with no decoding: rows signed in more than
        `older_than` seconds ago, and unstamped rows whose data holds `UID_ENTRY`. The number of rows deleted."""
        result = await self._run(
            "DELETE FROM session WHERE signed_in_at < now() - make_interval(secs => :older)"
            " OR (signed_in_at IS NULL AND position(CAST(:entry AS bytea) IN data) > 0)",
            {"older": float(older_than), "entry": UID_ENTRY})
        return int(result.rowcount)

    async def close(self) -> None:
        await self._engine.dispose()


class InMemoryForgeSessions:
    """The sessions port's memory twin, on the process clock. `insert` and `keys` are for tests."""

    def __init__(self) -> None:
        self._rows: dict[str, tuple[bytes, _dt.datetime | None]] = {}

    def insert(self, key: str, data: bytes, *, signed_in_at: _dt.datetime | None) -> None:
        self._rows[key] = (bytes(data), signed_in_at)

    def keys(self) -> set[str]:
        return set(self._rows)

    async def signed_in_rows(self) -> list[SessionRow]:
        return [SessionRow(key, data, at) for key, (data, at) in self._rows.items()
                if at is not None and UID_ENTRY in data]

    async def delete(self, keys: Collection[str]) -> None:
        for key in keys:
            self._rows.pop(key, None)

    async def cap(self, older_than: float) -> int:
        cut = _dt.datetime.now(_dt.UTC) - _dt.timedelta(seconds=older_than)
        gone = [key for key, (data, at) in self._rows.items()
                if (at is not None and at < cut) or (at is None and UID_ENTRY in data)]
        await self.delete(gone)
        return len(gone)

    async def close(self) -> None:
        return None
