"""The proxy's read of a tenant system's current record (#1366 O7, R14).

`PostgresSystemRecords(dsn)` is the port over the read-only login (a member of `defender_proxy_reader`, which
may select `tenancy.system_versions` and nothing else). Each call reads the highest version of one
(tenant, system) through a blocking connection bounded by the request's deadline (connect and statement
timeouts), like `OpenBaoStore`. Connections are kept for reuse, at most `IDLE_CONNECTIONS` idle at once, so a request
does not pay a connection's setup; one that failed is closed, never reused, and a reused one that fails is
replaced once by a fresh one. Building it does not connect. A database that cannot be reached is
`TransportFault`; a query it refuses (a login without the grant) is `ConfigFault`. No message holds the DSN."""
from __future__ import annotations

import contextlib
import math
import threading
from typing import Any, Protocol

import psycopg
from psycopg.rows import tuple_row

from defender.credential_proxy._deadline import current as current_deadline
from defender.kit.faults import ConfigFault, TransportFault
from defender.tenancy.models import SystemRecord

#: How long one read may take when no request deadline is current, in seconds.
READ_TIMEOUT_SEC = 10.0
#: How many idle connections the port keeps for reuse; one returned beyond them is closed.
IDLE_CONNECTIONS = 4

_QUERY = ("SELECT version, adapter_id, enabled, settings, access, credential_generation, deleted "
          "FROM tenancy.system_versions WHERE tenant_id = %s AND system_id = %s "
          "ORDER BY version DESC LIMIT 1")


class SystemRecordsPort(Protocol):
    """The proxy's read of a system's current record; None when there is none or it is deleted. A disabled
    record comes back with `enabled=False`."""

    def current_system(self, tenant_id: str, system_id: str) -> SystemRecord | None: ...


class PostgresSystemRecords:
    def __init__(self, dsn: str) -> None:
        if not isinstance(dsn, str) or not dsn or "\0" in dsn:
            raise ConfigFault("the records DSN must be non-empty text")
        self._dsn = dsn
        self._lock = threading.Lock()
        self._idle: list[Any] = []
        self._closed = False

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    __str__ = __repr__

    def current_system(self, tenant_id: str, system_id: str) -> SystemRecord | None:
        deadline = current_deadline()
        left = READ_TIMEOUT_SEC if deadline is None else min(READ_TIMEOUT_SEC, deadline.left("the record read"))
        reused = self._take()
        row: Any = None
        if reused is not None:
            try:
                row = self._read(reused, left, tenant_id, system_id, reused=True)
            except _Stale:
                reused = None  # closed by `_read`; a fresh connection answers instead
        if reused is None:
            row = self._read(self._connect(left), left, tenant_id, system_id, reused=False)
        if row is None:
            return None
        version, adapter_id, enabled, settings, access, generation, deleted = row
        if deleted:
            return None
        return SystemRecord(system_id=system_id, version=version, adapter_id=adapter_id, enabled=enabled,
                            settings=dict(settings), access=access, credential_generation=generation)

    def _take(self) -> Any:
        """An idle connection to reuse, or None."""
        with self._lock:
            if self._closed:
                raise TransportFault("the records port is closed")
            return self._idle.pop() if self._idle else None

    def _connect(self, left: float) -> Any:
        try:
            return psycopg.connect(self._dsn, connect_timeout=max(1, math.ceil(left)), row_factory=tuple_row,
                                   autocommit=True)
        except psycopg.Error as e:
            raise TransportFault(f"the records database is unreachable ({type(e).__name__})") from None

    def _read(self, conn: Any, left: float, tenant_id: str, system_id: str, *, reused: bool) -> Any:  # noqa: PLR0913 — one read's connection, bound and key
        """The row, on `conn` under a statement timeout of `left`; `conn` goes back to the idle set after a read that
        succeeded and is closed after one that failed. A connection kept idle that fails as a connection raises `_Stale`,
        for the caller to read again on a fresh one."""
        try:
            with conn.transaction():
                conn.execute("SELECT set_config('statement_timeout', %s, true)", (str(max(1, int(left * 1000))),))
                row = conn.execute(_QUERY, (tenant_id, system_id)).fetchone()
        except (psycopg.errors.InsufficientPrivilege, psycopg.errors.UndefinedTable,
                psycopg.errors.InvalidSchemaName, psycopg.errors.UndefinedColumn) as e:
            conn.close()
            raise ConfigFault(f"the records database refused the read of the system's record "
                              f"({type(e).__name__})") from None
        except psycopg.Error as e:
            conn.close()
            if reused and isinstance(e, psycopg.OperationalError):
                raise _Stale from None
            raise TransportFault(f"the records database failed the read ({type(e).__name__})") from None
        self._give_back(conn)
        return row

    def _give_back(self, conn: Any) -> None:
        with self._lock:
            if not self._closed and len(self._idle) < IDLE_CONNECTIONS:
                self._idle.append(conn)
                return
        conn.close()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            held, self._idle = self._idle, []
        for conn in held:
            with contextlib.suppress(psycopg.Error):
                conn.close()


class _Stale(Exception):
    """A kept connection that failed as a connection (the server closed it while it sat idle)."""


__all__ = ["PostgresSystemRecords", "SystemRecordsPort"]
