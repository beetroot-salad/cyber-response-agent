"""The proxy's read of a tenant system's current record (#1366 O7, R14).

`PostgresSystemRecords(dsn)` is the port over the read-only login (a member of `defender_proxy_reader`, which
may select `tenancy.system_versions` and nothing else). Each call reads the highest version of one
(tenant, system) through a blocking connection bounded by the request's deadline (connect and statement
timeouts), like `OpenBaoStore`. Connections are kept for reuse, at most `IDLE_CONNECTIONS` idle at once, so a request
does not pay a connection's setup; one that failed is closed, never reused, and a reused one that fails is
replaced once by a fresh one. A fresh connection is bounded by the request's deadline; a kept one by the statement
timeout while its server answers, and by TCP (about `READ_TIMEOUT_SEC`, not the request's deadline) when the server
vanished without closing it. Building it does not connect. A database that cannot be reached is
`TransportFault`; a query it refuses (a login without the grant) is `ConfigFault`. No message holds the DSN."""
from __future__ import annotations

import contextlib
import math
import threading
import time
from typing import Any, Protocol

import psycopg
from psycopg.rows import tuple_row

from defender.credential_proxy._deadline import current as current_deadline
from defender.kit.faults import ConfigFault, TransportFault
from defender.tenancy.record_values import SystemRecord

#: How long one read may take when no request deadline is current, in seconds.
READ_TIMEOUT_SEC = 10.0
#: How many idle connections the port keeps for reuse; one returned beyond them is closed.
IDLE_CONNECTIONS = 4

#: One row always: whether the tenant is imported (its records mark, R8), then the system's newest version (nulls when it
#: has none), so an unknown tenant and an unknown system are told apart in one read.
_QUERY = ("SELECT k.known, v.version, v.adapter_id, v.enabled, v.settings, v.access, v.credential_generation, v.deleted "
          "FROM (SELECT EXISTS (SELECT 1 FROM tenancy.records_mark WHERE tenant_id = %(t)s) AS known) AS k "
          "LEFT JOIN LATERAL (SELECT version, adapter_id, enabled, settings, access, credential_generation, deleted "
          "FROM tenancy.system_versions WHERE tenant_id = %(t)s AND system_id = %(s)s "
          "ORDER BY version DESC LIMIT 1) AS v ON true")


class SystemRecordsPort(Protocol):
    """The proxy's read of a system's current record; None when there is none or it is deleted. A disabled
    record comes back with `enabled=False`. A tenant without the records mark (never imported, or not one of ours)
    raises an unlabelled `ConfigFault`: a validly signed token naming such a tenant is the proxy's access, not one
    system's setup (#1363)."""

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
        # One budget for the whole read, each step given what is left of it: a second connection after a stale one
        # never restarts the clock.
        end = time.monotonic() + (READ_TIMEOUT_SEC if deadline is None
                                  else min(READ_TIMEOUT_SEC, deadline.left("the record read")))

        def left() -> float:
            return max(0.001, end - time.monotonic())

        reused = self._take()
        row: Any = None
        if reused is not None:
            try:
                row = self._read(reused, left(), tenant_id, system_id, reused=True)
            except _Stale:
                reused = None  # closed by `_read`; a fresh connection answers instead
        if reused is None:
            row = self._read(self._connect(left()), left(), tenant_id, system_id, reused=False)
        known, version, adapter_id, enabled, settings, access, generation, deleted = row
        if not known:
            raise ConfigFault("the request token's tenant has no system records (it is not imported)")
        if version is None or deleted:
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
            # A kept connection's server is bounded by the statement timeout while it answers; one that vanished
            # without closing the connection is cut by TCP: unacknowledged data after `READ_TIMEOUT_SEC`, a silent peer
            # by keepalives on the same order.
            return psycopg.connect(self._dsn, connect_timeout=max(1, math.ceil(left)), row_factory=tuple_row,
                                   autocommit=True, tcp_user_timeout=int(READ_TIMEOUT_SEC * 1000), keepalives=1,
                                   keepalives_idle=5, keepalives_interval=2, keepalives_count=2)
        except psycopg.Error as e:
            raise TransportFault(f"the records database is unreachable ({type(e).__name__})") from None

    def _read(self, conn: Any, left: float, tenant_id: str, system_id: str, *, reused: bool) -> Any:  # noqa: PLR0913 — one read's connection, bound and key
        """The row, on `conn` under a statement timeout of `left`; `conn` goes back to the idle set after a read that
        succeeded and is closed after one that failed. A connection kept idle that fails as a connection raises `_Stale`,
        for the caller to read again on a fresh one."""
        try:
            with conn.transaction():
                conn.execute("SELECT set_config('statement_timeout', %s, true)", (str(max(1, int(left * 1000))),))
                row = conn.execute(_QUERY, {"t": tenant_id, "s": system_id}).fetchone()
        except (psycopg.errors.InsufficientPrivilege, psycopg.errors.UndefinedTable,
                psycopg.errors.InvalidSchemaName, psycopg.errors.UndefinedColumn) as e:
            conn.close()
            raise ConfigFault(f"the records database refused the read of the system's record "
                              f"({type(e).__name__})") from None
        except psycopg.Error as e:
            conn.close()
            # A kept connection the server closed fails as a connection; a statement it cancelled (the read's own
            # timeout) is a slow database, not a stale connection, and is not read again.
            if reused and isinstance(e, psycopg.OperationalError) and not isinstance(e, psycopg.errors.QueryCanceled):
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
