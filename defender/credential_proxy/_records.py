"""The proxy's read of a tenant system's current record (#1366 O7, R14).

`PostgresSystemRecords(dsn)` is the port over the read-only login (a member of `defender_proxy_reader`, which
may select `tenancy.system_versions` and nothing else). Each call reads the highest version of one
(tenant, system) through a blocking connection bounded by the request's deadline (connect and statement
timeouts), like `OpenBaoStore`. Building it does not connect. A database that cannot be reached is
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
        self._open: set[Any] = set()
        self._closed = False

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    __str__ = __repr__

    def current_system(self, tenant_id: str, system_id: str) -> SystemRecord | None:
        deadline = current_deadline()
        left = READ_TIMEOUT_SEC if deadline is None else min(READ_TIMEOUT_SEC, deadline.left("the record read"))
        seconds = max(1, math.ceil(left))
        try:
            conn = psycopg.connect(self._dsn, connect_timeout=seconds, row_factory=tuple_row,
                                   options=f"-c statement_timeout={max(1, int(left * 1000))}")
        except psycopg.Error as e:
            raise TransportFault(f"the records database is unreachable ({type(e).__name__})") from None
        with self._lock:
            if self._closed:
                conn.close()
                raise TransportFault("the records port is closed")
            self._open.add(conn)
        try:
            with conn:
                row = conn.execute(_QUERY, (tenant_id, system_id)).fetchone()
        except (psycopg.errors.InsufficientPrivilege, psycopg.errors.UndefinedTable,
                psycopg.errors.InvalidSchemaName, psycopg.errors.UndefinedColumn) as e:
            raise ConfigFault(f"the records database refused the read of the system's record "
                              f"({type(e).__name__})") from None
        except psycopg.Error as e:
            raise TransportFault(f"the records database failed the read ({type(e).__name__})") from None
        finally:
            with self._lock:
                self._open.discard(conn)
            conn.close()
        if row is None:
            return None
        version, adapter_id, enabled, settings, access, generation, deleted = row
        if deleted:
            return None
        return SystemRecord(system_id=system_id, version=version, adapter_id=adapter_id, enabled=enabled,
                            settings=dict(settings), access=access, credential_generation=generation)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            held, self._open = list(self._open), set()
        for conn in held:
            with contextlib.suppress(psycopg.Error):
                conn.close()


__all__ = ["PostgresSystemRecords", "SystemRecordsPort"]
