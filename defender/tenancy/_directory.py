"""`TenantDirectory`: the synchronous, read-only view of the tenant repository for host code (#1214
Flow 4), which runs outside any event loop (run start, drains, the connect command, the host
actor's step bodies in a worker thread).

Each call is one `asyncio.run`: it opens a repository, reads, and closes the repository in that same
loop (#1339's engine rule), so no engine outlives its loop; a connection per call is fine at
per-drain-claim rates. Called inside a running loop it refuses (RuntimeError) before opening
anything. Its public methods only read; the one write host processes make, the publish outcome
(P2), goes through `_call` from `tenancy._publish_status`. Imports no database code: the repository comes from the factory it is given.

A call the database cannot answer (the driver's connection-class error: refused, dropped, timed
out, the login refused) is `RecordsUnreachable`, a `TenantRefused` every host caller may treat as
transient; any other error reaches the caller as raised."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, TypeVar

from defender.records.formats import TenantId, TenantRefused

if TYPE_CHECKING:
    from defender.tenancy.models import ForgeWiring, Generation

_R = TypeVar("_R")


class RecordsUnreachable(TenantRefused):
    """The tenant records' database could not be reached: the next attempt may find it up."""


def _connection_lost(error: BaseException) -> bool:
    """Is `error` the driver's connection-class error (SQLAlchemy's `OperationalError` or
    `InterfaceError`)? Read off the loaded module, never imported: a process that raised one has it
    loaded, and one that has not loaded it raised none."""
    exc = sys.modules.get("sqlalchemy.exc")
    return exc is not None and isinstance(error, (exc.OperationalError, exc.InterfaceError))


def _why(error: BaseException) -> str:
    """The driver's first line (it names the host and port, never the password)."""
    cause = getattr(error, "orig", None)
    lines = str(cause if cause is not None else error).splitlines()
    return lines[0] if lines else type(error).__name__


class TenantDirectory:
    def __init__(self, open_repository: Callable[[], Any]) -> None:
        self._open = open_repository

    def state(self, tenant_id: TenantId) -> str | None:
        """The tenant's state (`creating`, `active`, `offboarding`, `offboarded`), None when unknown."""
        async def read(repository: Any) -> str | None:
            record = await repository.tenant(tenant_id)
            return None if record is None else record.state
        return self._call(read)

    def forge_wiring(self, tenant_id: TenantId) -> ForgeWiring | None:
        """The tenant's recorded repo and origin, None when none is recorded."""
        async def read(repository: Any) -> ForgeWiring | None:
            return await repository.forge_wiring(tenant_id)
        return self._call(read)

    def admission(self, tenant_id: TenantId) -> tuple[str | None, ForgeWiring | None]:
        """The tenant's state and its recorded forge wiring in one repository call (r10 Finding 9)."""
        async def read(repository: Any) -> tuple[str | None, ForgeWiring | None]:
            return await repository.admission(tenant_id)
        return self._call(read)

    def generations(self, tenant_id: TenantId) -> list[Generation]:
        """The tenant's credential generations (the live one among them), [] when none: what the
        host's forge credential provider reads on every mint (P4)."""
        async def read(repository: Any) -> list[Generation]:
            return await repository.generations(tenant_id)
        return self._call(read)

    def _call(self, read: Callable[[Any], Awaitable[_R]]) -> _R:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError("TenantDirectory is synchronous: call it from a thread with no running event loop")

        async def once() -> _R:
            repository = self._open()
            try:
                return await read(repository)
            finally:
                await repository.close()
        try:
            return asyncio.run(once())
        except Exception as error:
            if not _connection_lost(error):
                raise
            raise RecordsUnreachable(f"the database could not be reached: {_why(error)}") from error
