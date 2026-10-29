"""`TenantDirectory`: the synchronous, read-only view of the tenant repository for host code (#1214
Flow 4), which runs outside any event loop (run start, drains, the connect command, the host
actor's step bodies in a worker thread).

Each call is one `asyncio.run`: it opens a repository, reads, and closes the repository in that same
loop (#1339's engine rule), so no engine outlives its loop; a connection per call is fine at
per-drain-claim rates. Called inside a running loop it refuses (RuntimeError) before opening
anything. Imports no database code: the repository comes from the factory it is given."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from defender.tenancy.models import ForgeWiring

_R = TypeVar("_R")


class TenantDirectory:
    def __init__(self, open_repository: Callable[[], Any]) -> None:
        self._open = open_repository

    def state(self, tenant_id: str) -> str | None:
        """The tenant's state (`creating`, `active`, `offboarding`, `offboarded`), None when unknown."""
        async def read(repository: Any) -> str | None:
            record = await repository.tenant(str(tenant_id))
            return None if record is None else record.state
        return self._call(read)

    def forge_wiring(self, tenant_id: str) -> ForgeWiring | None:
        """The tenant's recorded repo and origin, None when none is recorded."""
        async def read(repository: Any) -> ForgeWiring | None:
            return await repository.forge_wiring(str(tenant_id))
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
        return asyncio.run(once())
