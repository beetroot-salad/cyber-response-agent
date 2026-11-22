"""`PeopleDirectory`: the synchronous view of who is wanted in a tenant (#1592 OD-6), for host code that runs outside
any event loop (the feedback tick, which counts a comment by its author's product membership).

The shape of `tenancy.TenantDirectory`, not a subclass of it: each call is one `asyncio.run` that opens an identity
repository from the factory it is given, reads, and closes it in that same loop; called inside a running loop it
refuses (RuntimeError) before opening anything. A call the database cannot answer is `RecordsUnreachable`, a refusal
every host caller may treat as transient; any other error reaches the caller as raised. Imports no database code."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from defender.records.formats import TenantId, UserId
from defender.tenancy import RecordsUnreachable, connection_lost, why_unreachable


class PeopleDirectory:
    def __init__(self, open_repository: Callable[[], Any]) -> None:
        self._open = open_repository

    def wanted_users(self, tenant_id: TenantId) -> set[UserId]:
        """The users wanted in the tenant (an `active` membership of an `active` tenant), empty for any other tenant."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError("PeopleDirectory is synchronous: call it from a thread with no running event loop")

        async def once() -> set[UserId]:
            repository = self._open()
            try:
                return set(await repository.wanted_users(tenant_id))
            finally:
                await repository.close()
        try:
            return asyncio.run(once())
        except Exception as error:
            if not connection_lost(error):
                raise
            raise RecordsUnreachable(f"the database could not be reached: {why_unreachable(error)}") from error
