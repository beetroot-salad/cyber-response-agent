"""The helper's rows (#1546 PR2, PR7, A-O3, A-O6): the job store's writes under the job's claim, and the claim's reads.

The helper is synchronous and answers each connection on its own thread; the job store is async. One event loop runs on a
thread of its own for the helper's life, and every call is handed to it and waited for (`Rows.call`), so no transaction is
ever held across a socket request: each write is one store transaction that checks the claim is live (PR7).

Every read and write goes through `JobStore` alone (`stage_fact`, `begin_upload`, `finish_upload`, `refuse_upload`;
`get_claim`, `claim_live`, `accepted_input`, `get_alert`); a `Conflict` on a write (the claim no longer live, a second
write of a create-once name) is answered as False, never raised."""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import threading
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from defender.evidence import object_key
from defender.jobs.models import ClaimView

_logger = logging.getLogger(__name__)

_T = TypeVar("_T")

#: Seconds one database call may take before the helper gives up on it.
_CALL_WAIT = 60.0
#: Pull refusal codes (A-O6): not in the claim's input set (any tenant, any object: one code, no existence oracle); in the
#: set but not usable now (non-`clean`, expired, offboarded); the store did not answer the accepted bytes.
OUT_OF_CLAIM, UNAVAILABLE, STORE_FAULT = "out_of_claim", "unavailable", "store_fault"


@dataclass(frozen=True)
class InputObject:
    """One accepted object a pull may read: where it lies (`t/<T>/<owner kind>/<owner>/<claim>/<object>`), its recorded size
    and digest, and its wrapped data key."""

    key: str
    size: int
    sha256: str
    wrapped_key: str


class Rows:
    """The job store and the claim's reads over `dsn`, on one loop thread (module doc). `close()` at the helper's end."""

    def __init__(self, dsn: str) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, name="job-rows", daemon=True)
        self._thread.start()
        self._dsn = dsn
        self._store: Any = None
        self.call(self._open)

    async def _open(self) -> None:
        from defender.jobs import JobStore

        self._store = JobStore(self._dsn, clock=lambda: _dt.datetime.now(_dt.UTC), max_connections=4)

    def call(self, make: Callable[[], Awaitable[_T]], *, timeout: float = _CALL_WAIT) -> _T:
        """`make()` awaited on the loop thread; its result, or what it raised."""
        async def run() -> _T:
            return await make()

        return asyncio.run_coroutine_threadsafe(run(), self._loop).result(timeout)

    def close(self) -> None:
        async def shut() -> None:
            if self._store is not None:
                await self._store.close()

        try:
            self.call(shut, timeout=10)
        except Exception:  # noqa: BLE001 — closing at the end; a fault here changes nothing written
            _logger.warning("the helper's database connections did not close cleanly", exc_info=True)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)

    # --- writes (the store's) --------------------------------------------------------------------------------------

    def _conflicted(self, make: Callable[[], Awaitable[Any]], what: str) -> bool:
        from defender.jobs import Conflict

        try:
            self.call(make)
        except Conflict as refused:
            _logger.info("%s was not written: %s", what, refused)
            return False
        return True

    def stage(self, token: str, name: str, body: Any) -> bool:
        """`name` staged under the live claim `token`; False when the store refused it (not live, or create-once)."""
        return self._conflicted(lambda: self._store.stage_fact(token, name, body), f"the fact {name!r}")

    def begin_upload(self, token: str, obj: str, *, size: int, sha256: str, wrapped_key: str, scrub: str | None) -> bool:
        return self._conflicted(lambda: self._store.begin_upload(token, obj, size=size, sha256=sha256,
                                                                 wrapped_key=wrapped_key, scrub=scrub),
                                f"the upload row of {obj!r}")

    def refuse_upload(self, token: str, obj: str, *, scrub: str | None) -> bool:
        return self._conflicted(lambda: self._store.refuse_upload(token, obj, scrub=scrub), f"the refusal of {obj!r}")

    def finish_upload(self, token: str, obj: str, *, status: str) -> bool:
        return self._conflicted(lambda: self._store.finish_upload(token, obj, status=status),
                                f"the upload end of {obj!r}")

    def alert(self, tenant_id: str, alert_id: str) -> Any:
        """The stored alert (its exact bytes in `raw`), or None."""
        from defender.records.formats import AlertId, IdRefused, TenantId

        try:
            tenant, alert = TenantId(tenant_id), AlertId(alert_id)
        except (IdRefused, ValueError):
            return None
        return self.call(lambda: self._store.get_alert(tenant, alert))

    # --- reads (the claim's) -----------------------------------------------------------------------------------------

    def claim(self, token: str) -> ClaimView | None:
        """The claim row `token`, or None when there is none."""
        return self.call(lambda: self._store.get_claim(token))

    def run_unusable(self, tenant_id: str, run_id: str) -> bool:
        """Whether the tenant's investigation `run_id` can never be a drain's input (`JobStore.run_unusable`)."""
        return self.call(lambda: self._store.run_unusable(tenant_id, run_id))

    def input_object(self, claim: ClaimView, owner: object, obj: object) -> InputObject | str:
        """The accepted object a pull of `(owner, obj)` under `claim` reads, or the refusal code (A-O6): `out_of_claim` for
        anything the claim's fixed input set does not name (or an owner of no row of the claim's tenant), `unavailable`
        while the pulling claim is no longer live (a read after an offboard or a take-over), or for a member whose owner
        is not `clean`, has no readable evidence or no accepted upload of the object, or whose tenant is not active."""
        from defender.jobs import Conflict, NotFound

        if not isinstance(owner, str) or not isinstance(obj, str) or (owner, obj) not in claim.inputs:
            return OUT_OF_CLAIM
        try:
            parsed = str(uuid.UUID(owner))
        except ValueError:
            return OUT_OF_CLAIM
        if not self.call(lambda: self._store.claim_live(claim.token)):
            return UNAVAILABLE
        try:
            found = self.call(lambda: self._store.accepted_input(claim.tenant_id, parsed, obj))
        except NotFound:
            return OUT_OF_CLAIM
        except Conflict:
            return UNAVAILABLE
        return InputObject(object_key(claim.tenant_id, found.owner_kind, parsed, found.claim, obj), found.size,
                           found.sha256, found.wrapped_key)
