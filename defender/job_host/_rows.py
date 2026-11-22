"""The helper's rows (#1546 PR2, PR7, A-O3, A-O6): the job store's writes under the job's claim, and the claim's reads.

The helper is synchronous and answers each connection on its own thread; the job store is async. One event loop runs on a
thread of its own for the helper's life, and every call is handed to it and waited for (`Rows.call`), so no transaction is
ever held across a socket request: each write is one store transaction that checks the claim is live (PR7).

Writes go through `JobStore` alone (`stage_fact`, `begin_upload`, `finish_upload`); a `Conflict` (the claim no longer
live, a second write of a create-once name) is answered as False, never raised. The reads the store has no verb for (the
claim row itself, and an input's accepted upload for a pull) are read-only queries over the jobs tables, here; they write
nothing."""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import threading
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

_logger = logging.getLogger(__name__)

_T = TypeVar("_T")

#: Seconds one database call may take before the helper gives up on it.
_CALL_WAIT = 60.0
#: Pull refusal codes (A-O6): not in the claim's input set (any tenant, any object: one code, no existence oracle); in the
#: set but not usable now (non-`clean`, expired, offboarded); the store did not answer the accepted bytes.
OUT_OF_CLAIM, UNAVAILABLE, STORE_FAULT = "out_of_claim", "unavailable", "store_fault"
#: Evidence states whose accepted objects may be read (an owner whose state is `none` or `expired` has none).
_READABLE_STATES = ("complete", "partial", "lost")


@dataclass(frozen=True)
class ClaimView:
    """The claim row the worker's claim transaction wrote: its token, tenant, kind, fixed input set `(owner, object)`, launch
    facts and the id of the row it references."""

    token: str
    tenant_id: str
    kind: str
    inputs: tuple[tuple[str, str], ...]
    launch: dict[str, Any]
    reference: str | None


@dataclass(frozen=True)
class InputObject:
    """One accepted object a pull may read: where it lies (`t/<T>/<owner kind>/<owner>/<claim>/<object>`), its recorded size
    and digest, and its wrapped data key."""

    key: str
    size: int
    sha256: str
    wrapped_key: str


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def object_key(tenant_id: str, owner_kind: str, owner: str, claim: str, obj: str) -> str:
    """The store key of an object (design: `t/<tenant>/<owner kind>/<owner id>/<claim token>/<object>`)."""
    return f"t/{tenant_id}/{owner_kind}/{owner}/{claim}/{obj}"


def _inputs(raw: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(raw, list):
        return ()
    return tuple((str(i["owner"]), str(i["object"])) for i in raw
                 if isinstance(i, dict) and isinstance(i.get("owner"), str) and isinstance(i.get("object"), str))


class Rows:
    """The job store and the claim's reads over `dsn`, on one loop thread (module doc). `close()` at the helper's end."""

    def __init__(self, dsn: str) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, name="job-rows", daemon=True)
        self._thread.start()
        self._dsn = dsn
        self._store: Any = None
        self._sessions: Any = None
        self._engine: Any = None
        self.call(self._open)

    async def _open(self) -> None:
        from defender.database import async_engine, sessions
        from defender.jobs import JobStore

        self._store = JobStore(self._dsn, clock=_now, max_connections=4)
        self._engine = async_engine(self._dsn, max_connections=2)
        self._sessions = sessions(self._engine)

    def call(self, make: Callable[[], Awaitable[_T]], *, timeout: float = _CALL_WAIT) -> _T:
        """`make()` awaited on the loop thread; its result, or what it raised."""
        async def run() -> _T:
            return await make()

        return asyncio.run_coroutine_threadsafe(run(), self._loop).result(timeout)

    def close(self) -> None:
        async def shut() -> None:
            if self._store is not None:
                await self._store.close()
            if self._engine is not None:
                await self._engine.dispose()

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
        return self.call(lambda: self._claim(token))

    async def _claim(self, token: str) -> ClaimView | None:
        from sqlalchemy import select

        from defender.jobs.models import ClaimRow

        async with self._sessions() as s:
            row = (await s.execute(select(ClaimRow).where(ClaimRow.token == token))).scalars().first()
        if row is None:
            return None
        reference = row.investigation_id or row.learning_job_id or row.host_request_id or row.hold_tenant_id
        return ClaimView(token=row.token, tenant_id=str(row.tenant_id), kind=row.kind, inputs=_inputs(row.inputs),
                         launch=dict(row.launch) if isinstance(row.launch, dict) else {},
                         reference=None if reference is None else str(reference))

    def input_object(self, claim: ClaimView, owner: object, obj: object) -> InputObject | str:
        """The accepted object a pull of `(owner, obj)` under `claim` reads, or the refusal code (A-O6): `out_of_claim` for
        anything the claim's fixed input set does not name, `unavailable` for a member whose owner is not `clean`, has no
        readable evidence, has no accepted upload of the object, or whose tenant is not active."""
        if not isinstance(owner, str) or not isinstance(obj, str) or (owner, obj) not in claim.inputs:
            return OUT_OF_CLAIM
        try:
            parsed = uuid.UUID(owner)
        except ValueError:
            return OUT_OF_CLAIM
        return self.call(lambda: self._input(claim.tenant_id, str(parsed), obj))

    async def _input(self, tenant_id: str, owner: str, obj: str) -> InputObject | str:
        from sqlalchemy import select

        from defender.jobs.models import ClaimRow, InvestigationRow, LearningJobRow, UploadRow
        from defender.tenancy.models import TenantRecord

        column: Any
        async with self._sessions() as s:
            inv = (await s.execute(select(InvestigationRow.tenant_id, InvestigationRow.evidence_state, InvestigationRow.scrub)
                                   .where(InvestigationRow.id == owner))).first()
            if inv is not None:
                owner_kind, column, (tenant, state, scrub) = "investigation", ClaimRow.investigation_id, inv
            else:
                job = (await s.execute(select(LearningJobRow.tenant_id, LearningJobRow.evidence_state)
                                       .where(LearningJobRow.id == owner))).first()
                if job is None:
                    return OUT_OF_CLAIM
                owner_kind, column, (tenant, state), scrub = "learning", ClaimRow.learning_job_id, job, "clean"
            if str(tenant) != tenant_id:
                return OUT_OF_CLAIM
            tenant_state = (await s.execute(select(TenantRecord.state).where(TenantRecord.id == tenant))).scalar()
            if tenant_state != "active" or state not in _READABLE_STATES or scrub != "clean":
                return UNAVAILABLE
            found = (await s.execute(
                select(UploadRow.token, UploadRow.size, UploadRow.sha256, UploadRow.wrapped_key)
                .join(ClaimRow, ClaimRow.token == UploadRow.token)
                .where(column == owner, UploadRow.object == obj, UploadRow.status == "uploaded",
                       UploadRow.accepted_at.is_not(None)))).first()
        if found is None:
            return UNAVAILABLE
        claim, size, sha256, wrapped = found
        return InputObject(object_key(tenant_id, owner_kind, owner, claim, obj), int(size), str(sha256), str(wrapped))
