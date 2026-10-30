"""The tenant repository port (#1214): what the API, the lifecycle actors and host processes need
from the tenancy tables. `InMemoryTenantRepository` (`tenancy/memory.py`) and
`PostgresTenantRepository` (`tenancy/postgres.py`) answer one contract suite. Imports no database
code, so the refusals below can be caught by code that never builds a repository.

Writers (P2, DC-4):
- The API: `request_create(now=)`, `request_resume(T)`, `request_offboard(T, now=)`,
  `request_rotate(T)`. Each is one conditional update on an ordinary connection that never takes
  the tenant lock; it returns the record it left, or raises `NotFound` (no such tenant) or
  `Conflict` (the tenant's state refuses the request).
- Host processes: `record_publish_status(T, line, by=)`, a launch-time publish report line.
- The worker holding a tenant's lock (management service or host actor), through `HeldTenant`.

A worker's step, the only way it writes:

    for tenant_id in await tenants.claimable("service", now=now):
        async with tenants.lock(tenant_id) as held:
            if held is None or not claimable_now(held.record, "service", now):
                continue                      # another worker holds it, or the job moved: skip
            record = held.record              # re-read on the lock's own connection
            ...                               # names first (P1), then the external calls
            await held.commit(step="repo", actor="service", add_generation=...)

`lock(T)` takes the tenant's lock without waiting: a session-level advisory lock
`pg_try_advisory_lock(LOCK_NAMESPACE, hashtext(T))` on a connection of its own (not pooled, with
server-side TCP keepalives), released when the context ends or the connection dies. It yields
`None` when another worker holds it (or the tenant is gone). The worker checks the re-read row
(`claimable_now`) before it starts: the listing may be stale by then. Every write of `HeldTenant`
(`commit`, `fail`) is ONE statement on that connection, fenced on the pending action, step and actor as read when the step started, on
`failure IS NULL`, and on the lock still being held. A commit moves the fence to what it wrote, so
a worker may run its next step under the same lock. A fence that misses, or any error on the
lock's connection, raises `FenceMissed`: the connection is closed, nothing more is written through
this hold (no failure either), and the worker stops working on the tenant. Any other exception
of a step is the worker's to record with `fail` (its text names the step and the external answer,
never a secret). `PostgresTenantRepository(dsn, lock_keepalive=)` takes the keepalive bound in
seconds (`LifecycleConfig.lock_keepalive`).

`claimable(actor, now=)` lists the tenants whose current step is `actor`'s with no failure
(`delete_repo` only once `repo_delete_after` has passed), oldest first; it does not look at locks.

Reads (`tenant`, `tenants`, `generations`, `forge_wiring`, `publish_status`) return detached
copies: changing one changes nothing stored."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Collection, Mapping
from contextlib import AbstractAsyncContextManager
from typing import TYPE_CHECKING, Any, Literal, Protocol

if TYPE_CHECKING:
    from defender.tenancy.models import ForgeWiring, Generation, TenantRecord

#: The first key of every tenant lock: a fixed int4 naming tenancy's advisory locks.
LOCK_NAMESPACE = 1214
SERVICE = "service"
HOST = "host"

#: `HeldTenant.commit`'s marker for a tenant column the commit leaves as it is.
KEEP: Any = type("Keep", (), {"__repr__": lambda _self: "KEEP"})()
#: `destroy=ALL` marks every generation of the tenant not yet destroyed.
ALL: Literal["all"] = "all"


class NotFound(Exception):
    """No tenant with this id (the endpoints answer 404)."""


class Conflict(Exception):
    """The tenant's state refuses the request (the endpoints answer 409)."""


class FenceMissed(Exception):
    """A held tenant's write did not land: the job moved under the worker (an offboard, a resume,
    a hand edit), or the lock's connection failed or was cut. The hold is spent: the worker writes
    nothing more for the tenant, a failure included, and leaves it to the next pass."""


class HeldTenant(Protocol):
    """One tenant under its lock, for one worker. `record` is the row as re-read after locking
    (and as left by the last commit); writes go only through `commit` and `fail`."""

    tenant_id: str
    record: TenantRecord

    async def generations(self) -> list[Generation]:
        """The tenant's generations, read on the lock's connection."""
        ...

    async def forge_wiring(self) -> ForgeWiring | None: ...

    async def commit(  # noqa: PLR0913 — one keyword per thing a step records
        self, *, step: str | None, actor: str | None, state: str = KEEP, pending_action: str | None = KEEP,
        repo_url: str | None = KEEP, offboarded_at: _dt.datetime | None = KEEP,
        repo_delete_after: _dt.datetime | None = KEEP,
        add_generation: Generation | None = None,
        update_generations: Mapping[str, Mapping[str, Any]] | None = None,
        go_live: str | None = None, destroy: Collection[str] | Literal["all"] = (),
        wiring: ForgeWiring | None = None, drop_wiring: bool = False, drop_publish_status: bool = False,
    ) -> TenantRecord:
        """Record a step's outcome and the next step (`step`, `actor`; both None when nothing is
        left pending), in one fenced statement; the tenant's failure is left None. With it:
        other tenant columns; a new generation (names, P1); field changes per generation salt;
        `go_live` makes that generation `live` and the one live before it `retiring`; `destroy`
        marks generations (or `ALL` not yet destroyed) `destroyed`; `wiring` is recorded unless
        the tenant already has one (the lab keeps its own); `drop_wiring`/`drop_publish_status`
        delete those rows. Returns the row as written; `FenceMissed` when it did not land."""
        ...

    async def fail(self, failure: str, *, step: str, actor: str) -> TenantRecord:
        """Record a failed step with its restart point (DC-4), under the same fence. It stays until
        an administrator resumes (clears it) or offboards."""
        ...


class TenantRepository(Protocol):
    async def close(self) -> None:
        """Release what the repository holds (its connections)."""
        ...

    # --- reads
    async def tenant(self, tenant_id: str) -> TenantRecord | None: ...
    async def tenants(self) -> list[TenantRecord]:
        """Every tenant in every state, oldest first."""
        ...
    async def generations(self, tenant_id: str) -> list[Generation]: ...
    async def forge_wiring(self, tenant_id: str) -> ForgeWiring | None: ...
    async def publish_status(self, tenant_id: str) -> dict[str, str] | None:
        """The last publish outcome, keyed as the old file: `by`, then `published` (the commit),
        or `refused` with `kind` (`transient` | `operator`); None when none is recorded."""
        ...

    # --- requests (the API)
    async def request_create(self, *, now: _dt.datetime) -> TenantRecord:
        """A new tenant with a minted UUID: `creating`, `create` pending at step `names` (service)."""
        ...
    async def request_resume(self, tenant_id: str) -> TenantRecord:
        """Clear the failure, and nothing else; `Conflict` with no failure."""
        ...
    async def request_offboard(self, tenant_id: str, *, now: _dt.datetime) -> TenantRecord:
        """From `creating` or `active`: `offboarding`, `offboard` pending at step `offboard`
        (service), replacing any pending action and clearing the failure."""
        ...
    async def request_rotate(self, tenant_id: str) -> TenantRecord:
        """Only `active` with nothing pending: `rotate` pending at step `names` (service)."""
        ...

    # --- host processes
    async def record_publish_status(self, tenant_id: str, line: str, *, by: str) -> None:
        """Replace the tenant's publish outcome with what the report `line` states (`fresh <commit>`,
        `stale:transient <why>`, `stale:operator <why>`, `misconfigured <why>`)."""
        ...

    # --- workers
    async def claimable(self, actor: str, *, now: _dt.datetime) -> list[str]: ...
    def lock(self, tenant_id: str) -> AbstractAsyncContextManager[HeldTenant | None]: ...


def publish_outcome(line: str) -> tuple[str | None, str | None, str | None]:
    """`(published, refused, kind)` for a launch-time publish report line (`tenancy._publish_status`'s
    vocabulary): `fresh` publishes its commit; `stale:transient` is transient; `stale:operator` and
    `misconfigured` need an operator."""
    from defender._text import one_line
    from defender.tenancy._publish_status import FRESH, OPERATOR, STALE_TRANSIENT, TRANSIENT

    head, _sep, rest = line.strip().partition(" ")
    if head == FRESH:
        return rest, None, None
    return None, one_line(rest), TRANSIENT if head == STALE_TRANSIENT else OPERATOR


def claimable_now(record: TenantRecord, actor: str, now: _dt.datetime) -> bool:
    """Whether `actor` may take up the tenant's current step now (P6): something pending, the step
    is the actor's, no failure, and a repo deletion only once due."""
    return (record.pending_action is not None and record.step_actor == actor and record.failure is None
            and (record.pending_action != "delete_repo"
                 or (record.repo_delete_after is not None and record.repo_delete_after <= now)))
