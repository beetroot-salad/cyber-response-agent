"""The in-memory tenant repository: the demo's and the tests' store, with the rules of
`PostgresTenantRepository` held by itself (the state/pending-action pairs, one live generation per
tenant, rows that belong to a tenant) so both answer one contract suite (`repository.py`).

Safe across threads: every operation applies whole under one mutex and never awaits partway, so
the API's loop and a `TenantDirectory` call in another thread see each other's writes at once. The
tenant lock is a per-tenant flag, taken without waiting. Needs SQLAlchemy (the records are the
models) but no driver."""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import threading
import uuid
from collections.abc import AsyncIterator, Collection, Mapping
from typing import Any, Literal, TypeVar, overload

from defender.tenancy.models import ALLOWED_ACTIONS, ForgeWiring, Generation, PublishStatus, TenantRecord
from defender.tenancy.repository import (
    ADOPT_STEP,
    KEEP,
    SERVICE,
    Conflict,
    FenceMissed,
    NotFound,
    claimable_now,
    publish_outcome,
)

#: The job a seeded row in a state that requires one gets when the seeder names none.
_SEED_JOB = {"creating": ("create", "names", SERVICE), "offboarding": ("offboard", "offboard", SERVICE)}

_Row = TypeVar("_Row", TenantRecord, Generation, ForgeWiring, PublishStatus)


@overload
def _detached(row: _Row) -> _Row: ...
@overload
def _detached(row: None) -> None: ...
def _detached(row: _Row | None) -> _Row | None:
    """What the repository hands out: a copy, so the caller's changes never reach what is stored."""
    return None if row is None else dataclasses.replace(row)


def _check_pair(state: str, pending_action: str | None) -> None:
    if state not in ALLOWED_ACTIONS or pending_action not in ALLOWED_ACTIONS[state]:
        raise ValueError(f"a tenant {state!r} cannot have {pending_action!r} pending")


class InMemoryTenantRepository:
    def __init__(self) -> None:
        self._mutex = threading.RLock()
        self._tenants: dict[str, TenantRecord] = {}
        self._generations: dict[tuple[str, str], Generation] = {}
        self._wiring: dict[str, ForgeWiring] = {}
        self._publish: dict[str, PublishStatus] = {}
        self._locked: set[str] = set()

    async def close(self) -> None:
        """Nothing is held outside this object; the store outlives it."""

    # --- seeders (test support and the demo; not part of the port) ----------------------------
    async def add_tenant(  # noqa: PLR0913 — the pinned seeder signature
        self, tenant_id: str, *, created_at: _dt.datetime, state: str = "active", repo: str | None = None,
        origin: str | None = None, pending_action: str | None = None, step: str | None = None,
        step_actor: str | None = None, failure: str | None = None,
    ) -> TenantRecord:
        """Seeder: a tenant row (and its forge wiring when `repo` is given) as written, not requested.
        A state that requires a pending action gets its first step when none is named."""
        tenant_id = str(tenant_id)
        if pending_action is None and state in _SEED_JOB:
            pending_action, step, step_actor = _SEED_JOB[state]
        _check_pair(state, pending_action)
        if (repo is None) != (origin is None):
            raise ValueError("forge wiring needs both the repo and its origin")
        row = TenantRecord(id=tenant_id, created_at=created_at, state=state, pending_action=pending_action,
                           step=step, step_actor=step_actor, failure=failure)
        with self._mutex:
            if tenant_id in self._tenants:
                raise ValueError(f"tenant {tenant_id} is already stored")
            self._tenants[tenant_id] = row
            if repo is not None and origin is not None:
                self._wiring[tenant_id] = ForgeWiring(tenant_id=tenant_id, repo=repo, origin=origin)
            return _detached(row)

    async def add_generation(self, tenant_id: str, **fields: Any) -> Generation:
        """Seeder: one generation row of an existing tenant, with the model's field names."""
        row = Generation(tenant_id=str(tenant_id), **fields)
        with self._mutex:
            self._insert_generation(row)
            return _detached(row)

    def _insert_generation(self, row: Generation) -> None:
        if row.tenant_id not in self._tenants:
            raise ValueError(f"no tenant {row.tenant_id}")
        if (row.tenant_id, row.salt) in self._generations:
            raise ValueError(f"tenant {row.tenant_id} already has a generation {row.salt}")
        self._generations[(row.tenant_id, row.salt)] = row
        self._check_one_live(row.tenant_id)

    def _check_one_live(self, tenant_id: str) -> None:
        live = [g for (t, _), g in self._generations.items() if t == tenant_id and g.status == "live"]
        if len(live) > 1:
            raise ValueError(f"tenant {tenant_id} would have two live generations")

    def state_of(self, tenant_id: str) -> str | None:
        """The tenant's state now, or None: synchronous, for the identity twin that shares this store."""
        with self._mutex:
            row = self._tenants.get(str(tenant_id))
            return None if row is None else row.state

    # --- reads ---------------------------------------------------------------------------------
    async def tenant(self, tenant_id: str) -> TenantRecord | None:
        with self._mutex:
            return _detached(self._tenants.get(str(tenant_id)))

    async def tenants(self) -> list[TenantRecord]:
        with self._mutex:
            return [_detached(t) for t in sorted(self._tenants.values(), key=lambda t: (t.created_at, t.id))]

    async def generations(self, tenant_id: str) -> list[Generation]:
        with self._mutex:
            return [_detached(g) for (t, _), g in sorted(self._generations.items()) if t == str(tenant_id)]

    async def forge_wiring(self, tenant_id: str) -> ForgeWiring | None:
        with self._mutex:
            return _detached(self._wiring.get(str(tenant_id)))

    async def publish_status(self, tenant_id: str) -> dict[str, str] | None:
        with self._mutex:
            row = self._publish.get(str(tenant_id))
            return None if row is None else row.as_dict()

    # --- requests (the API) ----------------------------------------------------------------------
    async def request_create(self, *, now: _dt.datetime) -> TenantRecord:
        row = TenantRecord(id=str(uuid.uuid4()), created_at=now, state="creating", pending_action="create",
                           step="names", step_actor=SERVICE)
        with self._mutex:
            self._tenants[row.id] = row
            return _detached(row)

    def _request(self, tenant_id: str, allowed: bool, refusal: str, **changes: Any) -> TenantRecord:
        """Apply `changes` when `allowed` (read under the mutex with the row) else `Conflict`."""
        row = self._tenants[str(tenant_id)]
        if not allowed:
            raise Conflict(refusal)
        for name, value in changes.items():
            setattr(row, name, value)
        return _detached(row)

    def _row(self, tenant_id: str) -> TenantRecord:
        row = self._tenants.get(str(tenant_id))
        if row is None:
            raise NotFound(f"no tenant {tenant_id}")
        return row

    async def request_resume(self, tenant_id: str) -> TenantRecord:
        with self._mutex:
            row = self._row(tenant_id)
            return self._request(
                tenant_id, row.failure is not None and row.step != ADOPT_STEP,
                "nothing to resume" if row.failure is None else "only adoption clears this failure",
                failure=None)

    async def request_offboard(self, tenant_id: str, *, now: _dt.datetime) -> TenantRecord:
        with self._mutex:
            row = self._row(tenant_id)
            return self._request(
                tenant_id, row.state in ("creating", "active"), f"a tenant {row.state} cannot be offboarded",
                state="offboarding", pending_action="offboard", step="offboard", step_actor=SERVICE, failure=None)

    async def request_rotate(self, tenant_id: str) -> TenantRecord:
        with self._mutex:
            row = self._row(tenant_id)
            return self._request(
                tenant_id, row.state == "active" and row.pending_action is None,
                "only an active tenant with nothing pending can rotate",
                pending_action="rotate", step="names", step_actor=SERVICE)

    # --- host processes --------------------------------------------------------------------------
    async def record_publish_status(self, tenant_id: str, line: str, *, by: str) -> None:
        published, refused, kind = publish_outcome(line)
        with self._mutex:
            if str(tenant_id) not in self._tenants:
                raise ValueError(f"no tenant {tenant_id}")
            self._publish[str(tenant_id)] = PublishStatus(
                tenant_id=str(tenant_id), recorded_by=by, published=published, refused=refused, kind=kind)

    # --- workers ---------------------------------------------------------------------------------
    async def claimable(self, actor: str, *, now: _dt.datetime) -> list[str]:
        with self._mutex:
            return [t.id for t in sorted(self._tenants.values(), key=lambda t: (t.created_at, t.id))
                    if claimable_now(t, actor, now)]

    @contextlib.asynccontextmanager
    async def lock(self, tenant_id: str) -> AsyncIterator[_Held | None]:
        tenant_id = str(tenant_id)
        with self._mutex:
            taken = tenant_id in self._tenants and tenant_id not in self._locked
            if taken:
                self._locked.add(tenant_id)
                record = _detached(self._tenants[tenant_id])
        if not taken:
            yield None
            return
        held = _Held(self, record)
        try:
            yield held
        finally:
            held.spent = True
            with self._mutex:
                self._locked.discard(tenant_id)


def _move_statuses(generations: dict[tuple[str, str], Generation], tenant_id: str, go_live: str | None,
                   destroy: Collection[str] | Literal["all"]) -> None:
    """`go_live` live and the one live before it `retiring`; `destroy`'s (or every) generation `destroyed`."""
    if go_live is not None:
        for g in generations.values():
            if g.status == "live" and g.salt != go_live:
                g.status = "retiring"
        generations[(tenant_id, go_live)].status = "live"
    for g in generations.values():
        if (destroy == "all" and g.status != "destroyed") or (destroy != "all" and g.salt in destroy):
            g.status = "destroyed"


class _Held:
    """A tenant under its in-memory lock: the fence of `HeldTenant`, checked under the mutex."""

    def __init__(self, store: InMemoryTenantRepository, record: TenantRecord) -> None:
        self._store = store
        self.tenant_id = record.id
        self.record = record
        self.spent = False

    async def generations(self) -> list[Generation]:
        self._live()
        return await self._store.generations(self.tenant_id)

    async def forge_wiring(self) -> ForgeWiring | None:
        self._live()
        return await self._store.forge_wiring(self.tenant_id)

    def _live(self) -> None:
        if self.spent:
            raise FenceMissed(f"the hold on tenant {self.tenant_id} is spent")

    def _fenced(self, expect_failure: str | None) -> TenantRecord:
        """The stored row, if the fence holds; else the hold is spent and `FenceMissed`."""
        self._live()
        row = self._store._tenants.get(self.tenant_id)
        seen = self.record
        if row is None or (row.pending_action, row.step, row.step_actor, row.failure) != (
                seen.pending_action, seen.step, seen.step_actor, expect_failure):
            self.spent = True
            raise FenceMissed(f"tenant {self.tenant_id}'s job moved since the step started")
        return row

    async def commit(  # noqa: PLR0913 — `HeldTenant.commit`
        self, *, step: str | None, actor: str | None, state: str = KEEP, pending_action: str | None = KEEP,
        repo_url: str | None = KEEP, offboarded_at: _dt.datetime | None = KEEP,
        repo_delete_after: _dt.datetime | None = KEEP,
        add_generation: Generation | None = None,
        update_generations: Mapping[str, Mapping[str, Any]] | None = None,
        go_live: str | None = None, destroy: Collection[str] | Literal["all"] = (),
        wiring: ForgeWiring | None = None, drop_wiring: bool = False, drop_publish_status: bool = False,
        expect_failure: str | None = None,
    ) -> TenantRecord:
        store = self._store
        columns: dict[str, Any] = {k: v for k, v in dict(state=state, pending_action=pending_action, repo_url=repo_url,
                                         offboarded_at=offboarded_at, repo_delete_after=repo_delete_after).items()
                   if v is not KEEP}
        with store._mutex:
            row = self._fenced(expect_failure)
            after = dataclasses.replace(row, step=step, step_actor=actor, failure=None, **columns)
            _check_pair(after.state, after.pending_action)
            generations = self._changed_generations(add_generation, update_generations, go_live, destroy)
            store._tenants[self.tenant_id] = after
            store._generations.update(generations)
            if wiring is not None:
                store._wiring.setdefault(self.tenant_id, dataclasses.replace(wiring, tenant_id=self.tenant_id))
            if drop_wiring:
                store._wiring.pop(self.tenant_id, None)
            if drop_publish_status:
                store._publish.pop(self.tenant_id, None)
            self.record = _detached(after)
            return _detached(after)

    def _changed_generations(
        self, add: Generation | None, updates: Mapping[str, Mapping[str, Any]] | None, go_live: str | None,
        destroy: Collection[str] | Literal["all"],
    ) -> dict[tuple[str, str], Generation]:
        """The tenant's generations as the commit leaves them (copies; stored by the caller)."""
        generations = {k: _detached(g) for k, g in self._store._generations.items() if k[0] == self.tenant_id}
        if add is not None:
            new = dataclasses.replace(add, tenant_id=self.tenant_id)
            if (self.tenant_id, new.salt) in generations:
                raise ValueError(f"tenant {self.tenant_id} already has a generation {new.salt}")
            generations[(self.tenant_id, new.salt)] = new
        for salt, fields in (updates or {}).items():
            for name, value in fields.items():
                setattr(generations[(self.tenant_id, salt)], name, value)
        _move_statuses(generations, self.tenant_id, go_live, destroy)
        if sum(g.status == "live" for g in generations.values()) > 1:
            raise ValueError(f"tenant {self.tenant_id} would have two live generations")
        return generations

    async def fail(self, failure: str, *, step: str, actor: str) -> TenantRecord:
        store = self._store
        with store._mutex:
            row = self._fenced(None)
            after = dataclasses.replace(row, step=step, step_actor=actor, failure=failure)
            store._tenants[self.tenant_id] = after
            self.record = _detached(after)
            return _detached(after)
