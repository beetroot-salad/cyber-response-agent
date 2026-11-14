"""Seeders for the in-memory tenant twin (#1496): a tenant row as written, not requested, and the offboard transition.
They were the twin's own methods; no production code seeds, so they live with the tests. In-memory only: a case on the
database plants rows by SQL (`_active1214.insert_active_tenant`) and offboards through tenancy's own `offboard`."""
from __future__ import annotations

import datetime as _dt
from typing import cast

from defender.records.formats import TenantId
from defender.tenancy import InMemoryTenantRepository
from defender.tenancy.memory import _SEED_JOB, _check_pair, _detached
from defender.tenancy.models import _OFFBOARD_VALUES, ForgeWiring, TenantRecord


def _twin(tenants: object) -> InMemoryTenantRepository:
    if not isinstance(tenants, InMemoryTenantRepository):
        raise TypeError(f"an in-memory twin seeder was handed {type(tenants).__name__}")
    return tenants


async def seed_tenant(  # noqa: PLR0913 — every tenant column a case plants
    tenants: InMemoryTenantRepository, tenant_id: str, *, created_at: _dt.datetime, state: str = "active",
    repo: str | None = None, origin: str | None = None, pending_action: str | None = None, step: str | None = None,
    step_actor: str | None = None, failure: str | None = None,
) -> TenantRecord:
    """A tenant row (and its forge wiring when `repo` is given) as written, not requested. A state that requires a
    pending action gets its first step when none is named. The id is stored as given, unchecked, so a case can plant
    one the entry points must refuse."""
    twin = _twin(tenants)
    tid = cast(TenantId, tenant_id)
    if pending_action is None and state in _SEED_JOB:
        pending_action, step, step_actor = _SEED_JOB[state]
    _check_pair(state, pending_action)
    if (repo is None) != (origin is None):
        raise ValueError("forge wiring needs both the repo and its origin")
    row = TenantRecord(id=tid, created_at=created_at, state=state, pending_action=pending_action,
                       step=step, step_actor=step_actor, failure=failure)
    with twin._mutex:  # noqa: SLF001 — test support: the twin's own rows
        if tid in twin._tenants:  # noqa: SLF001
            raise ValueError(f"tenant {tenant_id} is already stored")
        twin._tenants[tid] = row  # noqa: SLF001
        if repo is not None and origin is not None:
            twin._wiring[tid] = ForgeWiring(tenant_id=tid, repo=repo, origin=origin)  # noqa: SLF001
        return _detached(row)


async def offboard_twin(tenants: InMemoryTenantRepository, tenant_id: str) -> TenantRecord:
    """What tenancy's `offboard` leaves, on the twin: from `creating` or `active`, `offboarding` with the teardown
    pending at its first step and any failure cleared; `NotFound` for an absent tenant, `Conflict` otherwise."""
    twin = _twin(tenants)
    tid = cast(TenantId, tenant_id)
    with twin._mutex:  # noqa: SLF001 — test support: the twin's own rows and request
        row = twin._row(tid)  # noqa: SLF001 — `NotFound` for an absent tenant
        return twin._request(  # noqa: SLF001
            tid, row.state in ("creating", "active"), "only a creating or active tenant can be offboarded",
            **_OFFBOARD_VALUES)
