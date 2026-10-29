# ruff: noqa: F811, PT018
"""#1214 attack-1 on the tenant repository's twins: the tenant lock excludes a second holder (H-16), the fence includes the
actor and the failure (H-16), a commit never replaces a recorded wiring (H-17) (P6, RC-1, RC-9)."""
from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from defender.tests.support.shared._postgres1339 import execute
from defender.tests.tenancy.lifecycle_1214.test_1214_repository_contract import (  # noqa: F401 — fixtures and rows
    CREATING,
    ORIGIN,
    T1,
    T2,
    Store,
    store,
)

pytestmark = pytest.mark.anyio


async def test_a_second_lock_on_a_held_tenant_yields_nothing_on_both_twins(store: Store):
    """While T's lock is open another `lock(T)` yields None, another tenant's is free, and T's is free again after (P6)."""
    await store.seed(T1, CREATING)
    await store.seed(T2, CREATING)
    async with store.repo.lock(T1) as first:
        assert first is not None
        async with store.repo.lock(T1) as second:
            assert second is None
        async with store.repo.lock(T2) as other:
            assert other is not None
    async with store.repo.lock(T1) as again:
        assert again is not None


async def _change(store: Store, column: str, value: Any) -> None:
    """Change one column of T1 behind the hold's back (neither twin offers a request that changes only this)."""
    if store.dsn is not None:
        execute(store.dsn, f"UPDATE tenancy.tenants SET {column} = %s WHERE id = %s", (value, T1))
    else:
        store.twin._tenants[T1] = dataclasses.replace(store.twin._tenants[T1], **{column: value})


@pytest.mark.parametrize("write", ["commit", "fail"])
@pytest.mark.parametrize("changed", ["step_actor", "failure", "step", "nothing"])
async def test_a_write_lands_only_if_step_actor_and_failure_are_as_read_on_both_twins(store: Store, changed, write):
    """The row changes one column under the hold: the hold's commit or failure misses and the row is as the change left it;
    with nothing changed the same write lands (RC-1)."""
    from defender.tenancy import FenceMissed

    await store.seed(T1, CREATING)
    values = {"step_actor": "host", "failure": "put there by the case", "step": "repo"}
    async with store.repo.lock(T1) as held:
        assert held is not None
        if changed != "nothing":
            await _change(store, changed, values[changed])
        before = await store.repo.tenant(T1)
        attempt = (held.commit(step="repo", actor="service") if write == "commit"
                   else held.fail("boom", step="provider", actor="service"))
        if changed == "nothing":
            await attempt
            assert await store.repo.tenant(T1) != before, "control: an unchanged row takes the write"
        else:
            with pytest.raises(FenceMissed):
                await attempt
            assert await store.repo.tenant(T1) == before, f"the write ignored a changed {changed}"


async def test_a_commit_for_a_tenant_that_has_a_wiring_leaves_the_recorded_one_on_both_twins(store: Store):
    """`names` keeps an already recorded repo and origin (the lab's own); a tenant without one gets the committed one (RC-9)."""
    from defender.tenancy import ForgeWiring

    await store.seed(T1, CREATING, repo="tenants/playground", origin=ORIGIN)
    await store.seed(T2, CREATING)
    for tenant in (T1, T2):
        async with store.repo.lock(tenant) as held:
            assert held is not None
            await held.commit(step="repo", actor="service",
                              wiring=ForgeWiring(tenant_id=tenant, repo=f"tenants/{tenant}", origin="http://forge.test/new.git"))
    kept = await store.repo.forge_wiring(T1)
    assert (kept.repo, kept.origin) == ("tenants/playground", ORIGIN)
    fresh = await store.repo.forge_wiring(T2)
    assert (fresh.repo, fresh.origin) == (f"tenants/{T2}", "http://forge.test/new.git")
