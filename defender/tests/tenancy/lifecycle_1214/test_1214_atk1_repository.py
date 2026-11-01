# ruff: noqa: F811, PT018
"""#1214 attack-1 on the tenant repository's twins: the tenant lock excludes a second holder (H-16), the fence includes the
actor and the failure (H-16), a commit never replaces a recorded wiring (H-17), a write the store refuses as data is the
step's recorded failure, not a lost lock (DC-14) (P6, RC-1, RC-9)."""
from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from defender.tests.support.shared._postgres1339 import execute
from defender.tests.tenancy.lifecycle_1214.test_1214_repository_contract import (  # noqa: F401 — fixtures and rows
    CREATING,
    NOW,
    ORIGIN,
    T1,
    T2,
    Store,
    pg_store,
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


# --- a write the store refuses as data ---------------------------------------------------------------

#: Commits the store refuses for what they say, not because the lock is lost.
REFUSED = {"state-and-action-pair": dict(state="offboarded", pending_action="create"),  # ck_tenants_state_allows_pending_action
           "nul": dict(repo_url="http://forge.test/a\x00b")}  # PostgreSQL text cannot hold a NUL


async def _two_passes(store: Store, refused: dict[str, Any]) -> tuple[list[int], int, Any]:
    """A service actor whose `provider` step commits `refused`, run for two passes on T1 (creating, at provider): the
    passes' step counts, how often the step ran, and T1 after."""
    from defender.lifecycle._job import SERVICE, Actor

    class _Refusing(Actor):
        actor = SERVICE
        runs = 0

        def steps(self) -> Any:
            return {"provider": self._provider}

        async def _provider(self, held: Any) -> None:
            self.runs += 1
            await held.commit(step="repo", actor=SERVICE, **refused)

    await store.seed(T1, CREATING)
    worker = _Refusing(store.repo, clock=lambda: NOW)
    ran = [await worker.work(), await worker.work()]
    return ran, worker.runs, await store.repo.tenant(T1)


def _recorded_once(ran: list[int], runs: int, after: Any) -> None:
    assert (ran, runs) == ([1, 0], 1), f"the refused step was not recorded as failed and ran again: {ran}, {runs} runs"
    assert (after.state, after.step, after.step_actor) == ("creating", "provider", "service"), after
    assert after.failure and after.failure.startswith("provider: ") and "\x00" not in after.failure, after.failure


async def test_a_commit_the_store_refuses_is_the_steps_recorded_failure_and_is_not_rerun_on_both_twins(store: Store):
    """A step's commit breaks the state/pending-action pair: the store refuses it, the lock is still held, so the job
    records the failure at the step (restart there) and the next pass leaves the tenant alone (DC-14, RC-1)."""
    _recorded_once(*await _two_passes(store, REFUSED["state-and-action-pair"]))


@pytest.mark.postgres
async def test_a_commit_with_a_value_postgresql_cannot_store_is_the_steps_recorded_failure(pg_store: Store):
    """A NUL in a committed value is a data error, not a lost lock: the failure is recorded once, the step not rerun.
    (The in-memory twin stores a NUL, so this case is PostgreSQL's.)"""
    _recorded_once(*await _two_passes(pg_store, REFUSED["nul"]))


@pytest.mark.postgres
async def test_a_write_that_times_out_waiting_for_the_row_spends_the_hold_and_records_nothing(pg_store: Store):
    """A transient refusal is not the step's failure: the tenant row is locked by another session past the lock
    connection's `lock_timeout`, so the commit raises `FenceMissed` and leaves the row for the next pass (RC-1)."""
    import psycopg
    from sqlalchemy import text

    from defender.tenancy import FenceMissed

    await pg_store.seed(T1, CREATING)
    with psycopg.connect(pg_store.dsn) as blocker:
        blocker.execute("SELECT 1 FROM tenancy.tenants WHERE id = %s FOR UPDATE", (T1,))
        async with pg_store.repo.lock(T1) as held:
            assert held is not None
            await held._conn.execute(text("SET lock_timeout = '100ms'"))  # the hold's own session, as H-3 does
            await held._conn.commit()
            with pytest.raises(FenceMissed):
                await held.commit(step="repo", actor="service")
        blocker.rollback()
    after = await pg_store.repo.tenant(T1)
    assert (after.step, after.failure) == ("provider", None), after
