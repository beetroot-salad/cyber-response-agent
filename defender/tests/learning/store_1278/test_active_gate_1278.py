"""#1278 repair 2, family 2: a tenant off active never gets a new learning row, even when the offboarding lands while a verb is mid-transaction.

One test over every verb that creates rows (`publish_findings`, `add_pitfall`, `enqueue_request`, `claim`, `claim_revert`,
the import): with the tenant already off active the verb refuses and adds nothing; with the verb held open on a table lock
after its decision, the offboarding update is fired from another session under a `lock_timeout`, and the tenant is never
off active with the verb's new row. (O6, Offboarding, D11a)
"""
from __future__ import annotations

import anyio
import psycopg
import pytest

from defender.tests.learning.store_1278.test_import_1278 import world  # noqa: F401 — the p4 tenant with a learning folder
from defender.tests.support.jobs._jobs1342 import move_tenant
from defender.tests.support.learning.core import _legacy1278 as legacy
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, ONE, finding, learning_store, store_mod
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


def _pitfall(pid: str) -> dict:
    return {"schema_version": 1, "pitfall_id": pid, "source_run": "r", "system": "elastic", "query_id": "elastic.esql",
            "goal": "g", "executed_query": "x", "stderr_digest": f"exit=1; {pid}", "error_class": "agent-fixable"}


async def _prep_nothing(w, store):
    return None


async def _prep_one_finding(w, store):
    await store.publish_findings(w.tid, "run-0", [finding("due")], kind="finding")


async def _prep_legacy_queue(w, store):
    legacy.queue(w.root, "finding", [finding("queued")])


#: verb -> (what to set up while the tenant is active, the table whose lock holds the verb open, the call).
VERBS = {
    "publish_findings": (_prep_nothing, "work_items",
                         lambda w, s: s.publish_findings(w.tid, "run-1", [finding("f-new")], kind="finding")),
    "add_pitfall": (_prep_nothing, "work_items", lambda w, s: s.add_pitfall(w.tid, _pitfall("p-new"))),
    "enqueue_request": (_prep_nothing, "work_items", lambda w, s: s.enqueue_request(w.tid, "run-1", "case-1", {"case": "c"})),
    "claim": (_prep_one_finding, "work_items", lambda w, s: s.claim(w.tid, AUTHOR_LANE, owner="host-a", thresholds=ONE)),
    "claim_revert": (_prep_nothing, "batches", lambda w, s: s.claim_revert(w.tid, owner="cli")),
    "import": (_prep_legacy_queue, "work_items",
               lambda w, s: store_mod().import_learning_state(s, w.tid, w.root, delivery=w.t.open_delivery())),
}

ARMS = ["already-offboarding", "already-offboarded", "offboarding-lands-mid-transaction"]


def _rows_of(dsn: str, tenant: str) -> dict[str, list[str]]:
    """Every row of `tenant` in every `learning` table that carries a tenant id, as JSON text."""
    tables = [t for (t,) in execute(dsn, "SELECT DISTINCT table_name FROM information_schema.columns "
                                         "WHERE table_schema = 'learning' AND column_name = 'tenant_id' ORDER BY 1")]
    assert tables, "premise: the learning schema has tables that carry a tenant id"
    return {t: sorted(r[0] for r in execute(dsn, f"SELECT row_to_json(x)::text FROM learning.{t} x WHERE tenant_id = %s",  # noqa: S608
                                            (tenant,))) for t in tables}


def _state(dsn: str, tenant: str) -> str:
    return execute(dsn, "SELECT state FROM tenancy.tenants WHERE id = %s", (tenant,))[0][0]


def _added(before: dict[str, list[str]], after: dict[str, list[str]]) -> dict[str, list[str]]:
    return {t: [r for r in rows if r not in before[t]] for t, rows in after.items() if [r for r in rows if r not in before[t]]}


def _waiting_on_a_lock(dsn: str) -> bool:
    return execute(dsn, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                        "AND wait_event_type = 'Lock'")[0][0] > 0


def _fire_offboarding(dsn: str, tenant: str) -> bool:
    """The lifecycle's update of the tenant to offboarding, from a session of its own that waits at most half a second
    for the row: True if it went through, False if the row was held against it."""
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("SET lock_timeout = '500ms'")
        try:
            conn.execute("UPDATE tenancy.tenants SET state = 'offboarding', pending_action = 'offboard', step = 'offboard', "
                         "step_actor = 'service' WHERE id = %s", (tenant,))
        except psycopg.errors.LockNotAvailable:
            return False
    return True


@pytest.mark.parametrize("arm", ARMS)
@pytest.mark.parametrize("verb", sorted(VERBS))
async def test_o6_a_tenant_off_active_never_gets_a_new_row_not_even_when_the_offboarding_lands_mid_verb(world, verb, arm):  # noqa: F811 — the imported fixture
    """Already off active the verb refuses and adds nothing; with the update fired inside its transaction, off active and a new row never go together. (O6, D11a)"""
    S = store_mod()
    prep, locked, call = VERBS[verb]
    async with learning_store(world.dsn) as store:
        await prep(world, store)
        before = _rows_of(world.dsn, world.tid)

        if arm != "offboarding-lands-mid-transaction":
            move_tenant(world.dsn, world.tid, state=arm.removeprefix("already-"))
            with pytest.raises(S.TenantInactive):
                await call(world, store)
            assert _added(before, _rows_of(world.dsn, world.tid)) == {}, f"`{verb}` added rows for a tenant off active"
            return

        outcome: dict[str, object] = {}

        async def run_the_verb():
            try:
                outcome["result"] = await call(world, store)
            except S.TenantInactive as refused:
                outcome["refused"] = refused

        holder = psycopg.connect(world.dsn)
        try:
            holder.execute(f"LOCK TABLE learning.{locked} IN SHARE ROW EXCLUSIVE MODE")  # noqa: S608 — a fixed table name
            async with anyio.create_task_group() as group:
                group.start_soon(run_the_verb)
                with anyio.fail_after(30):
                    while not await anyio.to_thread.run_sync(_waiting_on_a_lock, world.dsn):
                        assert not outcome, f"`{verb}` finished without waiting on the lock: {outcome}"
                        await anyio.sleep(0.05)
                landed = await anyio.to_thread.run_sync(_fire_offboarding, world.dsn, world.tid)
                holder.rollback()
        finally:
            holder.close()

        added = _added(before, _rows_of(world.dsn, world.tid))
        if landed:
            assert "refused" in outcome, f"`{verb}` was not refused for a tenant that went off active while it was open"
            assert not added, (
                f"`{verb}` added {sorted(added)} for a tenant that went to {_state(world.dsn, world.tid)} while it was in its transaction")
        else:
            assert "refused" not in outcome, f"control: the verb was refused for a tenant that stayed active: {outcome}"
            assert added, f"control: with the tenant held active `{verb}` made no row: {outcome}"
            assert _state(world.dsn, world.tid) == "active", "the update that was refused changed the tenant anyway"
