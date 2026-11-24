"""#1377's migration (`0010_cost_lower_limit`, on #1307's `0009_programs`; renumbered after merging #1344 and #1307): the investigation row's `cost_is_lower_limit`."""
from __future__ import annotations

import asyncio

import pytest

from defender.tests.migrations.test_1343_migrations import TENANT, _inv, _plant
from defender.tests.support.jobs._jobs1342 import job_store
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.migrations._marked1470 import upgrade_marking_tenants


@pytest.mark.postgres
def test_s2_b3_every_migrated_row_reads_the_stored_mark_unmarked_and_the_column_is_not_null_with_no_default(empty_database):
    """After the migration every row (one ended before 0006 with accounting back-filled, an unknown cost, a never-started row, and a row started and ended with a cost and no accounting) reads the stored mark, false: the column is a NOT NULL boolean with no server default and the store derives nothing (S2, B3; #1546 D15 replaces B2's derivation with the stored mark)."""
    from alembic import command

    from defender.migrations import _config

    config = _config()
    config.attributes["dsn"] = empty_database
    command.upgrade(config, "0005_uuid_ids")
    execute(empty_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (TENANT,))
    _plant(empty_database, _inv("done"), "completed", "1", cost=2.5)  # 0006 back-fills its accounting
    _plant(empty_database, _inv("unknown"), "failed", "2", cost=None)  # an unknown cost stays unknown, and unmarked
    command.upgrade(config, "0007_alert_mapping")
    _plant(empty_database, _inv("lost"), "failed", "3", cost=3.5)  # started, ended, its holder never wrote a figure
    _plant(empty_database, _inv("cancelled"), "aborted", "4", cost=0)
    execute(empty_database, "UPDATE jobs.investigations SET started_at = NULL WHERE id = %s", (_inv("cancelled"),))
    upgrade_marking_tenants(empty_database)  # #1470 O12: the tenant has its mark, so the drop does not stop

    from defender.migrations import _scripts

    assert _scripts().get_revision("0010_cost_lower_limit").down_revision == "0009_programs"
    assert sorted(execute(empty_database, "SELECT cost_usd, cost_is_lower_limit FROM jobs.investigations"),
                  key=lambda r: (r[0] is None, r[0])) == [(0, False), (2.5, False), (3.5, False), (None, False)], (
        "the migration stores no mark")

    async def read_marks() -> dict[str, bool]:
        async with job_store(empty_database) as store:
            return {name: (await store.get_investigation(TENANT, _inv(name))).cost_is_lower_limit
                    for name in ("done", "unknown", "lost", "cancelled")}

    # #1546 D15 (r9): `apply` stores the mark for every ended row and the store reads that column; the derivation from "started,
    # ended with a cost, no accounting" went with `write_accounting`. The migration stores no mark and no tenant survives it
    # (D16), so every migrated row reads what its column holds: unmarked.
    assert asyncio.run(read_marks()) == {"done": False, "unknown": False, "lost": False, "cancelled": False}
    assert execute(empty_database, "SELECT data_type, is_nullable, column_default FROM information_schema.columns "
                                   "WHERE table_schema = 'jobs' AND table_name = 'investigations' "
                                   "AND column_name = 'cost_is_lower_limit'") == [("boolean", "NO", None)]
    assert execute(empty_database, "SELECT id, accounting_written_at IS NOT NULL FROM jobs.investigations "
                                   "WHERE cost_usd = 3.5") == [(_inv("lost"), False)], "premise: the lost row has no accounting"
    assert execute(empty_database, "SELECT count(*) FROM jobs.investigations WHERE accounting_written_at IS NOT NULL") == [(2,)], (
        "premise: the two rows ended before 0006 were back-filled")
