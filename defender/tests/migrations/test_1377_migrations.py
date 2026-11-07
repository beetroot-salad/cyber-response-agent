"""#1377's migration (`0008_cost_lower_limit`, on `0007_alert_mapping`): the investigation row's `cost_is_lower_limit`."""
from __future__ import annotations

import asyncio

import pytest

from defender.tests.migrations.test_1343_migrations import TENANT, _inv, _plant
from defender.tests.support.jobs._jobs1342 import job_store
from defender.tests.support.shared._postgres1339 import execute


@pytest.mark.postgres
def test_s2_b3_rows_whose_holder_wrote_its_figure_read_exact_and_an_ended_row_without_one_reads_at_least(empty_database):
    """After the migration a row ended before 0006 (accounting back-filled), an unknown cost and a never-started row read exact; a row started, ended with a cost and no accounting reads "at least"; the column is a NOT NULL boolean with no server default. (S2, B3)"""
    from alembic import command

    from defender.migrations import _config, head, upgrade

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
    upgrade(empty_database)

    assert head() == "0008_cost_lower_limit"
    assert sorted(execute(empty_database, "SELECT cost_usd, cost_is_lower_limit FROM jobs.investigations"),
                  key=lambda r: (r[0] is None, r[0])) == [(0, False), (2.5, False), (3.5, False), (None, False)], (
        "the migration stores no mark: B2 derives it")

    async def read_marks() -> dict[str, bool]:
        async with job_store(empty_database) as store:
            return {name: (await store.get_investigation(TENANT, _inv(name))).cost_is_lower_limit
                    for name in ("done", "unknown", "lost", "cancelled")}

    assert asyncio.run(read_marks()) == {"done": False, "unknown": False, "lost": True, "cancelled": False}
    assert execute(empty_database, "SELECT data_type, is_nullable, column_default FROM information_schema.columns "
                                   "WHERE table_schema = 'jobs' AND table_name = 'investigations' "
                                   "AND column_name = 'cost_is_lower_limit'") == [("boolean", "NO", None)]
    assert execute(empty_database, "SELECT id, accounting_written_at IS NOT NULL FROM jobs.investigations "
                                   "WHERE cost_usd = 3.5") == [(_inv("lost"), False)], "premise: the lost row has no accounting"
    assert execute(empty_database, "SELECT count(*) FROM jobs.investigations WHERE accounting_written_at IS NOT NULL") == [(2,)], (
        "premise: the two rows ended before 0006 were back-filled")
