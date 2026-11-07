"""#1377's migration (`0008_cost_lower_limit`, on `0007_alert_mapping`): the investigation row's `cost_is_lower_limit`."""
from __future__ import annotations

import pytest

from defender.tests.migrations.test_1343_migrations import TENANT, _inv, _plant
from defender.tests.support.shared._postgres1339 import execute


@pytest.mark.postgres
def test_s2_existing_rows_read_exact_after_the_migration_and_the_column_is_a_required_boolean(empty_database):
    """Rows from before the migration keep their cost and read `false`; the column is a NOT NULL boolean. (S2, Design "Data and API")"""
    from alembic import command

    from defender.migrations import _config, head, upgrade

    config = _config()
    config.attributes["dsn"] = empty_database
    command.upgrade(config, "0007_alert_mapping")
    execute(empty_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (TENANT,))
    _plant(empty_database, _inv("done"), "completed", "1", cost=2.5)
    upgrade(empty_database)

    assert head() == "0008_cost_lower_limit"
    assert execute(empty_database, "SELECT cost_usd, cost_is_lower_limit FROM jobs.investigations") == [(2.5, False)]
    assert execute(empty_database, "SELECT data_type, is_nullable FROM information_schema.columns WHERE table_schema = 'jobs' "
                                   "AND table_name = 'investigations' AND column_name = 'cost_is_lower_limit'") == [
        ("boolean", "NO")]
