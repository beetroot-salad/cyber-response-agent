# ruff: noqa: PT018
"""#1214 attack-3 hole 13 (O9, O11): the failure text the migration backfills is the exact text adoption looks for, so
a migrated row can be adopted (the clearing commit's fence matches it).
"""
from __future__ import annotations

import asyncio

import pytest

from defender.tests.migrations.test_1214_migrations import LAB, OTHER, _at_baseline
from defender.tests.support.shared._postgres1339 import empty_database  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import execute


@pytest.mark.postgres
def test_a_backfilled_row_carries_the_exact_text_adoption_expects_and_its_clearing_commit_lands(empty_database):  # noqa: F811
    """The migrated `failure` equals `tenancy.ADOPT_FAILURE`; clearing it with that fence activates the row (O9, O11)."""
    from defender.migrations import upgrade
    from defender.tenancy import ADOPT_FAILURE
    from defender.tenancy.postgres import PostgresTenantRepository

    _at_baseline(empty_database, tenants=(LAB, OTHER))
    upgrade(empty_database)
    failures = {row[0] for row in execute(empty_database, "SELECT failure FROM tenancy.tenants")}
    assert failures == {ADOPT_FAILURE}

    async def clear() -> str:
        repository = PostgresTenantRepository(empty_database)
        try:
            async with repository.lock(LAB) as held:
                assert held is not None and held.record.failure == ADOPT_FAILURE
                done = await held.commit(step=None, actor=None, state="active", pending_action=None,
                                         expect_failure=ADOPT_FAILURE)
                return done.state
        finally:
            await repository.close()

    assert asyncio.run(clear()) == "active"
