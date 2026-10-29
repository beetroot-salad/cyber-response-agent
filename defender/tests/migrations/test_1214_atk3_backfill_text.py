# ruff: noqa: PT018
"""#1214 attack-3 hole 13 (O9, O11): the failure text the migration backfills is the exact text adoption looks for, so
a migrated row can be adopted (the clearing commit fences on it). The text is the design's (r8, migration backfill).
"""
from __future__ import annotations

import pytest

from defender.tests.migrations.test_1214_migrations import LAB, OTHER, _at_baseline
from defender.tests.support.shared._postgres1339 import empty_database  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import execute

ADOPT_FAILURE = "registered before #1214: adopt it"


@pytest.mark.postgres
def test_a_backfilled_row_carries_the_exact_text_adoption_expects(empty_database):  # noqa: F811
    """The migrated `failure` of every backfilled row is the design's backfill text, the one adoption fences on (O9, O11)."""
    from defender.migrations import upgrade

    _at_baseline(empty_database, tenants=(LAB, OTHER))
    upgrade(empty_database)
    failures = {row[0] for row in execute(empty_database, "SELECT failure FROM tenancy.tenants")}
    assert failures == {ADOPT_FAILURE}

