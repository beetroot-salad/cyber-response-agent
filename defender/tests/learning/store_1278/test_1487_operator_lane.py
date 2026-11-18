"""#1487 (design r5, Data model): the finding insert moves down into `jobs`, and the operator lane's
`publish_findings` keeps today's behaviour: a refused row raises `ItemRefused`, an outage-class database error does not
read as a refusal. Real database."""
from __future__ import annotations

import pytest

from defender.tests.support.jobs import _findings1487 as F
from defender.tests.support.jobs._jobs1342 import T1, register_tenant
from defender.tests.support.learning.core._store1278 import call, finding
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

pytestmark = pytest.mark.postgres


@pytest.fixture
def dsn(migrated_database):  # noqa: F811
    register_tenant(migrated_database, T1)
    return migrated_database


def test_a_row_the_database_refuses_as_data_raises_item_refused_and_stores_none_of_the_call(dsn):
    """A class-22 error at the second row: `ItemRefused`, and the first row of the call is not stored either."""
    from defender.learning_store import ItemRefused

    F.trigger_fault(dsn, "learning.work_items", "22001", when="NEW.item_key LIKE '%/1'")
    rows = [finding(f"run/w/0/{n}", run_id="run") for n in range(2)]
    with pytest.raises(ItemRefused):
        call(dsn, "publish_findings", T1, "run", rows, kind="finding")
    assert F.all_items(dsn) == []


def test_a_nul_in_a_row_still_raises_item_refused_before_anything_is_stored(dsn):
    """Today's screen: a NUL anywhere in a row is `ItemRefused` and files nothing."""
    from defender.learning_store import ItemRefused

    row = dict(finding("run/w/0/0", run_id="run"), finding="a\x00b")
    with pytest.raises(ItemRefused):
        call(dsn, "publish_findings", T1, "run", [row], kind="finding")
    assert F.all_items(dsn) == []


def test_an_outage_class_error_is_not_read_as_a_refusal(dsn):
    """A deadlock at the insert surfaces as itself; it is not `ItemRefused`, and the same call then succeeds."""
    from defender.learning_store import ItemRefused

    F.trigger_fault(dsn, "learning.work_items", "40P01", once=True)
    rows = [finding("run/w/0/0", run_id="run")]
    with pytest.raises(Exception) as raised:  # noqa: PT011 — the driver's own error type is not the contract
        call(dsn, "publish_findings", T1, "run", rows, kind="finding")
    assert not isinstance(raised.value, ItemRefused)
    assert tuple(call(dsn, "publish_findings", T1, "run", rows, kind="finding")) == (1, 0)
