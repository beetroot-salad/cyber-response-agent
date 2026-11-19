"""#1487 (design r5, Data model): the finding insert moves down into `jobs`, and the operator lane's
`publish_findings` raises `ItemRefused` (with the refusal's message) whenever the shared insert reports `refused` for
the findings' content (amendment r5.1 item 7); an outage still propagates, and so does an error that neither the
content nor an outage explains, as `FindingsNotStored` (Amendment r5.3). Real database."""
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


def _rows():
    return [finding(f"run/w/0/{n}", run_id="run") for n in range(2)]


@pytest.mark.parametrize("sqlstate", F.REFUSED_SQLSTATES)
def test_an_error_the_content_causes_at_the_insert_raises_item_refused_and_stores_none(dsn, sqlstate):
    """The worker's refusal set (data 22, integrity 23, limits 54), at the second row: `ItemRefused`
    with the refusal's message, and the first row of the call is not stored either. (r5.1 item 7; the same errors as
    the worker's end write, `_findings1487.REFUSED_SQLSTATES`)"""
    from defender.learning_store import ItemRefused

    F.trigger_fault(dsn, "learning.work_items", sqlstate, when="NEW.item_key LIKE '%/1'")
    with pytest.raises(ItemRefused) as raised:
        call(dsn, "publish_findings", T1, "run", _rows(), kind="finding")
    assert str(raised.value), "the refusal carries its message"
    assert F.all_items(dsn) == []


@pytest.mark.parametrize("sqlstate", F.UNSTORED_SQLSTATES)
def test_r53_a_database_error_neither_content_nor_outage_raises_findings_not_stored_and_stores_none(dsn, sqlstate):
    """A permission error at the second row: `FindingsNotStored`, not `ItemRefused`, nothing stored, and the same call
    then succeeds. (Amendment r5.3)"""
    from defender.jobs import FindingsNotStored

    F.trigger_fault(dsn, "learning.work_items", sqlstate, when="NEW.item_key LIKE '%/1'", once=True)
    with pytest.raises(FindingsNotStored):
        call(dsn, "publish_findings", T1, "run", _rows(), kind="finding")
    assert F.all_items(dsn) == []
    assert call(dsn, "publish_findings", T1, "run", _rows(), kind="finding") == (2, 0)


@pytest.mark.parametrize("exc", F.UNSTORED_EXCEPTIONS, ids=lambda e: type(e).__name__)
def test_r53_a_non_database_exception_in_the_insert_raises_findings_not_stored_and_stores_none(dsn, exc):
    """The worker's non-database exceptions (`_findings1487.UNSTORED_EXCEPTIONS`) at the insert statement:
    `FindingsNotStored`, raised from the fault, nothing stored. (Amendment r5.3)"""
    from defender.jobs import FindingsNotStored

    with F.statement_fault(exc) as hit, pytest.raises(FindingsNotStored) as raised:
        call(dsn, "publish_findings", T1, "run", _rows(), kind="finding")
    assert hit, "premise: the insert statement was reached"
    assert isinstance(raised.value.__cause__, type(exc)), "raised from the fault"
    assert F.all_items(dsn) == []


def test_a_nul_in_a_row_still_raises_item_refused_before_anything_is_stored(dsn):
    """Today's screen: a NUL anywhere in a row is `ItemRefused` and files nothing."""
    from defender.learning_store import ItemRefused

    row = dict(finding("run/w/0/0", run_id="run"), finding="a\x00b")
    with pytest.raises(ItemRefused):
        call(dsn, "publish_findings", T1, "run", [row], kind="finding")
    assert F.all_items(dsn) == []


@pytest.mark.parametrize("sqlstate", F.OUTAGE_SQLSTATES, ids=F.OUTAGE_IDS)
def test_an_outage_class_error_is_not_read_as_a_refusal(dsn, sqlstate):
    """An outage-class error (the worker's retry set) at the insert surfaces as itself; it is not `ItemRefused`, nothing
    is stored by it, and the same call then succeeds. (r5.1 item 7: "an outage still propagates")"""
    from defender.learning_store import ItemRefused

    F.trigger_fault(dsn, "learning.work_items", sqlstate, once=True)
    rows = [finding("run/w/0/0", run_id="run")]
    with pytest.raises(Exception) as raised:  # noqa: PT011 — the driver's own error type is not the contract
        call(dsn, "publish_findings", T1, "run", rows, kind="finding")
    assert not isinstance(raised.value, ItemRefused)
    assert F.all_items(dsn) == []
    assert tuple(call(dsn, "publish_findings", T1, "run", rows, kind="finding")) == (1, 0)


@pytest.mark.parametrize("make", F.OUTAGE_FAULTS, ids=F.OUTAGE_FAULT_IDS)
def test_an_outage_with_no_sqlstate_is_not_read_as_a_refusal(dsn, make):
    """A lost or closed connection, an interface error, a pool timeout or an invalidated connection, none carrying a
    SQLSTATE, at the insert: it propagates, not `ItemRefused`, nothing stored, and the same call then succeeds. (r5.1
    item 7; P4: `is_outage` names these, whatever their SQLSTATE; `_findings1487.OUTAGE_FAULTS`, the worker's retry set)"""
    from defender.learning_store import ItemRefused

    rows = [finding("run/w/0/0", run_id="run")]
    with F.statement_fault(make(), once=True) as hit, pytest.raises(Exception) as raised:  # noqa: PT011 — not the contract
        call(dsn, "publish_findings", T1, "run", rows, kind="finding")
    assert hit, "premise: the insert met the fault"
    assert not isinstance(raised.value, ItemRefused), raised.value
    assert F.all_items(dsn) == []
    assert tuple(call(dsn, "publish_findings", T1, "run", rows, kind="finding")) == (1, 0)
