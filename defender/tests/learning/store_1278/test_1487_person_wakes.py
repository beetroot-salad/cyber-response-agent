"""#1487 Amendment r5.3: a batch waiting for a person keeps no check clock running (`learning_store.tick.work_waiting`),
so a person's word that gives a tick something to do wakes the tenant itself: an abandon request, a batch's release and
an item's release each make the tenant's check clock not idle in the transaction that records them. A clock a post-step
holds is marked, since that post-step's answer may predate the word (#1487 O7). Real PostgreSQL, the store's own verbs."""
from __future__ import annotations

import pytest

from defender.jobs.errors import Conflict
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._release1537 import CREDENTIAL, park, set_held
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, call, finding
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = pytest.mark.postgres

TENANT = fixture_uuid("tenant:1487-person-wakes")
ONE = {"finding": 1, "questioner_finding": 1, "pitfall": 1, "curation_request": 1}


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, TENANT)
    return migrated_database


def _clock(dsn: str, *, held: bool = False) -> None:
    """The tenant's clock idle (its last post-step found nothing waiting), held by a post-step when `held`."""
    execute(dsn, "INSERT INTO jobs.learning_checks (tenant_id, checked_at, idle, armed_while_held, checking_until, holder) "
                 "VALUES (%s, now(), true, false, " + ("now() + interval '1 hour', 'post-step-1')" if held else "NULL, NULL)"),
            (TENANT,))


def _state(dsn: str) -> tuple[bool, bool]:
    """`(idle, armed_while_held)` of the tenant's clock."""
    [(idle, marked)] = execute(dsn, "SELECT idle, armed_while_held FROM jobs.learning_checks WHERE tenant_id = %s", (TENANT,))
    return bool(idle), bool(marked)


def _parked(dsn: str) -> str:
    """A batch of the tenant parked for a person, for the one cause a person may release."""
    call(dsn, "publish_findings", TENANT, "run-1", [finding("f1")], kind="finding")
    held = call(dsn, "claim", TENANT, AUTHOR_LANE, owner="o", thresholds=ONE)
    park(dsn, held.batch_id, cause=CREDENTIAL)
    return str(held.batch_id)


def test_r53_an_abandon_request_wakes_an_idle_tenant(dsn):
    batch = _parked(dsn)
    _clock(dsn)

    call(dsn, "request_abandon", TENANT, batch, actor="u-1")

    assert _state(dsn) == (False, False)


def test_r53_a_refused_request_wakes_nothing(dsn):
    """The wake commits with the request: a second request is refused, and the clock it found idle stays idle."""
    batch = _parked(dsn)
    call(dsn, "request_abandon", TENANT, batch, actor="u-1")
    execute(dsn, "UPDATE jobs.learning_checks SET idle = true WHERE tenant_id = %s", (TENANT,))

    with pytest.raises(Conflict):
        call(dsn, "request_abandon", TENANT, batch, actor="u-2")

    assert _state(dsn) == (True, False)


def test_r53_a_request_starts_a_clock_the_tenant_never_had(dsn):
    batch = _parked(dsn)

    call(dsn, "request_abandon", TENANT, batch, actor="u-1")

    assert _state(dsn) == (False, False)


def test_r53_a_request_while_a_post_step_holds_the_clock_marks_it(dsn):
    """The holder may already have answered "nothing waits" from the store before the request: the mark makes its end
    leave the tenant due. (O7)"""
    batch = _parked(dsn)
    _clock(dsn, held=True)

    call(dsn, "request_abandon", TENANT, batch, actor="u-1")

    assert _state(dsn) == (False, True)


def test_r53_a_batch_release_wakes_an_idle_tenant(dsn):
    batch = _parked(dsn)
    _clock(dsn)

    call(dsn, "release_batch", TENANT, batch, actor="u-1")

    assert _state(dsn) == (False, False)


def test_r53_an_item_release_wakes_an_idle_tenant(dsn):
    call(dsn, "publish_findings", TENANT, "run-1", [finding("f1")], kind="finding")
    set_held(dsn, TENANT, "f1")
    _clock(dsn)
    [item] = [i for i in call(dsn, "work", TENANT) if i.key == "f1"]

    call(dsn, "release_item", TENANT, str(item.id))

    assert _state(dsn) == (False, False)
