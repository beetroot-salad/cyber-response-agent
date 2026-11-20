"""#1487 Amendment r5.3: a batch waiting for a person keeps no check clock running (`learning_store.tick.work_waiting`),
so a person's word that gives a tick something to do wakes the tenant itself: an abandon request, a batch's release and
an item's release each make the tenant's check clock not idle in the transaction that records them. A clock a post-step
holds is marked, since that post-step's answer may predate the word (#1487 O7). Real PostgreSQL, the store's own verbs."""
from __future__ import annotations

import pytest

from defender.jobs.errors import Conflict, NotFound
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._release1537 import CREDENTIAL, park, request, set_held
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


# --- G7: every person verb over every state of the tenant's check clock ----------------------------------------------

#: The tenant's check clock as a verb meets it: the row's columns (`None`: no row). A held clock is one a post-step
#: holds, live (its hold runs on) or lapsed (its hold ran out, not yet let go): both are marked (O7).
_CLOCKS = {
    "absent": None,
    "idle": ("true", "NULL", "NULL"),
    "not-idle-unheld": ("false", "NULL", "NULL"),
    "held-live": ("true", "now() + interval '1 hour'", "'post-step-1'"),
    "held-lapsed": ("true", "now() - interval '1 hour'", "'post-step-1'"),
}
_CLOCK_COLUMNS = ("checked_at", "idle", "armed_while_held", "checking_until", "holder")


def _plant_clock(dsn: str, state: str) -> None:
    values = _CLOCKS[state]
    if values is None:
        return
    idle, until, holder = values
    execute(dsn, "INSERT INTO jobs.learning_checks (tenant_id, checked_at, idle, armed_while_held, checking_until, holder) "  # noqa: S608 — the test's own literals
                 f"VALUES (%s, now() - interval '5 minutes', {idle}, false, {until}, {holder})", (TENANT,))


def _clock_row(dsn: str) -> dict | None:
    rows = execute(dsn, f"SELECT {', '.join(_CLOCK_COLUMNS)} FROM jobs.learning_checks WHERE tenant_id = %s",  # noqa: S608
                   (TENANT,))
    return None if not rows else dict(zip(_CLOCK_COLUMNS, rows[0], strict=True))


def _held_item(dsn: str) -> str:
    call(dsn, "publish_findings", TENANT, "run-1", [finding("f1")], kind="finding")
    set_held(dsn, TENANT, "f1")
    [item] = [i for i in call(dsn, "work", TENANT) if i.key == "f1"]
    return str(item.id)


def _waiting_item(dsn: str) -> str:
    call(dsn, "publish_findings", TENANT, "run-1", [finding("f1")], kind="finding")
    [item] = [i for i in call(dsn, "work", TENANT) if i.key == "f1"]
    return str(item.id)


def _working(dsn: str) -> str:
    call(dsn, "publish_findings", TENANT, "run-1", [finding("f1")], kind="finding")
    return str(call(dsn, "claim", TENANT, AUTHOR_LANE, owner="o", thresholds=ONE).batch_id)


def _parked_requested(dsn: str) -> str:
    batch = _parked(dsn)
    request(dsn, batch)
    return batch


def _parked_for_another_cause(dsn: str) -> str:
    batch = _parked(dsn)
    park(dsn, batch, cause="forge_refused")
    return batch


def _parked_beside_a_working_revert(dsn: str) -> str:
    batch = _parked(dsn)
    call(dsn, "claim_revert", TENANT, owner="o-revert")
    return batch


def _unknown_batch(_dsn: str) -> str:
    from defender.records.formats import BatchId

    return str(BatchId.mint())


def _unknown_item(_dsn: str) -> str:
    from defender.records.formats import WorkItemId

    return str(WorkItemId.mint())


def _act(dsn: str, verb: str, target: str) -> object:
    if verb == "release_item":
        return call(dsn, verb, TENANT, target)
    return call(dsn, verb, TENANT, target, actor="u-g7")


#: Each verb and the target it acts on.
_VERBS = {"request_abandon": _parked, "release_batch": _parked, "release_item": _held_item}
#: Each verb's every refusal (its docstring's): the target it is refused on and the refusal.
_REFUSALS = {
    ("request_abandon", "unknown-batch"): (_unknown_batch, NotFound),
    ("request_abandon", "not-parked"): (_working, Conflict),
    ("request_abandon", "already-requested"): (_parked_requested, Conflict),
    ("release_batch", "unknown-batch"): (_unknown_batch, NotFound),
    ("release_batch", "not-parked"): (_working, Conflict),
    ("release_batch", "parked-for-another-cause"): (_parked_for_another_cause, Conflict),
    ("release_batch", "another-batch-working-on-its-lane"): (_parked_beside_a_working_revert, Conflict),
    ("release_item", "unknown-item"): (_unknown_item, NotFound),
    ("release_item", "not-held"): (_waiting_item, Conflict),
}


@pytest.mark.parametrize("clock", _CLOCKS)
@pytest.mark.parametrize("verb", _VERBS)
def test_g7_a_persons_verb_wakes_the_tenant_and_marks_a_held_clock(dsn, verb, clock):
    """Each verb over each state of the clock: afterwards the clock is not idle, marked exactly when a post-step held it
    (live or lapsed), and nothing else of it moved: its time and hold are as they were; a clock the tenant never had
    starts now, unmarked. (Amendment r5.3, O7)"""
    target = _VERBS[verb](dsn)
    _plant_clock(dsn, clock)
    before = _clock_row(dsn)

    _act(dsn, verb, target)

    after = _clock_row(dsn)
    assert after is not None, "the verb left the tenant with no clock"
    held = before is not None and before["holder"] is not None
    assert (after["idle"], after["armed_while_held"]) == (False, held)
    if before is not None:
        assert after == {**before, "idle": False, "armed_while_held": held}, "the verb moved more of the clock than its wake"
    else:
        assert (after["checking_until"], after["holder"]) == (None, None)


@pytest.mark.parametrize("clock", _CLOCKS)
@pytest.mark.parametrize("refusal", list(_REFUSALS), ids=lambda r: "-".join(r))
def test_g7_a_refused_verb_leaves_the_clock_exactly_as_it_was(dsn, refusal, clock):
    """Each verb's every refusal over each state of the clock: the clock is exactly as it was, an absent one still
    absent. (Amendment r5.3: the wake commits with the verb)"""
    verb, _ = refusal
    make, refused = _REFUSALS[refusal]
    target = make(dsn)
    _plant_clock(dsn, clock)
    before = _clock_row(dsn)

    with pytest.raises(refused):
        _act(dsn, verb, target)

    assert _clock_row(dsn) == before


#: The table each verb's own write lands in.
_WRITES = {"request_abandon": "learning.batches", "release_batch": "learning.batches", "release_item": "learning.work_items"}


@pytest.mark.parametrize("clock", _CLOCKS)
@pytest.mark.parametrize("verb", _VERBS)
def test_g7_a_verb_whose_write_fails_after_the_arm_leaves_no_arm(dsn, verb, clock):
    """The verb's own write is refused when its transaction commits, after the arm ran (a deferred constraint trigger on
    the verb's table, the database's own seam): the verb fails, and the clock is exactly as it was, so the arm was in
    the verb's transaction. The control, with the trigger gone, wakes. (Amendment r5.3: in the same transaction)"""
    import sqlalchemy.exc

    target = _VERBS[verb](dsn)
    _plant_clock(dsn, clock)
    before = _clock_row(dsn)
    table = _WRITES[verb]
    execute(dsn, "CREATE FUNCTION g7_refuse_at_commit() RETURNS trigger LANGUAGE plpgsql AS "
                 "$$ BEGIN RAISE EXCEPTION 'g7: the write is refused at commit'; END $$")
    execute(dsn, f"CREATE CONSTRAINT TRIGGER g7_refuse AFTER UPDATE ON {table} DEFERRABLE INITIALLY DEFERRED "
                 "FOR EACH ROW EXECUTE FUNCTION g7_refuse_at_commit()")
    try:
        with pytest.raises(sqlalchemy.exc.DBAPIError, match="g7: the write is refused at commit"):
            _act(dsn, verb, target)
        assert _clock_row(dsn) == before, "the arm committed without the verb's write"
    finally:
        execute(dsn, f"DROP TRIGGER g7_refuse ON {table}")
        execute(dsn, "DROP FUNCTION g7_refuse_at_commit()")

    _act(dsn, verb, target)
    assert _clock_row(dsn)["idle"] is False, "control: without the trigger the verb wakes the tenant"  # type: ignore[index]
