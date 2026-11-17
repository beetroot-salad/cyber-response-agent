"""#1537 API half (design r3 O1-O7): `POST /api/tenants/{t}/learning/items/{id}/release`, `.../batches/{id}/release` and
`.../batches/{id}/abandon` over the server's own wiring (`soar()`: a #1496 database world whose `learning_work` is the real
adapter over a real learning store; admin `ann` of T1, admin `bob` of T2, a T1 program on `automation`).

Rows come from `support/api/_actions1537` (store verbs; r3's park state by one UPDATE over the design's columns). Each
refusal sits beside the admin's success on a real row (a missing route is a 404/405 for everyone). Forced choices
the design leaves open are tagged `FC-n`:
FC-1 the response's id key (the id is found by value); FC-2 the audit event carries the prior cause and detail in
`detail` (the only free field of `announce`); FC-3 the 409's words name a status, phase or cause as text.
"""
from __future__ import annotations

from typing import Any

import pytest

from defender.tests.support.api._actions1537 import (
    CREDENTIAL,
    OLD,
    OTHER_PARK_CAUSES,
    batch_row,
    held_item,
    in_review,
    item_id,
    item_row,
    items_in,
    merged,
    names,
    on_store,
    park,
    set_batch,
    set_item,
    working,
    working_registry,
    working_revert,
)
from defender.tests.support.api._identity1306 import T1, T2, user_id
from defender.tests.support.api._learning1485 import instant
from defender.tests.support.api._mount1161 import API
from defender.tests.support.api._programs1307 import soar
from defender.tests.support.learning.core._store1278 import claim, publish
from defender.tests.support.shared._fixture_uuid import fixture_uuid

pytestmark = [pytest.mark.postgres]

LEARNING = "learning"
LONG_LINE = "the forge said: " + "x" * 300
TAIL = "TAIL-SENTINEL-NEVER-LOGGED"


def _post(client: Any, tenant: str, tail: str) -> Any:
    return client.post(f"{API}/tenants/{tenant}/{LEARNING}/{tail}")


def _release_item(client: Any, tenant: str, item: Any) -> Any:
    return _post(client, tenant, f"items/{item}/release")


def _release_batch(client: Any, tenant: str, batch: Any) -> Any:
    return _post(client, tenant, f"batches/{batch}/release")


def _abandon(client: Any, tenant: str, batch: Any) -> Any:
    return _post(client, tenant, f"batches/{batch}/abandon")


def _listed(client: Any, tenant: str, route: str) -> list[dict[str, Any]]:
    r = client.get(f"{API}/tenants/{tenant}/{LEARNING}/{route}")
    assert r.status_code == 200, r.text
    return r.json()["items"]


def _carries(body: dict[str, Any], identifier: Any) -> bool:
    """FC-1: the body names the row by id, under whatever key (`id`, `item_id`, `batch_id`)."""
    return str(identifier) in {str(v) for v in body.values()}


@pytest.fixture
def s():
    built = soar()
    yield built
    built.world.close()


# --- O1 release an item --------------------------------------------------------------------------------------------

def test_o1_an_admin_releases_a_held_item_it_waits_afresh_and_a_second_release_is_a_409_naming_waiting(s):
    """200 with the id and status `waiting`; the item starts afresh, leaves the held list; again, 409 naming `waiting`. (O1, PR3)"""
    dsn = s.world.dsn
    item = held_item(dsn, T1, "h1")
    before = item_row(dsn, item)
    assert (before["status"], before["attempts"]) == ("held", 1), "premise: held at the attempt ceiling"
    assert before["cause"] is not None, "premise: a held item has a cause"
    assert [i["key"] for i in _listed(s.ann, T1, "items")] == ["h1"], "premise: it lists"

    r = _release_item(s.ann, T1, item)
    assert r.status_code == 200, r.text
    assert _carries(r.json(), item)
    assert r.json()["status"] == "waiting"
    after = item_row(dsn, item)
    assert (after["status"], after["attempts"], after["deferrals"], after["cause"], after["reason"]) == (
        "waiting", 0, 0, None, None)
    assert _listed(s.ann, T1, "items") == []

    again = _release_item(s.ann, T1, item)
    assert again.status_code == 409, again.text
    assert names(again.json()["detail"], "waiting")  # FC-3
    assert item_row(dsn, item) == after


def test_o1_a_held_request_with_a_fresher_one_waiting_is_released_as_skipped_and_the_answer_says_so(s):
    """Releasing a held curation request while a fresher request for its case waits: 200 `skipped`, stored skipped
    with cause `superseded`, the fresher one still waiting. (O1)"""
    dsn = s.world.dsn

    async def seed(store: Any) -> None:
        assert await store.enqueue_request(T1, "run-1", "case-1", {"case": "case-1"})
        set_item(dsn, T1, "run-1", status="held", cause="curator_held", reason="held for a person")
        assert await store.enqueue_request(T1, "run-2", "case-1", {"case": "case-1"})
    on_store(dsn, seed)
    old, fresher = item_id(dsn, T1, "run-1"), item_id(dsn, T1, "run-2")
    assert (item_row(dsn, old)["status"], item_row(dsn, fresher)["status"]) == ("held", "waiting"), "premise"

    r = _release_item(s.ann, T1, old)
    assert r.status_code == 200, r.text
    assert _carries(r.json(), old)
    assert r.json()["status"] == "skipped"
    skipped = item_row(dsn, old)
    assert (skipped["status"], skipped["cause"]) == ("skipped", "superseded")
    assert item_row(dsn, fresher)["status"] == "waiting"


def test_o1_an_item_that_is_not_held_is_a_409_naming_its_status_and_nothing_changes(s):
    """Waiting, in-batch, published, skipped and dead items are each refused 409 naming the status (dead items are not
    retried: O1 says held); the held one beside them releases (control). (O1, PR3)"""
    dsn = s.world.dsn
    held = held_item(dsn, T1, "h1")

    async def seed(store: Any) -> None:
        await merged(store, T1, "p1")
        await publish(store, T1, "b1")
        assert await claim(store, T1) is not None
        await publish(store, T1, "w1", "s1", "d1")
    on_store(dsn, seed)
    set_item(dsn, T1, "s1", status="skipped", cause="curator_skipped")
    set_item(dsn, T1, "d1", status="dead", cause="replacement_ceiling")
    states = {"p1": "published", "b1": "in_batch", "w1": "waiting", "s1": "skipped", "d1": "dead"}
    for key, status in states.items():
        row = item_row(dsn, item_id(dsn, T1, key))
        assert row["status"] == status, f"premise: {key}"
        r = _release_item(s.ann, T1, item_id(dsn, T1, key))
        assert r.status_code == 409, (key, r.text)
        assert names(r.json()["detail"], status), (key, r.json()["detail"])  # FC-3
        assert item_row(dsn, item_id(dsn, T1, key)) == row, key
    assert _release_item(s.ann, T1, held).status_code == 200


def test_o1_another_tenants_item_and_an_unknown_id_are_404_and_the_item_stays_held(s):
    """T2's held item released through T1 by T1's admin, and an id no one holds, are 404; T2's admin releases it (control). (O1)"""
    dsn = s.world.dsn
    theirs = held_item(dsn, T2, "b1")
    before = item_row(dsn, theirs)
    assert _release_item(s.ann, T1, theirs).status_code == 404
    assert _release_item(s.ann, T1, fixture_uuid("item:1537-none")).status_code == 404
    assert item_row(dsn, theirs) == before
    assert _release_item(s.bob, T2, theirs).status_code == 200


# --- O2 release a batch --------------------------------------------------------------------------------------------

def test_o2_a_credential_parked_batch_with_a_pr_is_released_to_review_and_leaves_the_parked_list(s):
    """200 with its id and phase `in_review`; stored in review, PR kept, cause, parked_at and refusals cleared; the
    parked list no longer has it. (O2)"""
    dsn = s.world.dsn
    batch = on_store(dsn, in_review, T1, "f1", "f2", pr=9)
    park(dsn, batch)
    assert [b["batch_id"] for b in _listed(s.ann, T1, "parked-batches")] == [batch], "premise: listed"

    r = _release_batch(s.ann, T1, batch)
    assert r.status_code == 200, r.text
    assert _carries(r.json(), batch)
    assert r.json()["phase"] == "in_review"
    row = batch_row(dsn, batch)
    assert (row["phase"], row["pr_number"], row["cause"], row["parked_at"], row["refusals"]) == (
        "in_review", 9, None, None, 0)
    assert items_in(dsn, batch) == ["f1", "f2"]
    assert _listed(s.ann, T1, "parked-batches") == []


def test_o2_a_credential_parked_batch_with_no_pr_is_released_to_working(s):
    """Parked while being worked on (no PR): 200 with phase `working`; stored working, no PR, cause and parked_at cleared. (O2)"""
    dsn = s.world.dsn
    batch = on_store(dsn, working, T1, "f1")
    park(dsn, batch)
    assert batch_row(dsn, batch)["pr_number"] is None, "premise: no PR"

    r = _release_batch(s.ann, T1, batch)
    assert r.status_code == 200, r.text
    assert _carries(r.json(), batch)
    assert r.json()["phase"] == "working"
    row = batch_row(dsn, batch)
    assert (row["phase"], row["pr_number"], row["cause"], row["parked_at"], row["refusals"]) == ("working", None, None, None, 0)
    assert _listed(s.ann, T1, "parked-batches") == []


def test_o2_release_is_refused_for_every_other_cause_and_for_a_pending_request_naming_why_until_neither_holds(s):
    """One parked batch: each cause other than `forge_credential_refused` is a 409 naming the cause, a pending abandon
    request is a 409 naming the request; every refusal leaves the row as it was; with the credential cause and no
    request the same batch releases (control). (O2, PR3)"""
    dsn = s.world.dsn
    batch = on_store(dsn, in_review, T1, "f1")
    park(dsn, batch)
    for cause in OTHER_PARK_CAUSES:
        set_batch(dsn, batch, cause=cause)
        row = batch_row(dsn, batch)
        r = _release_batch(s.ann, T1, batch)
        assert r.status_code == 409, (cause, r.text)
        assert names(r.json()["detail"], cause), (cause, r.json()["detail"])  # FC-3
        assert batch_row(dsn, batch) == row, cause
    set_batch(dsn, batch, cause=CREDENTIAL, abandon_requested_at=OLD, abandon_requested_by=user_id(s.ann))
    row = batch_row(dsn, batch)
    pending = _release_batch(s.ann, T1, batch)
    assert pending.status_code == 409, pending.text
    assert names(pending.json()["detail"], "abandon"), pending.json()["detail"]  # FC-3
    assert batch_row(dsn, batch) == row
    set_batch(dsn, batch, abandon_requested_at=None, abandon_requested_by=None)
    assert _release_batch(s.ann, T1, batch).status_code == 200


def test_o2_a_batch_parked_from_working_is_not_released_while_another_batch_works_on_its_lane(s):
    """A working-parked author batch whose lane has a working revert: 409 naming the lane, still parked. (O2)"""
    dsn = s.world.dsn
    batch = on_store(dsn, working, T1, "f1")
    park(dsn, batch)
    revert = on_store(dsn, working_revert, T1)
    assert batch_row(dsn, revert)["phase"] == "working", "premise: another batch works on the lane"
    row = batch_row(dsn, batch)

    r = _release_batch(s.ann, T1, batch)
    assert r.status_code == 409, r.text
    assert names(r.json()["detail"], "lane"), r.json()["detail"]  # FC-3
    assert batch_row(dsn, batch) == row


@pytest.mark.parametrize("act", [_release_batch, _abandon], ids=["release", "abandon"])
def test_o2_o3_another_tenants_batch_and_an_unknown_id_are_404_and_the_batch_stays_parked(s, act):
    """T2's parked batch through T1, and an unknown id: 404, nothing changes; T2's admin acts on it (control). (O2, O3)"""
    dsn = s.world.dsn
    theirs = on_store(dsn, in_review, T2, "g1")
    park(dsn, theirs)
    before = batch_row(dsn, theirs)
    assert act(s.ann, T1, theirs).status_code == 404
    assert act(s.ann, T1, fixture_uuid("batch:1537-none")).status_code == 404
    assert batch_row(dsn, theirs) == before
    assert act(s.bob, T2, theirs).status_code in (200, 202)


# --- O3 abandon request --------------------------------------------------------------------------------------------

def test_o3_an_abandon_is_202_recorded_with_who_and_when_and_decides_nothing_else(s):
    """202 with the id and `abandon_requested_at`; the request is stored with the admin's id and shown on the parked list; the
    batch stays parked, its items stay in it, nothing ended (the loop settles it, PR2); `last_checked` older than the
    request is not reported. (O3, O5)"""
    dsn = s.world.dsn
    batch = on_store(dsn, in_review, T1, "f1", "f2")
    park(dsn, batch)
    set_batch(dsn, batch, last_checked=OLD)

    r = _abandon(s.ann, T1, batch)
    assert r.status_code == 202, r.text
    assert _carries(r.json(), batch)
    row = batch_row(dsn, batch)
    assert instant(r.json()["abandon_requested_at"]) == row["abandon_requested_at"]
    assert str(row["abandon_requested_by"]) == user_id(s.ann)
    assert (row["phase"], row["outcome"], row["cause"]) == ("needs_person", None, CREDENTIAL)
    assert items_in(dsn, batch) == ["f1", "f2"]
    [wire] = _listed(s.ann, T1, "parked-batches")
    assert wire["batch_id"] == batch
    assert instant(wire["abandon_requested_at"]) == row["abandon_requested_at"]
    assert wire["releasable"] is False
    assert wire["last_checked"] is None


def test_o3_a_second_abandon_is_a_409_naming_the_request_and_the_first_request_stands(s):
    """Again: 409 naming the pending request; `abandon_requested_at` and its author are unchanged. (O3, PR3)"""
    dsn = s.world.dsn
    batch = on_store(dsn, in_review, T1, "f1")
    park(dsn, batch)
    assert _abandon(s.ann, T1, batch).status_code == 202
    first = batch_row(dsn, batch)

    again = _abandon(s.ann, T1, batch)
    assert again.status_code == 409, again.text
    assert names(again.json()["detail"], "abandon"), again.json()["detail"]  # FC-3
    assert batch_row(dsn, batch) == first


def test_o3_a_batch_that_is_not_parked_is_a_409_naming_its_state_and_records_no_request(s):
    """A merged batch, a batch in review and a working revert are each refused naming `merged`, `in_review` and `working`;
    a parked one beside them takes the request (control). (O3, PR3)"""
    dsn = s.world.dsn
    done = on_store(dsn, merged, T1, "m1")
    reviewing = on_store(dsn, in_review, T1, "f1")
    revert = on_store(dsn, working_revert, T1)
    for batch, word in ((done, "merged"), (reviewing, "in_review"), (revert, "working")):
        row = batch_row(dsn, batch)
        r = _abandon(s.ann, T1, batch)
        assert r.status_code == 409, (word, r.text)
        assert names(r.json()["detail"], word), (word, r.json()["detail"])  # FC-3
        assert batch_row(dsn, batch) == row
        assert row["abandon_requested_at"] is None
    park(dsn, reviewing)
    assert _abandon(s.ann, T1, reviewing).status_code == 202


def test_o3_every_kind_of_parked_batch_takes_an_abandon_request_whatever_its_cause(s):
    """A parked author (credential), revert (`forge_refused`) and registry (`foreign_pr`) batch each answer 202 and store a request. (O3)"""
    dsn = s.world.dsn

    async def seed(store: Any) -> list[str]:
        return [await in_review(store, T1, "f1"), await working_revert(store, T1), await working_registry(store, T1)]
    author, revert, registry = on_store(dsn, seed)
    for batch, cause in ((author, CREDENTIAL), (revert, "forge_refused"), (registry, "foreign_pr")):
        park(dsn, batch, cause=cause)
    for batch in (author, revert, registry):
        r = _abandon(s.ann, T1, batch)
        assert r.status_code == 202, (batch, r.text)
        assert batch_row(dsn, batch)["abandon_requested_at"] is not None


# --- O4, O5 the lists ----------------------------------------------------------------------------------------------

def test_o4_the_lists_carry_each_rows_stored_cause(s):
    """A held item (the store's own attempt ceiling) and a dead item list with their stored cause; a parked batch lists with
    its stored cause. (O4)"""
    dsn = s.world.dsn
    held = held_item(dsn, T1, "h1")
    set_item(dsn, T1, "h1", reason="held for a person")
    dead = held_item(dsn, T1, "d1")
    set_item(dsn, T1, "d1", status="dead", cause="replacement_ceiling")
    batch = on_store(dsn, in_review, T1, "f1")
    park(dsn, batch, cause="foreign_pr")
    by_key = {i["key"]: i for i in _listed(s.ann, T1, "items")}
    stored = item_row(dsn, held)["cause"]
    assert stored is not None, "premise: the store gave the held item a cause"
    assert by_key["h1"]["cause"] == stored
    assert (by_key["d1"]["cause"], item_row(dsn, dead)["cause"]) == ("replacement_ceiling", "replacement_ceiling")
    [wire] = _listed(s.ann, T1, "parked-batches")
    assert wire["cause"] == "foreign_pr"


def test_o5_a_parked_batch_is_releasable_only_for_the_credential_cause_with_no_pending_request(s):
    """Every cause but `forge_credential_refused` is not releasable; the credential cause is, until a request is pending. (O5)"""
    dsn = s.world.dsn
    batch = on_store(dsn, in_review, T1, "f1")
    park(dsn, batch)

    def releasable() -> bool:
        [wire] = _listed(s.ann, T1, "parked-batches")
        return wire["releasable"]
    assert releasable() is True
    for cause in OTHER_PARK_CAUSES:
        set_batch(dsn, batch, cause=cause)
        assert releasable() is False, cause
    set_batch(dsn, batch, cause=CREDENTIAL, abandon_requested_at=OLD, abandon_requested_by=user_id(s.ann))
    assert releasable() is False
    set_batch(dsn, batch, abandon_requested_at=None, abandon_requested_by=None)
    assert releasable() is True


def test_o5_parked_at_and_a_request_show_and_last_checked_shows_for_a_request_only_from_the_request_on(s):
    """`parked_at` is the stored stamp (null when stored null); `abandon_requested_at` is null until requested;
    `last_checked` of a requested batch is null before the request and reported at and after it. (O5)"""
    dsn = s.world.dsn
    batch = on_store(dsn, in_review, T1, "f1")
    park(dsn, batch)
    parked = batch_row(dsn, batch)["parked_at"]
    [wire] = _listed(s.ann, T1, "parked-batches")
    assert instant(wire["parked_at"]) == parked
    assert wire["abandon_requested_at"] is None
    set_batch(dsn, batch, parked_at=None)
    assert _listed(s.ann, T1, "parked-batches")[0]["parked_at"] is None

    asked = OLD.replace(year=2026, month=3)
    set_batch(dsn, batch, abandon_requested_at=asked, abandon_requested_by=user_id(s.ann))
    for checked, shown in ((asked.replace(month=2), False), (asked, True), (asked.replace(month=4), True)):
        set_batch(dsn, batch, last_checked=checked)
        [wire] = _listed(s.ann, T1, "parked-batches")
        assert instant(wire["abandon_requested_at"]) == asked
        assert (instant(wire["last_checked"]) if wire["last_checked"] else None) == (checked if shown else None), checked


# --- O6 audit ------------------------------------------------------------------------------------------------------

def _events(s: Any, mark: int) -> list[Any]:
    return s.world.audit.events[mark:]


def test_o6_each_successful_action_is_one_event_with_the_actor_tenant_target_and_prior_cause_and_detail(s):
    """A release of an item, a release of a batch and an abandon request each announce exactly one event: the admin's id, T1,
    the target, no credential, and the cause and detail the row had; the three actions differ. (O6)"""
    dsn = s.world.dsn
    item = held_item(dsn, T1, "h1")
    set_item(dsn, T1, "h1", reason="held until a person looks")
    batch = on_store(dsn, in_review, T1, "f1")
    park(dsn, batch, reason="refused three times")
    cause = item_row(dsn, item)["cause"]
    ann = user_id(s.ann)
    seen = []
    for target, prior_cause, prior_detail, act in ((item, cause, "held until a person looks", _release_item),
                                                    (batch, CREDENTIAL, "refused three times", _release_batch)):
        mark = len(s.world.audit.events)
        assert act(s.ann, T1, target).status_code == 200
        [event] = _events(s, mark)
        assert (event.user_id, event.tenant_id, event.target, event.credential_id) == (ann, T1, str(target), None)
        assert prior_cause in (event.detail or "")  # FC-2
        assert prior_detail in (event.detail or "")
        seen.append(event.action)
    park(dsn, batch, reason="refused again")
    mark = len(s.world.audit.events)
    assert _abandon(s.ann, T1, batch).status_code == 202
    [event] = _events(s, mark)
    assert (event.user_id, event.tenant_id, event.target, event.credential_id) == (ann, T1, batch, None)
    assert CREDENTIAL in (event.detail or "")  # FC-2
    assert "refused again" in (event.detail or "")
    seen.append(event.action)
    assert len(set(seen)) == 3, seen


def test_o6_a_long_multi_line_prior_detail_arrives_shortened_on_one_line(s):
    """A model- or forge-written prior detail of many lines and thousands of characters is logged on one line, bounded, with
    its start and the cause kept and its tail dropped; the same holds for all three actions. (O6)"""
    dsn = s.world.dsn
    long_text = LONG_LINE + "\n" + "\n".join(f"line {n} " + "y" * 200 for n in range(60)) + "\n" + TAIL
    assert len(long_text) > 10_000
    item = held_item(dsn, T1, "h1")
    set_item(dsn, T1, "h1", reason=long_text)
    batch = on_store(dsn, in_review, T1, "f1")
    park(dsn, batch, reason=long_text)
    cause = item_row(dsn, item)["cause"]
    steps = ((_release_item, item, cause, 200), (_release_batch, batch, CREDENTIAL, 200), (_abandon, batch, CREDENTIAL, 202))
    for act, target, prior_cause, status in steps:
        if act is _abandon:
            park(dsn, batch, reason=long_text)
        mark = len(s.world.audit.events)
        assert act(s.ann, T1, target).status_code == status
        [event] = _events(s, mark)
        detail = event.detail or ""
        assert prior_cause in detail  # FC-2
        assert LONG_LINE[:40] in detail
        assert "\n" not in detail
        assert "\r" not in detail
        assert TAIL not in detail
        assert len(detail) < len(long_text) // 2


def test_o6_a_refused_action_announces_nothing_and_a_successful_one_beside_it_does(s):
    """409 (not held, wrong cause, pending request), 404 and 403 announce no event; a success on a real row does. (O6)"""
    dsn = s.world.dsn
    item = held_item(dsn, T1, "h1")
    batch = on_store(dsn, in_review, T1, "f1")
    park(dsn, batch)
    program = s.program()
    mark = len(s.world.audit.events)
    assert _release_item(program, T1, item).status_code == 403
    assert _release_batch(program, T1, batch).status_code == 403
    assert _abandon(program, T1, batch).status_code == 403
    assert _release_item(s.ann, T1, fixture_uuid("item:1537-none")).status_code == 404
    assert _abandon(s.ann, T1, fixture_uuid("batch:1537-none")).status_code == 404
    set_batch(dsn, batch, cause="forge_refused")
    assert _release_batch(s.ann, T1, batch).status_code == 409
    set_batch(dsn, batch, cause=CREDENTIAL)
    assert _abandon(s.ann, T1, batch).status_code == 202
    mark_after_success = len(s.world.audit.events)
    assert mark_after_success == mark + 1, "premise: the one success announced"
    assert _abandon(s.ann, T1, batch).status_code == 409
    assert _release_batch(s.ann, T1, batch).status_code == 409
    assert _release_item(s.ann, T1, item).status_code == 200
    assert _release_item(s.ann, T1, item).status_code == 409
    assert len(s.world.audit.events) == mark_after_success + 1


# --- O7 admins only ------------------------------------------------------------------------------------------------

def test_o7_a_program_is_refused_all_three_actions_and_nothing_changes_while_it_still_reads_the_lists(s):
    """A T1 program (`automation`) gets 403 on each action and the rows stay as they were; it reads both lists (`work.read`);
    a non-member admin is 404 and no sign-in 401; the admin's same calls succeed (control). (O7)"""
    dsn = s.world.dsn
    item = held_item(dsn, T1, "h1")
    batch = on_store(dsn, in_review, T1, "f1")
    park(dsn, batch)
    before = (item_row(dsn, item), batch_row(dsn, batch))
    program = s.program()
    for client, want in ((program, 403), (s.bob, 404), (s.world.client(), 401)):
        assert _release_item(client, T1, item).status_code == want, want
        assert _release_batch(client, T1, batch).status_code == want, want
        assert _abandon(client, T1, batch).status_code == want, want
    assert (item_row(dsn, item), batch_row(dsn, batch)) == before
    assert program.get(f"{API}/tenants/{T1}/{LEARNING}/items").status_code == 200
    assert program.get(f"{API}/tenants/{T1}/{LEARNING}/parked-batches").status_code == 200
    assert _release_item(s.ann, T1, item).status_code == 200
    assert _abandon(s.ann, T1, batch).status_code == 202


def test_o7_there_is_no_lanes_route(s):
    """`GET .../learning/lanes` is not served (the parked list's `lane` and `blocks_lane` answer it); the parked list is. (Design: API)"""
    assert s.ann.get(f"{API}/tenants/{T1}/{LEARNING}/lanes").status_code == 404
    assert s.ann.get(f"{API}/tenants/{T1}/{LEARNING}/parked-batches").status_code == 200
