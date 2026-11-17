"""#1537 (design r3): the loop's half of a person's release and abandon, end to end over `p4_tenant` (a real clone, a
loopback origin, the P3 forge fake) and the store at `DEFENDER_DATABASE_DSN`.

A batch is parked the way production parks it (three refusals through the real tick), a person's action is made through the
store's verbs (`_release1537`), and the next tick is the real one. Observed: the forge's recorded requests, the stored rows,
the branch's tip. Whether a settle lands in the pass that closes the PR or the next is the design's open point, so a case
ticks at most twice and asserts the final state and that the batch is never ended while its PR is still open.
"""
from __future__ import annotations

import contextlib
from typing import Any

import pytest

from defender.tests.support.learning.core._feedback1278 import (
    FeedbackCurator,
    claim_by_hand,
    make_scene,
    opened,
    reviewer_removes_citation,
    tick,
)
from defender.tests.support.learning.core._faults1537 import FORGE_FAULTS, OPEN_FAULTS, Fault, normalised
from defender.tests.support.learning.core._release1537 import CREDENTIAL, item_row, park, row
from defender.tests.support.learning.core._store1278 import (  # noqa: F401 — `world` is a fixture
    ONE,
    call,
    lapse_lease,
    lesson_citing,
    world,
)
from defender.tests.migrations.test_1537_causes_migration import backfilled_batch_cause
from defender.tests.support.shared._postgres1339 import empty_database, migrated_database  # noqa: F401 — fixtures
from defender.tests.tenancy.tenant_1108_delivery._support import close_on_remote, comment_row, merge_on_remote, pr_row
from defender.tests.tenancy.tenant_1108_p4._drain_support import LESSON_NAME, remote_branches

pytestmark = pytest.mark.postgres

READ_ISSUE = {"write:repository", "write:issue"}
ACTOR = "u-1537"
VC = "defender.learning.author.version_control"


@pytest.fixture
def scene(p4_tenant, migrated_database, monkeypatch, tmp_path):  # noqa: F811 — the imported fixture
    s = make_scene(p4_tenant, migrated_database, tmp_path, monkeypatch)
    s.t.forge.scopes = set(READ_ISSUE)
    s.mp = monkeypatch
    return s


def _lesson(*ids: str) -> FeedbackCurator:
    return FeedbackCurator({f"lessons/{LESSON_NAME}": lesson_citing(*ids)})


def _parked_in_review(w, caplog, *ids: str, writer: FeedbackCurator | None = None):
    """Authored, in review, then parked by three 403s on the reviews read through the real tick; the forge healthy again.
    `(batch id, branch, PR number, curator)`."""
    w.seed(*ids)
    writer = writer or _lesson(*ids[:1])
    batch_id, branch, number = opened(w, writer, caplog)
    w.t.forge.refuse("/reviews", 403)
    for _ in range(3):
        tick(w, writer)
    w.t.forge.clear_refusals()
    got = row(w.dsn, batch_id)
    assert (got["phase"], got["refusals"]) == ("needs_person", 3), "premise: parked by the refusal ceiling"
    return batch_id, branch, number, writer


def _request(w, batch_id) -> None:
    call(w.dsn, "request_abandon", w.t.tenant_id, str(batch_id), actor=ACTOR)


def _patches(w) -> list:
    return list(w.t.forge.patches)


def _settle(w, writer, batch_id, number=None) -> None:
    """At most two ticks; the batch is never ended while the PR of `number` is still open on the forge."""
    for _ in range(2):
        tick(w, writer)
        if number is not None and [p for p in w.t.forge.prs if p["number"] == number and p["state"] == "open"]:
            assert row(w.dsn, batch_id)["phase"] == "needs_person", "the batch ended while its PR was open"


def _lane_free(w) -> bool:
    return not call(w.dsn, "lane_work", w.t.tenant_id, "author", thresholds={"finding": 1}).busy


def _tick(w, writer, **seams: Any) -> int:
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain

    return author_drain(w.t, w.paths, trigger=writer, box=BoxSpy(), **seams)


def _tick_through_refusal(w, writer, **seams: Any) -> None:
    with contextlib.suppress(Exception, SystemExit):
        _tick(w, writer, **seams)


@contextlib.contextmanager
def _issuer_answers(w, **attributes: Any):
    """The tenant's issuer fake answers as `attributes` say (`status`, `body`): the credential fault met at the issuer's own
    transport, the edge the drain's fresh identity reads."""
    vault = w.t.vault
    before = {name: getattr(vault, name) for name in attributes}
    for name, value in attributes.items():
        setattr(vault, name, value)
    try:
        yield
    finally:
        for name, value in before.items():
            setattr(vault, name, value)


@contextlib.contextmanager
def _delivery_will_not_open(w, fault: Fault, tmp_path):
    """The delivery fails to open as `fault` says, at the edge it enters by: the issuer's answer, the secret store's login, the
    host secret file, or the tenant's recorded wiring. Yields the seams to give the tick."""
    from pathlib import Path

    from defender.tests.support.learning.core._faults1537 import secret_store_credential
    from defender.tests.tenancy.tenant_1108_p4._support import minting, unbind_forge

    if fault.issuer is not None:
        with _issuer_answers(w, **fault.issuer):
            yield {}
    elif fault.step == "no_wiring":
        unbind_forge(w.t)
        yield {}
    else:
        scene_minting = minting(w.t, tmp_path)
        if fault.step in {"secret_file_gone", "secret_file_empty"}:
            secret_file = Path(scene_minting.fields["host_secret_file"])
            if fault.step == "secret_file_gone":
                secret_file.unlink()
            else:
                secret_file.write_text("\n", encoding="utf-8")
            yield {"mint": True, "identity": scene_minting.credential}
        else:
            yield {"mint": True, "identity": secret_store_credential(w.t, scene_minting, int(fault.step.split(":")[1]))}


def _parked(w, batch_id, fault: Fault, path: str, old_database: str) -> None:
    """Parked by the third refusal with the table's cause; the stored reason holds the fault's own text, and the migration's
    backfill of that stored reason gives the same cause (the wording around the text is the code's, never frozen here)."""
    got = row(w.dsn, batch_id)
    assert (got["phase"], got["cause"], got["refusals"]) == ("needs_person", fault.cause, 3)
    assert got["parked_at"] is not None
    stored, text = normalised(got["reason"], w.t.tenant_id), fault.texts[path]
    # the loop keeps at most `FAULT_TEXT_LIMIT` (600) characters of a fault's text, so a long one is checked by its head
    assert (text if len(text) < 250 else text[:140]) in stored, (stored, text)
    assert backfilled_batch_cause(old_database, got["reason"]) == fault.cause, got["reason"]


# --- O4: the one classifier, one table of fault shapes through every counting path ---------------------------------------


@pytest.mark.parametrize("fault", FORGE_FAULTS, ids=lambda f: f.name)
def test_o4_three_refusals_of_a_reviews_read_park_the_batch_with_the_cause_the_fault_names(scene, caplog, fault, empty_database):  # noqa: F811 — fixture
    """In-review reconcile: three reads the forge refuses with the fault's status park the batch with the table's cause; the forge's words stay the detail. (O4, classifier)"""
    w = scene
    w.seed("f1")
    writer = _lesson("f1")
    batch_id, _b, _n = opened(w, writer, caplog)
    assert (row(w.dsn, batch_id)["phase"], row(w.dsn, batch_id)["refusals"]) == ("in_review", 0), "premise"
    w.t.forge.refuse("/reviews", fault.forge_status)
    for _ in range(3):
        tick(w, writer)
    _parked(w, batch_id, fault, "reviews", empty_database)
    assert w.statuses() == {"f1": "in_batch"}


@pytest.mark.parametrize("fault", FORGE_FAULTS, ids=lambda f: f.name)
def test_o4_three_refusals_of_the_pr_read_in_recovery_park_the_lapsed_batch_with_the_cause_the_fault_names(scene, fault, empty_database):  # noqa: F811 — fixture
    """Lapsed recovery: three PR lookups the forge refuses with the fault's status park the lapsed working batch with the table's cause. (O4, classifier)"""
    w = scene
    w.seed("f1")
    held = claim_by_hand(w, "host-lost")
    lapse_lease(w.dsn, held.batch_id)
    w.t.forge.refuse("/pulls", fault.forge_status, method="GET")
    for _ in range(3):
        tick(w, FeedbackCurator())
    _parked(w, held.batch_id, fault, "pulls", empty_database)


@pytest.mark.parametrize("state", ["in_review", "lapsed"])
@pytest.mark.parametrize("fault", OPEN_FAULTS, ids=lambda f: f.name)
def test_o4_three_deliveries_that_will_not_open_park_the_batch_with_the_cause_the_fault_names(scene, caplog, tmp_path, fault, state, empty_database):  # noqa: F811 — fixture
    """Delivery open: three ticks whose delivery fails to open as the fault says (at the issuer, the secret store, the host secret file or the wiring) park an in-review or a lapsed batch with the table's cause. (O4, classifier)"""
    w = scene
    w.seed("f1")
    writer = _lesson("f1")
    if state == "in_review":
        batch_id, _b, _n = opened(w, writer, caplog)
    else:
        held = claim_by_hand(w, "host-lost")
        lapse_lease(w.dsn, held.batch_id)
        batch_id = held.batch_id
    with _delivery_will_not_open(w, fault, tmp_path) as seams:
        for _ in range(3):
            _tick_through_refusal(w, writer, **seams)
    _parked(w, batch_id, fault, "open", empty_database)


def test_o4_the_stored_detail_of_a_refusal_is_bounded_however_long_the_fault_text_is(scene, caplog, tmp_path):  # noqa: F811 — fixture
    """A delivery that will not open names its secret file in the fault's text: with that file under a path of over a thousand characters, three refusals park the batch with the head of the text kept and the stored detail cut to a bound well below the text's own length. (O4: model- and forge-written text is only bounded detail)"""
    w = scene
    w.seed("f1")
    writer = _lesson("f1")
    batch_id, _b, _n = opened(w, writer, caplog)
    deep = tmp_path.joinpath(*["d" * 200] * 5)
    deep.mkdir(parents=True)
    [fault] = [f for f in OPEN_FAULTS if f.name == "misconfigured credential"]
    with _delivery_will_not_open(w, fault, deep) as seams:
        for _ in range(3):
            _tick_through_refusal(w, writer, **seams)
    got = row(w.dsn, batch_id)
    assert (got["phase"], got["cause"], got["refusals"]) == ("needs_person", fault.cause, 3)
    assert got["reason"].startswith("the forge refused 3 times: the tenant "), got["reason"][:80]
    assert len(str(deep)) > 1000, "premise: the fault's own text is long"
    assert len(got["reason"]) <= 1000, len(got["reason"])
    assert "\n" not in got["reason"]


# --- O3: the settle's branches --------------------------------------------------------------------------------------


def test_o3_a_parked_batch_is_left_alone_until_asked_then_its_open_pr_is_closed_once_kept_and_the_batch_settled_abandoned(scene, caplog):
    """No request: the tick touches nothing. Requested: the PR is closed once and kept, the branch keeps its tip, no new PR opens, the batch ends abandoned keeping its park cause, items held `abandoned_by_person`, the lane free. (O3, O4, O5)"""
    w = scene
    batch_id, branch, number, writer = _parked_in_review(w, caplog, "f1")
    parked = row(w.dsn, batch_id)
    tip = remote_branches(w.t.remote)[branch]
    tick(w, writer)
    assert _patches(w) == [], "control: a parked batch with no request is not touched"
    assert row(w.dsn, batch_id) == parked

    _request(w, batch_id)
    asked = row(w.dsn, batch_id)
    assert asked["abandon_requested_by"] == ACTOR
    assert asked["phase"] == "needs_person"
    _settle(w, writer, batch_id, number)

    got = row(w.dsn, batch_id)
    assert _patches(w) == [(number, {"state": "closed"})]
    assert [p["state"] for p in w.t.forge.prs if p["number"] == number] == ["closed"]
    assert remote_branches(w.t.remote)[branch] == tip
    assert len(w.t.forge.creates) == 1
    assert (got["phase"], got["outcome"], got["cause"]) == ("ended", "abandoned", CREDENTIAL)
    assert got["parked_at"] is None
    assert got["abandon_requested_by"] == ACTOR
    assert got["pr_number"] == number
    assert got["last_checked"] >= asked["abandon_requested_at"]
    assert item_row(w.dsn, w.t.tenant_id, "f1")["cause"] == "abandoned_by_person"
    assert w.statuses() == {"f1": "held"}
    assert _lane_free(w)


def test_o3_a_pr_merged_before_the_tick_is_read_as_merged_cause_and_detail_cleared_and_nothing_is_closed(scene, caplog):
    """A merged PR: the cited lesson published, the uncited item waiting again, the batch ended merged with no cause or detail, no PR touched. (O3, O4)"""
    w = scene
    batch_id, branch, _number, writer = _parked_in_review(w, caplog, "f1", "f2")
    merge_on_remote(w.t.p3, w.scratch, branch)
    _request(w, batch_id)
    _settle(w, writer, batch_id)

    got = row(w.dsn, batch_id)
    assert (got["phase"], got["outcome"], got["cause"], got["reason"], got["parked_at"]) == ("ended", "merged", None, None, None)
    assert w.statuses() == {"f1": "published", "f2": "waiting"}
    assert item_row(w.dsn, w.t.tenant_id, "f2")["cause"] is None
    assert _patches(w) == []


@pytest.mark.parametrize("words", [False, True])
def test_o3_a_pr_closed_on_the_forge_settles_abandoned_its_items_held_and_is_not_replaced_whatever_was_said(scene, caplog, words):
    """A PR already closed (with or without reviewers' words): no PATCH, the batch ended abandoned, items held `abandoned_by_person`, no replacement PR. (O3)"""
    w = scene
    batch_id, branch, number, writer = _parked_in_review(w, caplog, "f1")
    if words:
        w.t.forge.comments[number] = [comment_row(501, "analyst", "cite the alert rule, not the host")]
    close_on_remote(w.t.p3, branch)
    _request(w, batch_id)
    _settle(w, writer, batch_id)

    got = row(w.dsn, batch_id)
    assert (got["phase"], got["outcome"]) == ("ended", "abandoned")
    assert item_row(w.dsn, w.t.tenant_id, "f1")["cause"] == "abandoned_by_person"
    assert w.statuses() == {"f1": "held"}
    assert _patches(w) == []
    assert len(w.t.forge.creates) == 1
    assert _lane_free(w)


@pytest.mark.parametrize("on_forge", [True, False])
def test_o3_a_batch_parked_with_no_recorded_pr_is_found_by_its_branch_and_its_pr_closed_else_settled_with_none_opened(scene, on_forge):
    """Parked while working (no PR recorded): a PR the forge holds for its branch is closed and recorded; none: items held, batch ended abandoned, no PR opened. (O3, O2)"""
    w = scene
    w.seed("f1")
    held = claim_by_hand(w, "host-lost")
    if on_forge:
        w.t.forge.add_pr(pr_row(77, held.branch))
    park(w.dsn, held.batch_id)
    assert row(w.dsn, held.batch_id)["pr_number"] is None, "premise"
    _request(w, held.batch_id)
    _settle(w, FeedbackCurator(), held.batch_id, 77 if on_forge else None)

    got = row(w.dsn, held.batch_id)
    assert (got["phase"], got["outcome"], got["pr_number"]) == ("ended", "abandoned", 77 if on_forge else None)
    assert _patches(w) == ([(77, {"state": "closed"})] if on_forge else [])
    assert w.t.forge.creates == []
    assert w.statuses() == {"f1": "held"}


@pytest.mark.parametrize("how", ["read refused 403", "read server error", "close refused", "delivery refuses to open",
                                 "delivery fails to open transiently"])
def test_o3_a_forge_that_refuses_or_fails_leaves_the_request_waiting_stamped_and_uncounted_until_it_answers(scene, caplog, how):
    """With the forge refusing the read (403), failing it (503), refusing the close, the delivery refusing to open (the issuer answers 403) or failing to open transiently (503): the batch stays parked with its request, `last_checked` moves each pass, refusals stay 3; with the fault cleared the next passes settle it. (O3, O5)"""
    w = scene
    batch_id, _branch, number, writer = _parked_in_review(w, caplog, "f1")
    _request(w, batch_id)
    before = row(w.dsn, batch_id)
    faults = {"read refused 403": lambda: w.t.forge.refuse(f"/pulls/{number}", 403, method="GET"),
              "read server error": lambda: w.t.forge.refuse(f"/pulls/{number}", 503, method="GET"),
              "close refused": lambda: w.t.forge.refuse(f"/pulls/{number}", 403, method="PATCH")}
    stamps = [before["last_checked"]]
    if how.startswith("delivery"):
        with _issuer_answers(w, status=403 if how == "delivery refuses to open" else 503):
            for _ in range(4):
                _tick_through_refusal(w, writer)
                stamps.append(row(w.dsn, batch_id)["last_checked"])
    else:
        faults[how]()
        for _ in range(4):
            tick(w, writer)
            stamps.append(row(w.dsn, batch_id)["last_checked"])
    waiting = row(w.dsn, batch_id)
    assert (waiting["phase"], waiting["refusals"]) == ("needs_person", 3), "a waiting request counted a refusal or settled"
    assert waiting["abandon_requested_at"] == before["abandon_requested_at"]
    assert waiting["parked_at"] == before["parked_at"]
    assert all(later > earlier for earlier, later in zip(stamps, stamps[1:], strict=False)), "last_checked did not move each pass"
    assert [p["state"] for p in w.t.forge.prs if p["number"] == number] == ["open"]
    assert w.statuses() == {"f1": "in_batch"}

    w.t.forge.clear_refusals()
    _settle(w, writer, batch_id, number)
    assert (row(w.dsn, batch_id)["phase"], w.statuses()) == ("ended", {"f1": "held"})


def test_o3_a_requested_revert_or_lead_lane_batch_has_its_open_pr_closed_and_kept_like_an_authors(scene):
    """Parked in review with a request: a revert's open PR (author lane) and a lead lane batch's open PR are each closed once and kept, and each batch ends abandoned with its park cause (only a registry PR is left open). (O3, A4)"""
    w = scene
    tenant = w.t.tenant_id
    revert = call(w.dsn, "claim_revert", tenant, owner="cli")
    call(w.dsn, "in_review", revert, 5, {})
    call(w.dsn, "enqueue_request", tenant, "run-1537", "case-1", {"case": "c"})
    lead = call(w.dsn, "claim", tenant, "lead_author", owner="host-l", thresholds=ONE)
    call(w.dsn, "in_review", lead, 6, {})
    for number, held in ((5, revert), (6, lead)):
        w.t.forge.add_pr(pr_row(number, held.branch))
        park(w.dsn, held.batch_id)
        _request(w, held.batch_id)
    for _ in range(2):
        tick(w, FeedbackCurator())
    assert sorted(_patches(w), key=lambda p: p[0]) == [(5, {"state": "closed"}), (6, {"state": "closed"})]
    assert {p["number"]: p["state"] for p in w.t.forge.prs} == {5: "closed", 6: "closed"}
    for held in (revert, lead):
        got = row(w.dsn, held.batch_id)
        assert (got["phase"], got["outcome"], got["cause"]) == ("ended", "abandoned", CREDENTIAL), held.kind


def test_o3_an_abandon_settled_on_another_reconciled_lane_holds_back_no_claim_on_the_tick_s_own(scene, caplog):
    """The author drain reconciles the lead lane too. Settling a lead lane batch's requested abandon frees the lead lane,
    not the author lane, so the author lane's due work is claimed in that same pass. (O3, #1558 review)"""
    w = scene
    tenant = w.t.tenant_id
    call(w.dsn, "enqueue_request", tenant, "run-1537", "case-1", {"case": "c"})
    lead = call(w.dsn, "claim", tenant, "lead_author", owner="host-l", thresholds=ONE)
    call(w.dsn, "in_review", lead, 6, {})
    w.t.forge.add_pr(pr_row(6, lead.branch))
    park(w.dsn, lead.batch_id)
    _request(w, lead.batch_id)
    w.seed("f1")
    writer = _lesson("f1")
    tick(w, writer)
    got = row(w.dsn, lead.batch_id)
    assert (got["phase"], got["outcome"]) == ("ended", "abandoned"), "premise: the lead batch's abandon settled this pass"
    assert len(writer.served) == 1, "the author lane's due work waited a pass behind another lane's abandon"


def test_o3_an_abandon_request_that_waits_on_the_tick_s_own_lane_holds_back_no_claim(scene, caplog):
    """A revert batch is on the author lane but holds no lane. While its requested abandon waits on a failing forge, nothing
    was given back, so the author lane's due work is claimed as usual. (O3)"""
    w = scene
    revert = call(w.dsn, "claim_revert", w.t.tenant_id, owner="cli")
    call(w.dsn, "in_review", revert, 5, {})
    w.t.forge.add_pr(pr_row(5, revert.branch))
    park(w.dsn, revert.batch_id)
    _request(w, revert.batch_id)
    w.t.forge.refuse("/pulls/5", 503, method="GET")
    w.seed("f1")
    writer = _lesson("f1")
    tick(w, writer)
    assert row(w.dsn, revert.batch_id)["phase"] == "needs_person", "premise: the request waits this pass"
    assert len(writer.served) == 1, "a request that settled nothing held back the claim"


def test_o3_an_abandon_settled_on_the_tick_s_own_lane_holds_back_its_claim_for_one_pass(scene, caplog):
    """An author batch's settled abandon gives its lane back: the claim that room makes waits for the next pass, then
    happens. (O3)"""
    w = scene
    batch_id, _branch, _number, writer = _parked_in_review(w, caplog, "f1")
    w.seed("f2")
    _request(w, batch_id)
    served = len(writer.served)
    tick(w, writer)
    assert row(w.dsn, batch_id)["phase"] == "ended", "premise: the abandon settled this pass"
    assert len(writer.served) == served, "the pass that ended the batch also claimed over what it gave back"
    tick(w, writer)
    assert len(writer.served) == served + 1, "the next pass did not claim the waiting work"


def test_o3_a_pr_merged_in_the_gap_after_the_close_is_settled_merged_never_abandoned(scene, caplog):
    """The forge merges the PR as the loop's close arrives: the loop reads the PR again before it settles, so the batch ends merged (the cited lesson published, the uncited item waiting again, no cause), not abandoned with its items held. (O3: close first, then settle)"""
    w = scene
    batch_id, branch, number, writer = _parked_in_review(w, caplog, "f1", "f2")
    merged: list[str] = []

    def merge_as_the_close_arrives(request: Any) -> None:
        if request.method == "PATCH" and not merged:
            merged.append(merge_on_remote(w.t.p3, w.scratch, branch))

    w.t.forge.on_request = merge_as_the_close_arrives
    _request(w, batch_id)
    _settle(w, writer, batch_id)

    assert merged, "premise: the loop tried to close the open PR"
    got = row(w.dsn, batch_id)
    assert (got["phase"], got["outcome"], got["cause"], got["reason"], got["parked_at"]) == ("ended", "merged", None, None, None)
    assert w.statuses() == {"f1": "published", "f2": "waiting"}


def test_o3_a_lesson_cut_from_the_merge_is_held_as_cut_from_merge_when_the_requested_batch_settles_merged(scene, caplog):
    """A reviewer's edit drops one cited finding from the merged lesson, and the batch is parked with a request: it settles merged, the kept citation published and the cut one held with the cause `cut_from_merge` (not waiting again), no cause on the batch. (O3, O4)"""
    w = scene
    batch_id, branch, _number, writer = _parked_in_review(w, caplog, "f1", "f2", writer=_lesson("f1", "f2"))
    merge_on_remote(w.t.p3, w.scratch, branch, edit=reviewer_removes_citation(LESSON_NAME, lesson_citing("f2")))
    _request(w, batch_id)
    _settle(w, writer, batch_id)

    got = row(w.dsn, batch_id)
    assert (got["phase"], got["outcome"], got["cause"]) == ("ended", "merged", None)
    assert w.statuses() == {"f1": "held", "f2": "published"}
    cut = item_row(w.dsn, w.t.tenant_id, "f1")
    assert cut["cause"] == "cut_from_merge", cut
    assert cut["reason"], "the detail stays beside the cause"


# --- O2: release, end to end ---------------------------------------------------------------------------------------


def test_o2_a_released_batch_is_read_again_as_in_review_and_a_later_merge_ends_it_merged(scene, caplog):
    """Released after a credential park: refusals 0, back in review; the next tick reads its open PR as usual; once merged, the following tick ends it merged and publishes the lesson. (O2)"""
    w = scene
    batch_id, branch, number, writer = _parked_in_review(w, caplog, "f1")
    call(w.dsn, "release_batch", w.t.tenant_id, str(batch_id), actor=ACTOR)
    got = row(w.dsn, batch_id)
    assert (got["phase"], got["refusals"], got["cause"], got["pr_number"]) == ("in_review", 0, None, number)
    tick(w, writer)
    assert row(w.dsn, batch_id)["phase"] == "in_review"
    assert _patches(w) == []
    merge_on_remote(w.t.p3, w.scratch, branch)
    tick(w, writer)
    assert (row(w.dsn, batch_id)["outcome"], w.statuses()) == ("merged", {"f1": "published"})


def test_o2_a_batch_parked_while_working_is_released_taken_over_by_recovery_and_its_one_pr_opened(world, caplog):  # noqa: F811
    """A lapsed author batch with commits and no PR, parked by three credential failures at the delivery open, released: the next healthy tick takes it over, runs no curator again and opens its one PR. (O2, C14)"""
    from defender.learning.author.version_control import store_delivery
    from defender.tests.support.learning.core._tickfaults1278 import Cast, Scene

    w = world
    s = Scene(w, "author")
    s.seed()

    def refuse_pr(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("injected: the PR open")
    with w.monkeypatch.context() as m:
        m.setattr(store_delivery, "open_pr_on", refuse_pr)  # lint-monkeypatch: ok — leaves a batch with commits and no PR, as a crashed holder does
        s.run(Cast(s))
    batch = s.only_batch()
    assert (batch.phase, batch.pr_number) == ("working", None), "premise: commits, no PR"
    assert s.open_prs() == []
    lapse_lease(w.dsn, batch.id)

    with _issuer_answers(w, body={"data": {}}):
        for _ in range(3):
            s.run(Cast(s, tag="-down"))
    parked = row(w.dsn, batch.id)
    assert (parked["phase"], parked["cause"], parked["pr_number"]) == ("needs_person", CREDENTIAL, None)

    call(w.dsn, "release_batch", w.t.tenant_id, batch.id, actor=ACTOR)
    released = row(w.dsn, batch.id)
    assert (released["phase"], released["lease_owner"]) == ("working", f"released:{ACTOR}")
    again = Cast(s, tag="-again")
    s.run(again)
    after = row(w.dsn, batch.id)
    [pr] = s.open_prs()
    assert again.started() == [], "the takeover ran a curator again"
    assert (after["phase"], after["pr_number"], pr["head"]["ref"]) == ("in_review", pr["number"], batch.branch)
    assert after["cause"] is None
    assert after["parked_at"] is None
