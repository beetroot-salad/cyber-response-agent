"""#1537 (design r3): the loop's half of a person's release and abandon, end to end over `p4_tenant` (a real clone, a
loopback origin, the P3 forge fake) and the store at `DEFENDER_DATABASE_DSN`.

A batch is parked the way production parks it (three refusals through the real tick), a person's action is made through the
store's verbs (`_release1537`), and the next tick is the real one. Observed: the forge's recorded requests, the stored rows,
the branch's tip. Whether a settle lands in the pass that closes the PR or the next is the design's open point, so a case
ticks at most twice and asserts the final state and that the batch is never ended while its PR is still open.
"""
from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from defender.tests.support.learning.core._feedback1278 import (
    FeedbackCurator,
    claim_by_hand,
    make_scene,
    opened,
    tick,
)
from defender.tests.support.learning.core._release1537 import CREDENTIAL, item_row, park, row
from defender.tests.support.learning.core._store1278 import (  # noqa: F401 — `world` is a fixture
    call,
    lapse_lease,
    lesson_citing,
    world,
)
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
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


def _authentication_failure(*, status: int | None) -> BaseException:
    from defender.learning.author.version_control import ForgejoAuthError

    error = ForgejoAuthError("the issuer AppRole login failed")
    if status is not None:
        request = httpx.Request("POST", "http://issuer.invalid/login")
        error.__cause__ = httpx.HTTPStatusError(str(status), request=request,
                                                response=httpx.Response(status, request=request))
    return error


def _misconfigured() -> BaseException:
    from defender.learning.author.version_control.auth import CredentialMisconfigured

    return CredentialMisconfigured("the generation records no host secret file")


@contextlib.contextmanager
def _delivery_will_not_open(w, error: BaseException):
    """The tenant's delivery refuses to open with `error` (the credential step, before any forge request)."""
    def refuse(*_a: Any, **_k: Any) -> Any:
        raise error
    with (getattr(w, "mp", None) or w.monkeypatch).context() as m:
        m.setattr(f"{VC}.opened_delivery", refuse)  # lint-monkeypatch: ok — the delivery open is the seam the credential fault enters by
        yield


def _tick_through_refusal(w, writer) -> None:
    with contextlib.suppress(Exception, SystemExit):
        tick(w, writer)


# --- O4: the one classifier ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(("status", "cause"), [(401, CREDENTIAL), (403, CREDENTIAL), (404, "forge_refused"),
                                                (422, "forge_refused")])
def test_o4_three_refusals_of_a_reviews_read_park_the_batch_with_the_cause_its_status_names(scene, caplog, status, cause):
    """401 and 403 park for `forge_credential_refused`, another 4xx for `forge_refused`; the forge's words stay the detail, `parked_at` is set. (O4, classifier)"""
    w = scene
    w.seed("f1")
    writer = _lesson("f1")
    batch_id, _b, _n = opened(w, writer, caplog)
    w.t.forge.refuse("/reviews", status)
    for _ in range(3):
        tick(w, writer)
    got = row(w.dsn, batch_id)
    assert (got["phase"], got["cause"]) == ("needs_person", cause)
    assert got["reason"]
    assert got["parked_at"] is not None
    assert w.statuses() == {"f1": "in_batch"}


@pytest.mark.parametrize(("error", "cause"), [
    pytest.param(lambda: _authentication_failure(status=None), CREDENTIAL, id="statusless credential failure"),
    pytest.param(lambda: _authentication_failure(status=403), CREDENTIAL, id="credential failure carrying a 403"),
    pytest.param(lambda: _authentication_failure(status=401), CREDENTIAL, id="credential failure carrying a 401"),
    pytest.param(_misconfigured, "delivery_unavailable", id="misconfigured delivery"),
])
def test_o4_a_delivery_that_will_not_open_parks_a_lapsed_batch_with_its_class_of_refusal(scene, error: Callable, cause):
    """Three ticks whose delivery refuses to open park a lapsed working batch: credential failures (with or without a status) as `forge_credential_refused`, a misconfiguration as `delivery_unavailable`. (O4, classifier)"""
    w = scene
    w.seed("f1")
    held = claim_by_hand(w, "host-lost")
    lapse_lease(w.dsn, held.batch_id)
    with _delivery_will_not_open(w, error()):
        for _ in range(3):
            _tick_through_refusal(w, FeedbackCurator())
    got = row(w.dsn, held.batch_id)
    assert (got["phase"], got["cause"], got["pr_number"]) == ("needs_person", cause, None)
    assert got["parked_at"] is not None
    assert got["reason"]


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


@pytest.mark.parametrize("how", ["read refused 403", "read server error", "close refused", "delivery will not open"])
def test_o3_a_forge_that_refuses_or_fails_leaves_the_request_waiting_stamped_and_uncounted_until_it_answers(scene, caplog, how):
    """With the forge refusing the read (403), failing it (503), refusing the close, or the delivery not opening: the batch stays parked with its request, `last_checked` moves each pass, refusals stay 3; with the fault cleared the next passes settle it. (O3, O5)"""
    w = scene
    batch_id, _branch, number, writer = _parked_in_review(w, caplog, "f1")
    _request(w, batch_id)
    before = row(w.dsn, batch_id)
    faults = {"read refused 403": lambda: w.t.forge.refuse(f"/pulls/{number}", 403, method="GET"),
              "read server error": lambda: w.t.forge.refuse(f"/pulls/{number}", 503, method="GET"),
              "close refused": lambda: w.t.forge.refuse(f"/pulls/{number}", 403, method="PATCH")}
    stamps = [before["last_checked"]]
    if how == "delivery will not open":
        with _delivery_will_not_open(w, _authentication_failure(status=None)):
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

    with _delivery_will_not_open(w, _authentication_failure(status=None)):
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
