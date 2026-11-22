"""#1278 the author and lead-author ticks on the stop path: a stop delivered at every point of the claim (family 7).
Split from `test_1278_tick_faults.py` (one file's CI cost), whose helpers these cases use.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import pytest

from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    RENEW_ENV,
    call,
    lease_seconds_left,
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — fixture
)
from defender.tests.support.learning.core._tickfaults1278 import (
    AFTER_COMMIT,
    BEFORE_COMMIT,
    CURATORS,
    Cast,
    PushSpy,
    Scene,
    ask_for_stop_and_wait,
    hang_pushes,
    raise_in,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import critical_text, without_clone
from defender.tests.tenancy.tenant_1108_p4.test_1278_tick_faults import (
    LANES,
    the_batch,
)

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

# =====================================================================================================================
# Family 7: the stop path
# =====================================================================================================================

STOP_BOUND = 30.0
#: A stopped holder's push must leave room for the login and the box stop inside the worker's 30 s stop grace (G-C7).
STOP_PUSH_BUDGET = 15.0


@dataclass(frozen=True)
class StopPoint:
    """Where the stop lands: `curator` and `point` of its turn, or `push` (inside the claim's own push); how many
    commits the claim has made by then and which curators have started."""

    name: str
    commits: int
    started: int
    curator: int | None = None
    point: str | None = None
    push: bool = False
    push_fails: bool = False


STOP_POINTS = (
    StopPoint("first_curator_before_its_commit", 0, 1, curator=0, point=BEFORE_COMMIT),
    StopPoint("first_curator_after_its_commit", 1, 1, curator=0, point=AFTER_COMMIT),
    StopPoint("second_curator_before_its_commit", 1, 2, curator=1, point=BEFORE_COMMIT),
    StopPoint("second_curator_after_its_commit", 2, 2, curator=1, point=AFTER_COMMIT),
    StopPoint("during_the_push", 2, 2, push=True),
    StopPoint("during_the_push_which_then_fails", 2, 2, push=True, push_fails=True),  # 1618-tradeoff: a stop whose push fails loses the work
)


def _stop_cases():
    """Each lane at each stop point, delivered as the worker's stop (cancel, ended by the renewer's signal); a store
    `Stop` raised inside a curator as well, wherever a curator can raise one."""
    return [pytest.param(lane, p, how, id=f"{lane}-{p.name}-{how}") for lane in LANES for p in STOP_POINTS
            for how in ("cancel_signal", "store_stop") if how == "cancel_signal" or p.curator is not None]


def test_the_stop_points_cover_each_curator_before_and_after_its_commit_and_the_push():
    """The stop domain is every curator's turn either side of its commit, and the push: one more curator or point needs an entry. (Stop path)"""
    assert {len(c) for c in CURATORS.values()} == {2}
    assert [(p.curator, p.point) for p in STOP_POINTS if p.curator is not None] == [
        (0, BEFORE_COMMIT), (0, AFTER_COMMIT), (1, BEFORE_COMMIT), (1, AFTER_COMMIT)]
    assert [p.name for p in STOP_POINTS if p.push] == ["during_the_push", "during_the_push_which_then_fails"]


def _the_takeover_abandons(w, s, batch) -> None:  # 1618-tradeoff: nothing is on the remote, so the takeover abandons the batch, the attempt counted
    assert w.t.server.pushes == ["refused"], "premise: the one push the remote saw was refused"
    assert s.batches()[batch.id].outcome == "abandoned", "the takeover delivered what only the stopped holder had"
    assert s.branch_tip_on_remote(batch.branch) is None
    assert all(i.attempts >= 1 for i in s.items().values()), "the stopped attempt was forgiven"
    assert [pr["head"]["ref"] for pr in s.open_prs()] != [batch.branch]


@pytest.mark.parametrize(("lane", "stop", "how"), _stop_cases())
def test_a_stop_anywhere_in_a_claim_runs_no_further_curator_commit_or_pr_and_leaves_the_batch_expired_or_abandoned(
        world, caplog, lane, stop, how):  # noqa: F811 — the imported fixture
    """A stop inside any curator, after a commit, or in the push (also a failing one): nothing more is authored, committed or opened; with commits the lease is expired and the next tick delivers once, without any commits the batch is abandoned and the lane free. (Stop path)"""
    from defender.learning_store import Stop
    from defender.tests.support.learning.core._feedback1278 import ONE_ITEM

    w = world
    s = Scene(w, lane)
    s.seed()
    cast = Cast(s)
    mp = pytest.MonkeyPatch()
    signalled = how == "cancel_signal"
    if stop.curator is not None:
        name = CURATORS[lane][stop.curator]
        cast.hooks[(name, stop.point)] = ask_for_stop_and_wait(w) if signalled else raise_in(lambda: Stop("injected stop"))
        spy = PushSpy(cast, mp)
    else:
        first = ask_for_stop_and_wait(w)
        spy = PushSpy(cast, mp, before=lambda n: first(None) if n == 1 else None)
        if stop.push_fails:  # 1618: the stop path's push is refused by the remote (nothing lands), no longer by a spy
            without_clone(w.t)
            w.t.server.fail_push("refuse", times=1)
    try:
        if signalled:
            child = s.run_in_child(cast, "stop")
            child.wait(seconds=STOP_BOUND)
        else:
            s.run(cast)
    finally:
        mp.undo()

    [batch] = s.batches().values()
    names = CURATORS[lane]
    assert cast.started() == list(names[:stop.started]), \
        f"curators ran past the stop: {cast.started()} ({critical_text(caplog)})"
    assert len(cast.commits()) == stop.commits, "a commit was made past the stop, or the stop came before one it should not"
    assert s.open_prs() == [], "a stopped claim opened a PR"
    if stop.commits == 0:
        assert (batch.phase, batch.outcome) == ("ended", "abandoned")
        assert [e for e in cast.events() if e.startswith("push")] == [], "a stopped claim with no commits pushed"
        assert s.branch_tip_on_remote(batch.branch) is None
        assert {i.status for i in s.items().values()} == {"waiting"}, "a stopped claim's items did not go back to waiting"
        if signalled:
            assert {i.attempts for i in s.items().values()} == {0}, "a stop cost the items an attempt"
        assert call(w.dsn, "claim", w.t.tenant_id, lane, owner="next-host", thresholds=ONE_ITEM) is not None
        return
    assert (batch.phase, batch.outcome) == ("working", None)
    assert lease_seconds_left(w.dsn, batch.id) <= 0, "a stopped holder with commits kept its lease"
    assert [r.commit for r in call(w.dsn, "commit_record", w.t.tenant_id)] == cast.commits()
    if signalled:
        pushed = s.branch_tip_on_remote(batch.branch)
        assert pushed == (None if stop.push_fails else cast.commits()[-1]), \
            "the stop path's push is the claim's commits, once, or nothing when it fails"
        assert spy.timeouts()[-1] <= STOP_PUSH_BUDGET, "the stop path's push is not bounded by the stop budget"
    w.monkeypatch.setenv(RENEW_ENV, "600")
    again = Cast(s, tag='-again')
    s.run(again)
    if stop.push_fails:
        _the_takeover_abandons(w, s, batch)
        return
    assert again.started() == [], "the takeover ran a curator again"
    [pr] = s.open_prs()
    after = s.only_batch()
    assert (after.phase, after.pr_number, pr["head"]["ref"]) == ("in_review", pr["number"], batch.branch)
    assert s.branch_tip_on_remote(batch.branch) == cast.commits()[-1]


def test_a_cancel_the_tick_itself_reads_before_its_pr_is_a_clean_stop_whose_push_the_renewer_does_not_interrupt(
        world, capfd):  # noqa: F811 — the imported fixture
    """The cancel lands during the claim's own push, so the tick's renewal after it usually reads the stop itself. Its
    stop path expires the lease and pushes for longer than a renewal interval: the renewer, halted first, does not find
    its lease gone and signal a lost lease into that push. (Should the renewer read the cancel first, the tick ends by
    its signalled stop instead, which this also accepts.) (finding 3 of the #1476 review)"""
    w = world
    s = Scene(w, AUTHOR_LANE)
    s.seed()
    cast = Cast(s)
    mp = pytest.MonkeyPatch()

    def before(number: int) -> None:
        if number == 1:
            call(w.dsn, "request_cancel", w.t.tenant_id)
        else:
            time.sleep(1.0)  # the stop path's push outlasts several renewals (0.2 s in the child)

    PushSpy(cast, mp, before=before)
    try:
        child = s.run_in_child(cast, "self-read-stop")
        ended = child.wait(seconds=STOP_BOUND)
    finally:
        mp.undo()

    err = capfd.readouterr().err
    assert "stopping the tick (lease)" not in err, f"the renewer signalled a lost lease into the stop path: {err}"
    assert ended in ({"rc": 0}, {"raised": "TickStopped"}), f"the tick crashed: {ended}"
    [batch] = s.batches().values()
    assert (batch.phase, s.open_prs()) == ("working", [])
    assert s.branch_tip_on_remote(batch.branch) == cast.commits()[-1]


def test_a_stopped_claims_push_that_hangs_is_cut_off_inside_the_stop_budget(world, caplog):  # noqa: F811 — the imported fixture
    """The origin never answers the stopped claim's push: the tick still ends within the stop budget, with the lease expired and the commits on the local branch for a takeover. (Stop budget, G-C7)"""
    from defender.learning.core import store_tick

    w = world
    s = Scene(w, AUTHOR_LANE)
    s.seed()
    w.monkeypatch.setattr(store_tick, "STOP_PUSH_SECONDS", 2.0)
    hang_pushes(w.t.remote, seconds=25)
    cast = Cast(s, hooks={(CURATORS[AUTHOR_LANE][0], AFTER_COMMIT): ask_for_stop_and_wait(w)})
    started = time.monotonic()
    child = s.run_in_child(cast, "hang")
    child.wait(seconds=12.0)
    took = time.monotonic() - started

    [batch] = s.batches().values()
    assert took < 12.0
    assert (batch.phase, len(cast.commits())) == ("working", 1), critical_text(caplog)
    assert lease_seconds_left(w.dsn, batch.id) <= 0
    assert s.branch_tip_on_remote(batch.branch) is None, "premise: the push never finished"
    assert s.open_prs() == []


@pytest.mark.parametrize("lane", LANES)
def test_1618_k10_a_stop_whose_budgeted_push_is_refused_loses_the_batch_and_the_takeover_abandons_it(world, caplog, lane):  # 1618-tradeoff  # noqa: F811 — the imported fixture
    """A deploy stop after a commit whose stop-path push is refused leaves nothing on the remote: the takeover abandons the batch (attempt counted) rather than deliver from a disk. (K10)"""
    w = world
    without_clone(w.t)
    s = Scene(w, lane)
    s.seed()
    cast = Cast(s, hooks={(CURATORS[lane][0], AFTER_COMMIT): ask_for_stop_and_wait(w)})
    w.t.server.fail_push("refuse", times=1)

    child = s.run_in_child(cast, "stop-refused")
    child.wait(seconds=STOP_BOUND)

    first = the_batch(s, caplog)
    assert w.t.server.pushes == ["refused"], "premise: the stop path pushed once and was refused"
    assert len(cast.commits()) == 1, critical_text(caplog)
    assert s.branch_tip_on_remote(first.branch) is None
    w.monkeypatch.setenv(RENEW_ENV, "600")
    again = Cast(s, tag="-again")

    s.run(again)

    rows = s.batches()
    assert (rows[first.id].phase, rows[first.id].outcome) == ("ended", "abandoned"), critical_text(caplog)
    assert s.branch_tip_on_remote(first.branch) is None
    assert {i.attempts for i in s.items().values()} == {2}, "the stopped attempt was forgiven"
    assert [pr["head"]["ref"] for pr in s.open_prs()] != [first.branch]
