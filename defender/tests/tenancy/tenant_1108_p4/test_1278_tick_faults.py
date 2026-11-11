"""#1278 the author and lead-author ticks under fault, at PR opening, and on the stop path.

Three families, each one test generated over its domain, over both lanes' real drains with the curators replaced
by `Cast` (`_tickfaults1278`): a fault the tick does not contain (family 5), the opening of a batch's one PR by a
fresh tick and by a takeover (family 6), and a stop delivered at every point of the claim (family 7). The curators
commit through the batch's own commit-maker, so the record, the branch and the push are the real ones.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import pytest

from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    LEAD_LANE,
    RENEW_ENV,
    call,
    lapse_lease,
    lease_seconds_left,
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — fixture
)
from defender.tests.support.learning.core._tickfaults1278 import (
    AFTER_COMMIT,
    BEFORE_COMMIT,
    CURATORS,
    START,
    Cast,
    PushSpy,
    Scene,
    ask_for_stop_and_wait,
    hang_pushes,
    raise_in,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, critical_text

pytestmark = pytest.mark.postgres

LANES = (AUTHOR_LANE, LEAD_LANE)


# =====================================================================================================================
# Family 5: a fault the tick does not contain
# =====================================================================================================================


class RefusingBox(BoxSpy):
    """The batch's box: refuses to start, or fails to stop."""

    def __init__(self, *, start: bool = False, stop: bool = False) -> None:
        super().__init__()
        self.fail_start, self.fail_stop = start, stop

    def start(self, request: Any, **kw: Any) -> Any:
        if self.fail_start:
            raise RuntimeError("injected: the box would not start")
        return super().start(request, **kw)

    def stop(self, box: Any, **kw: Any) -> None:
        if self.fail_stop:
            raise RuntimeError("injected: the box would not stop")
        super().stop(box, **kw)


def _boom(where: str):
    def make() -> BaseException:
        return RuntimeError(f"injected: {where}")
    return make


@dataclass(frozen=True)
class Step:
    """One step of the tick a fault is injected at: whether the claim has commits on its branch by then, and
    `arm(scene, mp)`, which returns the `(cast, box)` of the faulting tick."""

    name: str
    commits: bool
    arm: Any


def _arm_start_batch(s: Scene, mp: pytest.MonkeyPatch):
    from defender.learning.author.version_control import TenantDelivery

    def refuse(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("injected: the batch could not start")
    mp.setattr(TenantDelivery, "start_batch", refuse)
    return Cast(s), None


def _arm_start_box(s: Scene, mp: pytest.MonkeyPatch):
    return Cast(s), RefusingBox(start=True)


def _arm_curator_halts_first(s: Scene, mp: pytest.MonkeyPatch):
    from defender.box import BoxFault

    first = CURATORS[s.lane][0]
    return Cast(s, hooks={(first, START): raise_in(lambda: BoxFault("injected: the curator's box failed"))}), None


def _arm_curator_halts_after_commit(s: Scene, mp: pytest.MonkeyPatch):
    from defender.box import BoxFault

    first = CURATORS[s.lane][0]
    return Cast(s, hooks={(first, AFTER_COMMIT): raise_in(lambda: BoxFault("injected: the box failed"))}), None


def _arm_stop_box_no_commits(s: Scene, mp: pytest.MonkeyPatch):
    return Cast(s, commit=()), RefusingBox(stop=True)


def _arm_stop_box_with_commits(s: Scene, mp: pytest.MonkeyPatch):
    return Cast(s), RefusingBox(stop=True)


def _arm_push(s: Scene, mp: pytest.MonkeyPatch):
    cast = Cast(s)
    PushSpy(cast, mp, fail_from=1, error=_boom("the push"))
    return cast, None


def _arm_open_pr(s: Scene, mp: pytest.MonkeyPatch):
    from defender.learning.author.version_control import store_delivery

    def refuse(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("injected: the PR open")
    mp.setattr(store_delivery, "open_pr_on", refuse)
    return Cast(s), None


def _arm_commit_record_read(s: Scene, mp: pytest.MonkeyPatch):
    """The commit record read once the branch is pushed (the tick's own first read, at its start, is the real one)."""
    from defender.learning.author.version_control import store_delivery

    real, reads = store_delivery.StoreRecord.of, []

    def of(cls: Any, *args: Any, **kw: Any) -> Any:
        reads.append(1)
        if len(reads) > 1:
            raise RuntimeError("injected: the record read")
        return real(*args, **kw)
    mp.setattr(store_delivery.StoreRecord, "of", classmethod(of))
    return Cast(s), None


STEPS = (
    Step("start_batch", False, _arm_start_batch),
    Step("start_box", False, _arm_start_box),
    Step("curator_halts_before_its_commit", False, _arm_curator_halts_first),
    Step("stop_box_after_a_batch_with_no_commit", False, _arm_stop_box_no_commits),
    Step("curator_halts_after_its_commit", True, _arm_curator_halts_after_commit),
    Step("stop_box_after_a_batch_with_commits", True, _arm_stop_box_with_commits),
    Step("push", True, _arm_push),
    Step("record_read_before_the_pr", True, _arm_commit_record_read),
    Step("pr_open", True, _arm_open_pr),
)


def _ceiling() -> int:
    from defender.learning.core.config import author_max_attempts

    return author_max_attempts()


def test_the_step_table_names_each_step_of_the_claims_life_once():
    """The fault domain is the claim's steps, each once: a step added with no entry is a failure here. (Uncontained fault)"""
    assert [s.name for s in STEPS] == [
        "start_batch", "start_box", "curator_halts_before_its_commit", "stop_box_after_a_batch_with_no_commit",
        "curator_halts_after_its_commit", "stop_box_after_a_batch_with_commits", "push", "record_read_before_the_pr",
        "pr_open"]
    assert {s.commits for s in STEPS} == {True, False}


@pytest.mark.parametrize("pre_attempts", ["below_ceiling", "at_ceiling"])
@pytest.mark.parametrize("step", STEPS, ids=lambda s: s.name)
@pytest.mark.parametrize("lane", LANES)
def test_a_fault_the_tick_does_not_contain_leaves_the_batch_to_a_takeover_with_commits_and_ends_it_without(
        world, caplog, lane, step, pre_attempts):  # noqa: F811 — the imported fixture
    """A fault at any step: with commits the lease is expired, the batch left, no curator rerun, one PR next tick; without, the batch ends, the attempt is charged, an item at the ceiling is held, never dead. (Uncontained fault)"""
    w = world
    s = Scene(w, lane)
    s.seed()
    ceiling = _ceiling()
    before = 0 if pre_attempts == "below_ceiling" else ceiling - 1
    s.set_attempts(before)
    mp = pytest.MonkeyPatch()
    try:
        cast, box = step.arm(s, mp)
        s.run(cast, box)
    finally:
        mp.undo()

    [batch] = s.batches().values()
    items = s.items()
    assert items, "premise: the lane has items"
    if step.commits:
        assert (batch.phase, batch.outcome) == ("working", None), critical_text(caplog)
        assert lease_seconds_left(w.dsn, batch.id) <= 0, "a crashed holder with commits kept its lease"
        assert [r.commit for r in call(w.dsn, "commit_record", w.t.tenant_id)] == cast.commits()
        assert cast.commits(), "premise: the step is one after a commit"
        assert {i.status for i in items.values()} == {"in_batch"}
        assert {i.attempts for i in items.values()} == {before + 1}
        assert s.open_prs() == []
        again = Cast(s, tag='-again')
        rc = s.run(again)
        assert again.started() == [], f"the takeover ran a curator again (rc {rc})"
        [pr] = s.open_prs()
        after = s.only_batch()
        assert (after.phase, after.pr_number, pr["head"]["ref"]) == ("in_review", pr["number"], batch.branch)
    else:
        assert (batch.phase, batch.outcome) == ("ended", "abandoned"), critical_text(caplog)
        assert cast.commits() == []
        assert {i.attempts for i in items.values()} == {before + 1}, "the faulted attempt was not charged"
        if pre_attempts == "at_ceiling":
            assert {i.status for i in items.values()} == {"held"}, "an item at the ceiling is held for a person, never dead"
            assert all(i.reason for i in items.values())
        else:
            assert {i.status for i in items.values()} == {"waiting"}
        assert s.open_prs() == []


# =====================================================================================================================
# Family 6: opening a batch's one PR
# =====================================================================================================================

PR_NUMBER = 90
PR_STATES = ("none", "open", "closed", "merged")
OPENING_PATHS = ("fresh_tick", "takeover")
BATCH_KINDS = ("plain", "replacement")


def _pr_on_forge(branch: str, state: str) -> dict[str, Any]:
    """The row a PR of `branch` in `state` has on the forge."""
    from defender.tests.tenancy.tenant_1108_delivery._support import pr_row

    return pr_row(PR_NUMBER, branch, state="closed" if state in ("closed", "merged") else "open", merged=state == "merged")


def _replacement_due(s: Scene) -> tuple[str, int]:
    """f1 and q1 authored and in review, closed by a person who left words, and ended by the reconcile: the
    next claim is their replacement. `(old batch id, old PR number)`."""
    from defender.tests.support.learning.core._feedback1278 import end_closed_by_hand
    from defender.tests.tenancy.tenant_1108_delivery._support import close_on_remote, comment_row

    w = s.w
    first = Cast(s)
    s.run(first)
    [pr] = s.open_prs()
    old = s.only_batch()
    w.t.forge.comments[pr["number"]] = [comment_row(501, "analyst", "cite the alert rule, not the host")]
    close_on_remote(w.t.p3, pr["head"]["ref"])
    end_closed_by_hand(type("S", (), {"dsn": w.dsn, "t": w.t})(), old.id)
    return old.id, pr["number"]


@pytest.mark.parametrize("kind", BATCH_KINDS)
@pytest.mark.parametrize("state", PR_STATES)
@pytest.mark.parametrize("path", OPENING_PATHS)
def test_a_batch_gets_one_pr_whichever_tick_opens_it_and_whatever_the_forge_already_holds_for_its_branch(
        world, caplog, path, state, kind):  # noqa: F811 — the imported fixture
    """Fresh tick or takeover, plain or replacement, with no PR, or an open, closed or merged one already on its branch: one PR, a found one recorded and never opened again, a new replacement PR links the old. (Opening a PR)"""
    w = world
    w.t.forge.scopes = {"write:repository", "read:issue"}
    s = Scene(w, AUTHOR_LANE)
    s.seed()
    old_id = old_number = None
    if kind == "replacement":
        old_id, old_number = _replacement_due(s)
    target = None

    def target_batch() -> Any:
        [b] = [b for b in s.batches().values() if b.id != old_id]
        return b

    if path == "fresh_tick":
        hooks = {}
        if state != "none":
            hooks[(CURATORS[AUTHOR_LANE][0], AFTER_COMMIT)] = lambda batch: w.t.forge.add_pr(_pr_on_forge(batch.branch, state))
        w.t.forge.requests.clear()
        cast = Cast(s, hooks=hooks)
        s.run(cast)
        assert cast.started(), critical_text(caplog)
    else:
        w.t.forge.fail_create = True
        cast = Cast(s)
        s.run(cast)
        w.t.forge.fail_create = False
        assert cast.started(), critical_text(caplog)
        target = target_batch()
        assert (target.phase, target.pr_number) == ("working", None), "premise: pushed, PR open failed"
        if state != "none":
            w.t.forge.add_pr(_pr_on_forge(target.branch, state))
        lapse_lease(w.dsn, target.id)
        w.t.forge.requests.clear()
        again = Cast(s, tag='-again')
        s.run(again)
        assert again.started() == [], "a takeover only finishes delivery: no curator runs"

    target = target_batch()
    ours = [r for r in w.t.forge.prs if r["head"]["ref"] == target.branch]
    posts = [c for c in w.t.forge.creates if c["head"] == target.branch]
    assert len(ours) == 1, f"{len(ours)} PRs on the branch: {[(r['number'], r['state']) for r in ours]}"
    assert len(posts) == (1 if state == "none" else 0), "a PR was opened though the forge held one for the branch"
    assert (target.phase, target.pr_number) == ("in_review", ours[0]["number"]), critical_text(caplog)
    if state != "none":
        assert target.pr_number == PR_NUMBER
    if kind == "replacement":
        assert target.replaces == old_id
        if state == "none":
            assert f"#{old_number}" in posts[0].get("body", ""), "the replacement's PR does not link the PR it replaces"
    if state in ("none", "open"):
        w.t.forge.requests.clear()
        s.run(Cast(s, tag='-later'))
        assert len([r for r in w.t.forge.prs if r["head"]["ref"] == target.branch]) == 1, "a later tick opened a second PR"


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
    StopPoint("during_the_push_which_then_fails", 2, 2, push=True, push_fails=True),
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


@pytest.mark.parametrize(("lane", "stop", "how"), _stop_cases())
def test_a_stop_anywhere_in_a_claim_runs_no_further_curator_commit_or_pr_and_leaves_the_batch_expired_or_abandoned(
        world, caplog, lane, stop, how):  # noqa: F811 — the imported fixture
    """A stop inside any curator, after a commit, or in the push (also a failing one): nothing more is authored, committed or opened; with commits the lease is expired and the next tick delivers once, without any commits the batch is abandoned and the lane free. (Stop path)"""
    from defender.learning.store import Stop
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
        spy = PushSpy(cast, mp, before=lambda n: first(None) if n == 1 else None,
                      fail_from=2 if stop.push_fails else None)
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
    assert again.started() == [], "the takeover ran a curator again"
    [pr] = s.open_prs()
    after = s.only_batch()
    assert (after.phase, after.pr_number, pr["head"]["ref"]) == ("in_review", pr["number"], batch.branch)
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
