"""#1278 the author and lead-author ticks under fault, at PR opening, and on the stop path.

Three families, each one test generated over its domain, over both lanes' real drains with the curators replaced
by `Cast` (`_tickfaults1278`): a fault the tick does not contain (family 5), the opening of a batch's one PR by a
fresh tick and by a takeover (family 6), and a stop delivered at every point of the claim (family 7). The curators
commit through the batch's own commit-maker, so the record, the branch and the push are the real ones.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


import pytest

from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    LEAD_LANE,
    call,
    lease_seconds_left,
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — fixture
)
from defender.tests.support.learning.core._tickfaults1278 import (
    AFTER_COMMIT,
    CURATORS,
    START,
    Cast,
    Scene,
    raise_in,
)
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, critical_text, without_clone
from defender.tests.tenancy.tenant_1108_p4._support import git

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

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


@dataclass(frozen=True)
class Step:
    """One step of the tick a fault is injected at: whether the claim has commits on its branch by then, and
    `arm(scene, mp)`, which returns the `(cast, box)` of the faulting tick."""

    name: str
    commits: bool
    arm: Any
    #: #1618: the fault loses the commits (they were never pushed): the takeover abandons the batch and the attempt stays counted.
    redone: bool = False


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
    """The end push is refused by the remote (403, nothing lands), on a host with no clone: re-armed through the remote's state."""
    without_clone(s.w.t)
    s.w.t.server.fail_push("refuse", times=1)
    return Cast(s), None


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
    Step("push", True, _arm_push, redone=True),  # 1618-tradeoff: the unpushed work is redone, not delivered by a takeover
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

    batch = the_batch(s, caplog)
    items = s.items()
    assert items, "premise: the lane has items"
    if step.redone:
        assert (batch.phase, batch.outcome) == ("working", None), critical_text(caplog)
        assert lease_seconds_left(w.dsn, batch.id) <= 0, "a holder whose push failed kept its lease"
        assert w.t.server.pushes == ["refused"], "premise: the remote refused the push"
        assert s.branch_tip_on_remote(batch.branch) is None, "premise: nothing landed"
        assert cast.commits(), "premise: the step is one after a commit"
        again = Cast(s, tag="-again")
        s.run(again)
        assert s.batches()[batch.id].phase == "ended"
        assert s.batches()[batch.id].outcome == "abandoned", "the takeover delivered what only the lost holder had"
        assert s.open_prs() == [] or [pr["head"]["ref"] for pr in s.open_prs()] != [batch.branch]
        if pre_attempts == "at_ceiling":
            assert {i.status for i in s.items().values()} == {"held"}, "the abandoned attempt was forgiven at the ceiling"
            assert {i.attempts for i in s.items().values()} == {before + 1}
        else:
            assert again.started(), "the abandoned batch's items were not authored again"
            assert {i.attempts for i in s.items().values()} == {before + 2}, "the abandoned attempt was forgiven"
    elif step.commits:
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
# #1618 K10: a batch's pushed work survives its process; unpushed work is redone (no clone on the host)
# =====================================================================================================================


def the_batch(s, caplog):
    """The one batch the lane's first tick made: a named premise, so a tick that made none (or two) fails here, not in an unpack."""
    rows = list(s.batches().values())
    assert len(rows) == 1, f"premise: the tick made {len(rows)} batches, not one ({critical_text(caplog)})"
    return rows[0]


def _author_scene(w, lane=AUTHOR_LANE):
    """`lane` seeded for both its curators, over a host with no clone."""
    without_clone(w.t)
    s = Scene(w, lane)
    s.seed()
    return s


def test_1618_k10_an_end_push_that_succeeds_leaves_every_commit_of_the_batch_on_the_remote_and_in_the_record(world, caplog):  # noqa: F811 — the imported fixture
    """The end push puts the batch's every commit on the remote branch, each one in the commit record, and the PR opens. (K10)"""
    w = world
    s = _author_scene(w)
    cast = Cast(s)

    s.run(cast)

    batch = the_batch(s, caplog)
    assert len(cast.commits()) == 2, f"premise: two curators committed ({critical_text(caplog)})"
    on_remote = git(w.t.remote, "rev-list", "--reverse", f"{batch.base}..refs/heads/{batch.branch}").split()
    assert on_remote == cast.commits()
    assert [r.commit for r in call(w.dsn, "commit_record", w.t.tenant_id)] == on_remote
    assert w.t.server.pushes == ["landed"]
    assert [pr["head"]["ref"] for pr in s.open_prs()] == [batch.branch]


def _scene_on_a_fresh_data_root(w, s):
    """`s`'s lane on another host: a new data root holding only the tenant's placed folder (clone and exports removed), the same database,
    forge and remote. Nothing of the first tick's disk is reachable from it."""
    import dataclasses
    from types import SimpleNamespace

    from defender.learning.core.config import LoopPaths
    from defender.tests.support.tenancy import _tenants1106 as tenants
    from defender.tests.support.jobs._short_root import short_root
    from defender.tests.support.shared.contracts._data_root_1078 import DATA_ROOT_ENV

    other = short_root()
    assert other != w.t.data_root, "premise: another data root"
    assert not list(other.iterdir()), "premise: a fresh empty data root"
    tenants.place_tenant(other, w.t.tenant_id)
    t2 = dataclasses.replace(w.t, data_root=other, tenant=tenants.accept(other, w.t.tenant_id))
    fields = {f.name for f in dataclasses.fields(w.t)}
    for key, value in vars(w.t).items():  # the case's recorded wiring (`bind_forge`, carried values), not disk
        if key not in fields:
            object.__setattr__(t2, key, value)
    without_clone(t2)
    w.monkeypatch.setenv(DATA_ROOT_ENV, str(other))
    paths = t2.tenant.learning_paths(LoopPaths, repo_root=w.paths.repo_root)
    assert K.tenant_root(t2) != K.tenant_root(w.t)
    return Scene(SimpleNamespace(**{**vars(w), "t": t2, "paths": paths}), s.lane)


@pytest.mark.parametrize("elsewhere", [False, True], ids=["same-host", "other-host-sharing-no-disk"])
def test_1618_k10_an_end_push_that_landed_but_lost_its_reply_is_delivered_by_a_takeover_that_reads_only_the_remote(world, caplog, elsewhere):  # noqa: F811 — the imported fixture
    """The push lands and its reply is lost: the next tick, even on a host holding nothing of the first, opens the PR for the remote's commits and runs no curator. (K10)"""
    w = world
    s = _author_scene(w)
    cast = Cast(s)
    w.t.server.fail_push("lose_reply", times=1)

    s.run(cast)

    batch = the_batch(s, caplog)
    assert w.t.server.pushes == ["landed-reply-lost"], "premise: the push landed and its reply was lost"
    assert s.branch_tip_on_remote(batch.branch) == cast.commits()[-1]
    assert (batch.phase, s.open_prs()) == ("working", []), critical_text(caplog)
    assert lease_seconds_left(w.dsn, batch.id) <= 0
    again = Cast(s, tag="-again")
    runner = s
    if elsewhere:  # a replacement host: a fresh empty data root of its own, only the database and the forge are shared
        runner = _scene_on_a_fresh_data_root(w, s)

    runner.run(again)

    assert again.started() == [], "the takeover ran a curator again"
    [pr] = s.open_prs()
    after = s.only_batch()
    assert (after.phase, after.pr_number, pr["head"]["ref"]) == ("in_review", pr["number"], batch.branch)
    assert s.branch_tip_on_remote(batch.branch) == cast.commits()[-1]
    assert [r.commit for r in call(w.dsn, "commit_record", w.t.tenant_id)] == cast.commits()


@pytest.mark.parametrize("lane", LANES)
def test_1618_k10_an_end_push_the_remote_refused_leaves_nothing_to_deliver_and_the_takeover_abandons_the_batch(world, caplog, lane):  # 1618-tradeoff  # noqa: F811 — the imported fixture
    """A refused end push lands nothing: the takeover abandons that batch (attempt counted, nothing opened for it) and its items are authored again. (K10)"""
    w = world
    s = _author_scene(w, lane)
    cast = Cast(s)
    w.t.server.fail_push("refuse", times=1)

    s.run(cast)

    first = the_batch(s, caplog)
    assert w.t.server.pushes == ["refused"], "premise: the push was refused"
    assert s.branch_tip_on_remote(first.branch) is None
    assert len(cast.commits()) == 2, f"premise: the batch had commits ({critical_text(caplog)})"
    again = Cast(s, tag="-again")

    s.run(again)

    rows = s.batches()
    assert (rows[first.id].phase, rows[first.id].outcome) == ("ended", "abandoned"), "the takeover delivered what only the lost host held"
    assert s.branch_tip_on_remote(first.branch) is None
    [fresh] = [b for b in rows.values() if b.id != first.id]
    assert again.started(), "the abandoned batch's items were not authored again"
    assert [pr["head"]["ref"] for pr in s.open_prs()] == [fresh.branch]
    assert {i.attempts for i in s.items().values()} == {2}, "the abandoned attempt was forgiven"
