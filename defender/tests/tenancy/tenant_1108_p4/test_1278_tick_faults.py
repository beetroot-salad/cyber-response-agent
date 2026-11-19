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
    PushSpy,
    Scene,
    raise_in,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, critical_text

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
