"""#1278 the author and lead-author ticks at PR opening: a batch's one PR, opened by a fresh tick or a takeover (family
6). Split from `test_1278_tick_faults.py` (one file's CI cost), whose helpers these cases use.
"""
from __future__ import annotations

from typing import Any

import pytest

from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    lapse_lease,
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — fixture
)
from defender.tests.support.learning.core._tickfaults1278 import (
    AFTER_COMMIT,
    CURATORS,
    Cast,
    Scene,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import critical_text

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

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
