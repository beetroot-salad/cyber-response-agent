"""#1278 the author tick over the learning store, through the real drain entry.

Every case drives `author_drain` through the CLI's stage runner over `p4_tenant` (a real clone, a
loopback origin, P3's forge fake), with the store at `DEFENDER_DATABASE_DSN` on a migrated database
holding the tenant's row. Work is seeded and observed through the store's verbs; the curator is
`LessonWriter`, which commits through the batch's own commit-maker. Forge state is changed as a person
would. A stop is delivered to a forked child running the post-step, never to the pytest worker.
Reconcile and feedback are in the feedback slice's files.
"""
from __future__ import annotations

import contextlib
import importlib
import signal
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    LEAD_LANE,
    ONE,
    RENEW_ENV,
    LessonWriter,
    TickChild,
    await_file,
    batches,
    blocked_in_subprocess,
    call,
    files_under,
    finding,
    foreign_commit_on,
    kill_if_alive,
    lapse_lease,
    lease_seconds_left,
    lesson_citing,
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — fixture
)
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.tenancy.tenant_1108_delivery._support import pr_row
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSON_NAME,
    BoxSpy,
    author_drain,
    critical_text,
    drafts_dir,
    lead_author_drain,
    own_store,
    remote_branches,
    without_clone,
)
from defender.tests.tenancy.knowledge_1618 import _repos_1618 as R
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_p4._support import git

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)


def _seed(w, *fids):
    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", [finding(f) for f in fids], kind="finding")


def _tick(w, writer):
    return author_drain(w.t, w.paths, trigger=writer, box=BoxSpy())


def _work(w):
    """The tenant's items by `(kind, key)`: a key alone is not an item's identity."""
    return {(i.kind, i.key): i for i in call(w.dsn, "work", w.t.tenant_id)}


def _batches(w):
    return {b.id: b for b in batches(w.dsn, w.t.tenant_id)}


def _record(w):
    return call(w.dsn, "commit_record", w.t.tenant_id)


def _opened(w, writer, caplog):
    """One tick that authors f1's lesson and opens its PR: `(batch id, branch, PR number)`."""
    rc = _tick(w, writer)
    assert writer.served, f"the tick served no batch (rc {rc}): {critical_text(caplog)}"
    [(branch, _tip)] = remote_branches(w.t.remote).items()
    [pr] = [r for r in w.t.forge.prs if r["head"]["ref"] == branch]
    return writer.served[-1], branch, pr["number"]


def _stranded(w, caplog):
    """A tick whose push succeeded and whose PR open failed: `(writer, batch id, branch)`, the batch working
    and its lease still live."""
    _seed(w, "f1")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    w.t.forge.fail_create = True
    _tick(w, writer)
    assert writer.served, critical_text(caplog)
    [(branch, _tip)] = remote_branches(w.t.remote).items()
    w.t.forge.fail_create = False
    assert [r for r in w.t.forge.prs if r["state"] == "open"] == []
    [batch_id] = _batches(w)
    return writer, batch_id, branch


def test_o10_nothing_named_learning_exists_under_the_tenant_folder_after_a_tick_of_each_lane(world, caplog):  # noqa: F811 — the imported fixture
    """Host prepare makes no `<T>/learning` and neither the author tick (which opens a PR) nor the lead tick creates one
    anywhere under the tenant folder. (O10, D10)"""
    w = world
    folder = Path(location_path(w.t.tenant.tenant_root))
    named = lambda: sorted(p.relative_to(folder).as_posix() for p in folder.rglob("learning"))  # noqa: E731
    assert named() == [], "premise: the prepared tenant folder has no learning entry"
    _seed(w, "f1")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    _opened(w, writer, caplog)  # the author lane's tick: claims, commits, pushes, opens its PR
    assert named() == [], "the author tick created a learning entry"
    assert lead_author_drain(w.t, w.paths, box=BoxSpy()) == 0  # the lead lane's tick, and the reconcile every tick does
    assert named() == [], "the lead tick created a learning entry"


# --- P2', O3, D5: the row before the commit; a lapsed holder commits nothing ----------------------------------


def test_p2_the_batch_row_and_its_items_exist_before_the_first_commit_and_its_pr_puts_it_in_review(world, caplog):  # noqa: F811 — the imported fixture
    """At the curator's commit the batch is a working row holding f1, nothing pushed; after, in_review with its PR. (P2', O3, O10)"""
    w = world
    _seed(w, "f1")
    learning = Path(location_path(w.t.tenant.tenant_root)) / "learning"
    before = files_under(learning)
    seen = {}

    def observe(_batch):
        seen.update(work=_work(w), batches=_batches(w), branches=remote_branches(w.t.remote),
                    creates=list(w.t.forge.creates))

    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")}, before_commit=observe)
    batch_id, _branch, number = _opened(w, writer, caplog)

    assert [(b.id, b.phase) for b in seen["batches"].values()] == [(batch_id, "working")]
    assert (seen["work"][("finding", "f1")].status, seen["work"][("finding", "f1")].batch_id) == ("in_batch", batch_id)
    assert (seen["branches"], seen["creates"]) == ({}, [])
    after = _batches(w)[batch_id]
    assert (after.phase, after.pr_number) == ("in_review", number)
    assert _work(w)[("finding", "f1")].status == "in_batch", "a finding stays in its batch until its lesson merges"
    # O10: a tick that claimed, committed and delivered wrote nothing under the learning state root.
    assert files_under(learning) == before


def test_d5_the_branch_is_set_at_claim_base_and_start_with_the_first_commit_and_the_record_is_in_the_database(world, caplog):  # noqa: F811 — the imported fixture
    """Branch set before the commit and the one pushed; base and start appear with the first commit row; the rows are in the database. (D5, P2')"""
    w = world
    _seed(w, "f1")
    base = w.t.origin_main()
    seen = {}

    def before(_batch):
        [b] = _batches(w).values()
        seen["before"] = (b.branch, b.base, _record(w))

    def after(_batch):
        [b] = _batches(w).values()
        seen["after"] = (b.branch, b.base, _record(w))

    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")}, before_commit=before, after_commit=after)
    batch_id, branch, _number = _opened(w, writer, caplog)

    assert seen["before"][0] == branch
    assert seen["before"][1:] == (None, [])
    assert seen["after"][:2] == (branch, base)
    [row] = _record(w)
    assert (row.commit, row.branch, row.base, str(row.batch_id)) == (writer.commits[0], branch, base, str(batch_id))
    assert row.start
    assert not row.reverts
    assert [c[0] for c in row.changes] == [f"agent/lessons/{LESSON_NAME}"]
    assert dict(remote_branches(w.t.remote))[branch] == writer.commits[0]
    assert git(w.t.remote, "show", "--name-only", "--format=", writer.commits[0]).split() == [f"agent/lessons/{LESSON_NAME}"], \
        "raw findings (or anything but the lesson) went into Git (H1)"


def test_o3_a_holder_whose_lease_lapsed_makes_no_commit_and_changes_no_item(world, caplog):  # noqa: F811 — the imported fixture
    """The lease lapses between the curator's write and its commit: no commit, no branch, the row unchanged. (O3, P6)"""
    w = world
    _seed(w, "f1")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")},
                          before_commit=lambda batch: lapse_lease(w.dsn, batch.id))
    _tick(w, writer)

    assert writer.served, critical_text(caplog)
    assert writer.commits == []
    assert remote_branches(w.t.remote) == {}
    # #1618: the tick's private repository (where an unpushed commit could live) is gone with the tick.
    assert K.repo_scratch(w.t) == []
    assert _record(w) == []
    [batch] = _batches(w).values()
    assert batch.phase == "working", "a holder past its lease cannot end its own batch"
    assert (_work(w)[("finding", "f1")].status, _work(w)[("finding", "f1")].batch_id) == ("in_batch", batch.id)


def test_o3_a_holder_that_lost_its_lease_after_committing_pushes_nothing_and_opens_no_pr(world, caplog):  # noqa: F811 — the imported fixture
    """The lease lapses past grace after the commit: no push, no PR; the next tick's takeover reads only the forge, finds
    nothing there and abandons the batch, so the unpushed work is redone. (O3, P6, Renewal and stop; #1618 D4 amended)"""
    w = world
    _seed(w, "f1")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")}, after_commit=lambda batch: lapse_lease(w.dsn, batch.id))
    _tick(w, writer)

    assert writer.served, critical_text(caplog)
    assert len(writer.commits) == 1
    assert remote_branches(w.t.remote) == {}, "a holder past its lease pushed"
    assert w.t.forge.creates == [], "a holder past its lease opened a PR"
    [batch_id] = _batches(w)
    assert _batches(w)[batch_id].phase == "working"
    assert [r.commit for r in _record(w)] == writer.commits, "the commit was recorded before the lease went"

    # #1618 (design r5 "Retired promises": `test_1278_tick::o3` "a takeover only finishes delivery"): the lost holder's
    # commit was never pushed, and a takeover reads only the remote branch (K10), so it cannot deliver it.
    _tick(w, writer)

    assert (_batches(w)[batch_id].phase, _batches(w)[batch_id].outcome) == ("ended", "abandoned"), critical_text(caplog)
    assert writer.commits[0] not in remote_branches(w.t.remote).values(), "the takeover delivered what only the lost holder had"
    assert not [r for r in w.t.forge.prs if r["state"] == "open" and r["head"]["ref"] == _batches(w)[batch_id].branch]


# --- Locks: the working-batch rule replaces the author-drain lock ------------------------------------------------


def test_locks_a_tick_finding_a_live_batch_of_another_holder_authors_nothing_and_exits_quietly(world, caplog):  # noqa: F811 — the imported fixture
    """Another holder's live working batch stands in for the drain lock: this tick returns 0, serves no curator, claims nothing. (O3, Locks)"""
    w = world
    _seed(w, "f1")
    other = call(w.dsn, "claim", w.t.tenant_id, AUTHOR_LANE, owner="other-host", thresholds=ONE)
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})

    rc = _tick(w, writer)

    assert (rc, writer.served) == (0, []), critical_text(caplog)
    assert list(_batches(w)) == [other.batch_id]
    assert w.t.forge.creates == []


def _snapshot(w):
    """Everything a tick could change in the store and on the forge, as plain values."""
    return ({k: (i.status, i.batch_id, i.attempts, i.deferrals, i.offers_declined) for k, i in _work(w).items()},
            {b.id: (b.phase, b.outcome, b.refusals, b.pr_number) for b in _batches(w).values()},
            len(_record(w)), len(w.t.forge.creates), len([r for r in w.t.forge.requests if r.method != "GET"]))


@own_store("the refusal is raised in-process at `LearningStore.claim`: the port's helper holds its own store, and the port's refusals are the conformance module's")
@pytest.mark.parametrize("lane", ["author", "lead_author"])
@pytest.mark.parametrize("refusal", ["LaneBusy", "TenantInactive"])
def test_a_claim_the_store_refuses_ends_the_tick_at_zero_with_nothing_changed(world, caplog, monkeypatch, lane, refusal):  # noqa: F811 — the imported fixture
    """`LaneBusy` or `TenantInactive` raised from the claim itself (a race lost, offboarding begun) is no tick fault: the tick returns 0, claims nothing, and the same item is claimed by the next. (O3, O6, Locks)"""
    import defender.learning_store as learning_store
    from defender.learning_store import LearningStore
    from defender.tests.support.learning.core._declared870 import shim_row
    from defender.tests.tenancy.tenant_1108_p4._drain_support import lead_author_drain

    w = world
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    if lane == "author":
        _seed(w, "f1")
        tick = lambda: _tick(w, writer)  # noqa: E731
    else:
        call(w.dsn, "add_pitfall", w.t.tenant_id, shim_row("p4-run:1"))
        tick = lambda: lead_author_drain(w.t, w.paths, box=BoxSpy(), run_lead_author=lambda *_a, **_k: None,  # noqa: E731
                                         run_pitfalls=lambda *_a, **_k: 0)
    raised = getattr(learning_store, refusal)
    real, refused = LearningStore.claim, []

    async def claim(self, *args, **kw):
        refused.append(args)
        raise raised("refused for the test")

    before = _snapshot(w)
    monkeypatch.setattr(LearningStore, "claim", claim)  # lint-monkeypatch: ok — the store refuses at the claim, the point under test; the tick opens its own store, so no seam carries one
    rc = tick()
    monkeypatch.setattr(LearningStore, "claim", real)  # lint-monkeypatch: ok — puts back the real claim after the refusing one above

    assert refused, "the tick never reached the claim, so the refusal was not what it met"
    assert (rc, writer.served) == (0, []), critical_text(caplog)
    assert critical_text(caplog) == "", "a refused claim was reported as a failure"
    assert _snapshot(w) == before

    tick()
    assert list(_batches(w)), "control: with the refusal gone the next tick claims the same work"


@pytest.mark.parametrize("revert_state", ["working", "in_review"])
def test_reverts_a_revert_that_is_running_or_open_blocks_authoring(world, caplog, revert_state):  # noqa: F811 — the imported fixture
    """A running revert, and an open revert PR, each stop a tick from authoring: the item waits, nothing is claimed. (Reverts, O3)"""
    w = world
    _seed(w, "f1")
    revert = call(w.dsn, "claim_revert", w.t.tenant_id, owner="cli")
    if revert_state == "in_review":
        call(w.dsn, "in_review", revert, pr_number=40, outcomes={})
        w.t.forge.add_pr(pr_row(40, revert.branch))
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})

    _tick(w, writer)

    assert writer.served == [], critical_text(caplog)
    assert list(_batches(w)) == [revert.batch_id]
    assert _work(w)[("finding", "f1")].status == "waiting"
    assert w.t.forge.creates == []


def test_d6_a_hand_made_pr_on_the_lessons_prefix_sends_the_batch_to_needs_person_and_opens_none(world, caplog):  # noqa: F811 — the imported fixture
    """A foreign open PR on the prefix: the tick opens no PR of its own, its batch is needs_person, its item stays in the batch. (D6, O5)"""
    w = world
    _seed(w, "f1")
    w.t.forge.add_pr(pr_row(77, "lessons/hand-made"))
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})

    _tick(w, writer)

    assert w.t.forge.creates == [], critical_text(caplog)
    [batch] = _batches(w).values()
    assert batch.phase == "needs_person", (batch.phase, critical_text(caplog))
    assert _work(w)[("finding", "f1")].status == "in_batch", "the item is not lost"
    assert [r["number"] for r in w.t.forge.prs if r["state"] == "open"] == [77]


# --- O1, O5: crash recovery -----------------------------------------------------------------------------------


def test_o1_a_pushed_branch_with_no_pr_is_taken_over_and_gets_its_one_pr(world, caplog):  # noqa: F811 — the imported fixture
    """The PR open fails after the push; once the lease lapses, the next tick opens that branch's PR, no rerun. (O1, O5, Crash recovery)"""
    w = world
    writer, batch_id, branch = _stranded(w, caplog)

    lapse_lease(w.dsn, batch_id)
    _tick(w, writer)

    assert writer.served == [batch_id], "a takeover only finishes delivery: no new authoring run"
    assert list(remote_branches(w.t.remote)) == [branch]
    [pr] = [r for r in w.t.forge.prs if r["state"] == "open"]
    assert pr["head"]["ref"] == branch
    [batch] = _batches(w).values()
    assert (batch.id, batch.phase, batch.pr_number) == (batch_id, "in_review", pr["number"])
    _tick(w, writer)
    assert len([r for r in w.t.forge.prs if r["state"] == "open"]) == 1, "a second tick opened a second PR"


#: Every way a stranded batch is recovered; each is judged lapsed by the database's clock alone (one lapse rule).
RECOVERY = {
    "tick": None,
    "take_over": lambda w, bid: call(w.dsn, "take_over", w.t.tenant_id, bid, owner="host-b"),
    "abandon_by_recovery": lambda w, bid: call(w.dsn, "abandon", w.t.tenant_id, bid, by="recovery"),
    "offboard": lambda w, bid: call(w.dsn, "offboard", w.t.tenant_id, wait=0.3),
}


@pytest.mark.parametrize("skew_hours", [0, 1, -1], ids=["host-clock-right", "host-clock-an-hour-ahead", "host-clock-an-hour-behind"])
@pytest.mark.parametrize("path", sorted(RECOVERY))
def test_o1_every_recovery_path_judges_a_lapse_by_the_databases_clock_alone(world, caplog, path, skew_hours):  # noqa: F811 — the imported fixture
    """Live or lapsed within grace the stranded batch is left alone; past grace it is recovered; a host clock off by an hour changes neither. (O1, P6, Crash recovery)"""
    from defender.tests.support.learning.core._clock1278 import host_clock_skewed
    from defender.tests.support.learning.core._store1278 import store_mod

    S = store_mod()
    w = world
    writer, batch_id, branch = _stranded(w, caplog)
    [stranded] = _batches(w).values()

    def attempt():
        with host_clock_skewed(skew_hours):
            if RECOVERY[path] is None:
                return _tick(w, writer)
            return RECOVERY[path](w, batch_id)

    def standing():
        b = _batches(w)[batch_id]
        return (b.phase, b.outcome, b.token, b.pr_number, b.lease_owner)

    for lapsed in (None, "within grace"):  # the lease live (the stranding tick ended its own), then lapsed one second ago
        if lapsed:
            lapse_lease(w.dsn, batch_id, past_grace=False)
        else:
            execute(w.dsn, "UPDATE learning.batches SET lease_expiry = now() + interval '10 minutes' WHERE id = %s", (batch_id,))
        with contextlib.suppress(S.NotLapsed, S.LaneBusy):
            attempt()
        assert standing() == ("working", None, stranded.token, None, stranded.lease_owner), (
            f"a batch {lapsed or 'with a live lease'} was recovered by {path}")
        assert [r for r in w.t.forge.prs if r["state"] == "open"] == []
        assert list(_batches(w)) == [batch_id]
        assert writer.served == [batch_id], f"{path} ran a curator again for a batch that was not lapsed"
        if lapsed:
            assert lease_seconds_left(w.dsn, batch_id) < 0, f"{path} revived a lease that had lapsed"

    lapse_lease(w.dsn, batch_id)
    attempt()

    after = _batches(w).get(batch_id)
    if path == "tick":
        [pr] = [r for r in w.t.forge.prs if r["state"] == "open"]
        assert (pr["head"]["ref"], after.phase) == (branch, "in_review")
    elif path == "take_over":
        assert (after.phase, after.token > stranded.token) == ("working", True)
    elif path == "abandon_by_recovery":
        assert (after.phase, after.outcome) == ("ended", "abandoned")
    else:
        assert after is None, "offboarding a batch lapsed past grace left its rows"


def _replacement_host(w: Any) -> None:
    """The host as a replacement one finds it (was `forget_local_branch` on the clone): no draft, and no private
    repository of an earlier tick left under `.repo-scratch/` (premise: the stranded tick closed its own)."""
    import shutil

    for draft in (drafts_dir(w.t).iterdir() if drafts_dir(w.t).is_dir() else ()):
        shutil.rmtree(draft, ignore_errors=True)
    assert K.repo_scratch(w.t) == [], "premise: the earlier tick left its private repository"


def test_o1_a_branch_only_on_the_forge_is_verified_against_the_record_and_gets_its_pr_from_a_fresh_clone(world, caplog):  # noqa: F811 — the imported fixture
    """A replacement host has no draft and no repository of the stranded tick's (#1618: every tick's repository is its own,
    so this is every takeover): the takeover fetches the tip, finds it is the recorded commit, opens the PR. (O1, D11b)"""
    w = world
    writer, batch_id, branch = _stranded(w, caplog)
    _replacement_host(w)
    assert dict(remote_branches(w.t.remote))[branch] == writer.commits[0], "premise: the branch is only on the forge"

    lapse_lease(w.dsn, batch_id)
    _tick(w, writer)

    assert writer.served == [batch_id]
    [pr] = [r for r in w.t.forge.prs if r["state"] == "open"]
    assert pr["head"]["ref"] == branch
    assert dict(remote_branches(w.t.remote))[branch] == writer.commits[0]
    assert (_batches(w)[batch_id].phase, _batches(w)[batch_id].pr_number) == ("in_review", pr["number"])


def test_o5_a_forge_tip_beyond_the_record_is_not_opened_and_goes_to_a_person(world, caplog):  # noqa: F811 — the imported fixture
    """A commit nobody of ours made sits on the batch's branch: no PR is opened, the batch is needs_person. (O5, Crash recovery)"""
    w = world
    writer, batch_id, branch = _stranded(w, caplog)
    foreign_commit_on(w.t.remote, branch, w.scratch)
    _replacement_host(w)

    lapse_lease(w.dsn, batch_id)
    _tick(w, writer)

    assert [r for r in w.t.forge.prs if r["state"] == "open"] == [], critical_text(caplog)
    assert _batches(w)[batch_id].phase == "needs_person"
    assert _work(w)[("finding", "f1")].status == "in_batch"


def test_o1_a_lapsed_batch_with_nothing_anywhere_is_abandoned_and_its_item_authored_again(world, caplog):  # noqa: F811 — the imported fixture
    """A lost host's batch with no branch and no PR ends abandoned, its attempt kept; a new batch authors the item. (O1, P3, Crash recovery)"""
    w = world
    _seed(w, "f1")
    lost = call(w.dsn, "claim", w.t.tenant_id, AUTHOR_LANE, owner="lost-host", thresholds=ONE)
    lapse_lease(w.dsn, lost.batch_id)
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    _tick(w, writer)

    rows = _batches(w)
    assert (rows[lost.batch_id].phase, rows[lost.batch_id].outcome) == ("ended", "abandoned")
    assert writer.served, critical_text(caplog)
    assert lost.batch_id not in writer.served
    [fresh] = [b for b in rows.values() if b.id != lost.batch_id]
    assert fresh.phase == "in_review"
    item = _work(w)[("finding", "f1")]
    assert (item.status, item.batch_id, item.attempts) == ("in_batch", fresh.id, 2), "the lost host's attempt is kept (crash abandon)"


# --- Renewal and stop (O3, P6): a stop reaches a step blocked in a subprocess ---------------------------------------


STOP_BOUND = 30.0


def _post_step_child(w, start, writer, *, how):
    """A forked child running the real post-step (a family-less one) over a real helper (`start()`, after this sets the
    renewal), whose tick is `author_drain` over `writer` and takes the store the post-step hands it (#1487 Amendment 1:
    the port over the child's job socket, which forwards to the helper). `how` is how the stop will be delivered: `cancel`
    sets the store's flag, `sigterm` signals the child."""
    from defender.tests.learning.branch.test_1344_post_step import post_step_in_container

    w.monkeypatch.setenv(RENEW_ENV, "0.2")
    helper = start()

    def body():
        return post_step_in_container(None, w.t.tenant_id, forward=helper.ask,
                                      author_tick=lambda _paths, *, store: author_drain(
                                          w.t, w.paths, trigger=writer, box=BoxSpy(), store=store))
    return TickChild(body, w.scratch / f"child-{how}.json")


def _stop(w, child, how):
    if how == "cancel":
        call(w.dsn, "request_cancel", w.t.tenant_id)
    else:
        child.terminate()


@own_store("no store: the post-step's tick is a sleep")
def test_control_a_sigterm_reaches_the_post_step_blocked_in_a_subprocess(world):  # noqa: F811 — the imported fixture
    """Harness control, no store: the post-step's tick blocked in `sleep` ends on SIGTERM as a KeyboardInterrupt. (Renewal and stop)"""
    from defender.tests.learning.branch.test_1344_post_step import post_step_in_container

    w = world
    marker = w.scratch / "sleeper"
    block = blocked_in_subprocess(marker)

    def body():
        return post_step_in_container(None, w.t.tenant_id,
                              author_tick=lambda _paths, **_kw: block(None) or 0)
    child = TickChild(body, w.scratch / "child-control.json")
    sleeper = int(await_file(marker))
    try:
        child.signal(signal.SIGTERM)
        assert child.wait(seconds=STOP_BOUND) == {"raised": "KeyboardInterrupt"}
    finally:
        kill_if_alive(sleeper)


@own_store("the tick is the post-step's: its store is the port over the child's job socket")
@pytest.mark.parametrize("how", ["cancel", "sigterm"])
def test_stop_a_stop_while_the_curator_is_blocked_in_a_subprocess_ends_the_tick_and_abandons_a_batch_with_no_commits(world, post_step_helper, how):  # noqa: F811 — the imported fixture
    """Cancel flag or SIGTERM while the step waits on a child process: the tick ends in time, the batch is abandoned cleanly, f1 waits, attempt forgiven, lane free. (Renewal and stop, D4, D8)"""
    w = world
    _seed(w, "f1")
    marker = w.scratch / "sleeper"
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")}, before_commit=blocked_in_subprocess(marker))
    child = _post_step_child(w, post_step_helper, writer, how=how)
    sleeper = int(await_file(marker))
    try:
        _stop(w, child, how)
        child.wait(seconds=STOP_BOUND)
    finally:
        kill_if_alive(sleeper)

    assert remote_branches(w.t.remote) == {}
    assert [r for r in w.t.forge.prs if r["state"] == "open"] == [], "a stopped tick with no commits opened a PR"
    [batch] = _batches(w).values()
    assert (batch.phase, batch.outcome) == ("ended", "abandoned")
    item = _work(w)[("finding", "f1")]
    assert (item.status, item.attempts) == ("waiting", 0), "a stop cost the item an attempt"
    assert _record(w) == []
    assert call(w.dsn, "claim", w.t.tenant_id, AUTHOR_LANE, owner="next-host", thresholds=ONE) is not None


@own_store("the tick is the post-step's: its store is the port over the child's job socket")
@pytest.mark.parametrize("how", ["cancel", "sigterm"])
def test_stop_a_stop_after_the_commit_leaves_the_batch_for_takeover_at_once_and_one_pr(world, post_step_helper, caplog, how):  # noqa: F811 — the imported fixture
    """Stopped while blocked after committing: the batch is not abandoned and its own lease is expired, so the next tick delivers it at once, within grace, with no rerun. (Renewal and stop, D4)"""
    w = world
    _seed(w, "f1")
    marker = w.scratch / "sleeper"
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")}, after_commit=blocked_in_subprocess(marker))
    child = _post_step_child(w, post_step_helper, writer, how=how)
    sleeper = int(await_file(marker))
    try:
        _stop(w, child, how)
        child.wait(seconds=STOP_BOUND)
    finally:
        kill_if_alive(sleeper)
    [batch_id] = _batches(w)
    assert _batches(w)[batch_id].phase == "working"
    assert lease_seconds_left(w.dsn, batch_id) <= 0, "a cleanly stopped holder with commits kept its lease"
    assert len(_record(w)) == 1
    assert dict(remote_branches(w.t.remote)).get(_batches(w)[batch_id].branch) == _record(w)[0].commit, \
        "a clean stop after a commit left the branch off the remote (commits on the branch, pushed with a timeout)"

    w.monkeypatch.setenv(RENEW_ENV, "600")
    again = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    _tick(w, again)

    assert again.served == [], "the takeover authored again"
    [pr] = [r for r in w.t.forge.prs if r["state"] == "open"]
    assert (_batches(w)[batch_id].phase, _batches(w)[batch_id].pr_number) == ("in_review", pr["number"])


@own_store("the tick is the post-step's: its store is the port over the child's job socket")
def test_stop_a_lease_lost_while_the_curator_is_blocked_in_a_subprocess_ends_the_tick_and_pushes_nothing(world, post_step_helper):  # noqa: F811 — the imported fixture
    """The lease lapses (by SQL) while the step waits on a child process: the renewer sees it lost, the tick ends in time, nothing is pushed, no PR opens. (P6, Renewal and stop)"""
    w = world
    _seed(w, "f1")
    marker = w.scratch / "sleeper"
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")}, after_commit=blocked_in_subprocess(marker))
    child = _post_step_child(w, post_step_helper, writer, how="lease")
    sleeper = int(await_file(marker))
    try:
        [batch_id] = _batches(w)
        lapse_lease(w.dsn, batch_id)
        child.wait(seconds=STOP_BOUND)
    finally:
        kill_if_alive(sleeper)

    assert remote_branches(w.t.remote) == {}, "a holder whose lease was lost pushed"
    assert [r for r in w.t.forge.prs if r["state"] == "open"] == []
    assert w.t.forge.creates == []
    assert _batches(w)[batch_id].phase == "working", "a holder past its lease ended its own batch"
    assert _work(w)[("finding", "f1")].status == "in_batch"


# --- Reconcile stamps the check (D7) -----------------------------------------------------------------------------


def test_d7_a_reconcile_of_an_open_pr_stamps_the_batchs_last_checked(world, caplog):  # noqa: F811 — the imported fixture
    """A tick that reconciles a batch in review whose PR is untouched moves its `last_checked` to now, unconditionally. (D7, Wake)"""
    w = world
    _seed(w, "f1")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    batch_id, _branch, _number = _opened(w, writer, caplog)
    execute(w.dsn, "UPDATE learning.batches SET last_checked = now() - interval '1 hour' WHERE id = %s", (batch_id,))
    before = _batches(w)[batch_id].last_checked

    _tick(w, writer)

    after = _batches(w)[batch_id].last_checked
    assert after is not None
    assert after - before > timedelta(minutes=30), (before, after)
    assert _batches(w)[batch_id].phase == "in_review"


# --- The lead lane: operator-only (D9) ----------------------------


def _pitfall_row(pid: str):
    from defender.tests.support.learning.core._declared870 import shim_row

    return shim_row(pid)


# Retired by amendment A3 (the lead lane is served by the drain alone; there is no by-hand lead-author entry, so no
# by-hand claim): `test_locks_a_by_hand_lead_author_run_is_refused_while_the_lead_drain_holds_a_working_batch` and its
# control `test_locks_a_by_hand_lead_author_run_with_no_lead_drain_batch_is_not_refused`. Their obligation (the lead
# lane has one holder) survives in the store's `test_o3_a_second_claim_on_a_lane_with_a_not_ended_author_batch_is_refused` and
# `test_o3_two_claims_at_once_make_one_batch`.


def test_d9_a_lead_batch_closed_with_words_stays_due_and_the_author_tick_authors_nothing_for_it(world, caplog):  # noqa: F811 — the imported fixture
    """A rejected lead PR (closed, words left) keeps its pitfall in the batch; lead replacement is operator-only, so the author tick serves no curator and opens nothing. (D9)"""
    w = world
    call(w.dsn, "add_pitfall", w.t.tenant_id, _pitfall_row("p4-run:1"))
    claim = call(w.dsn, "claim", w.t.tenant_id, LEAD_LANE, owner="lead-drain", thresholds=ONE)
    call(w.dsn, "in_review", claim, 41, {})
    call(w.dsn, "end_review", w.t.tenant_id, claim.batch_id, expect_phase="in_review", outcome="closed", published=[], held=[])
    assert _work(w)[("pitfall", "p4-run:1")].status == "in_batch", "premise: the rejected batch's item is due a replacement"
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    branches = remote_branches(w.t.remote, prefix="")  # every branch, `main` included

    _tick(w, writer)

    assert writer.served == [], critical_text(caplog)
    assert list(_batches(w)) == [claim.batch_id], "the tick claimed a replacement for a lead batch"
    assert _work(w)[("pitfall", "p4-run:1")].status == "in_batch"
    assert w.t.forge.creates == []
    assert remote_branches(w.t.remote, prefix="") == branches, "the tick pushed a branch"


# --- #1618 (tenant knowledge lives only in Forgejo): a tick opens by fetching, with no clone on the host ----------------


def test_1618_f6_a_batch_starts_from_the_main_the_tick_fetched_with_no_clone_on_the_host(world, caplog):  # noqa: F811 — the imported fixture
    """With no clone, a batch's draft and recorded base are the remote `main` the tick opened on, merged since the host last saw it. (F6, K4)"""
    w = world
    without_clone(w.t)
    _seed(w, "f1")
    opening = K.advance_main(w.t, K.MERGED_MARK)
    seen = {}
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")},
                          before_commit=lambda batch: seen.update(lesson=(Path(batch.draft_root) / K.LESSON).read_text(encoding="utf-8")))

    _batch_id, branch, _number = _opened(w, writer, caplog)

    assert seen["lesson"] == K.lesson_text(K.MERGED_MARK), "the draft is not the tick's fetched main"
    [row] = _record(w)
    assert row.base == opening
    assert git(w.t.remote, "rev-parse", f"{branch}^") == opening


def test_1618_f6_a_main_that_moves_after_the_tick_opened_is_not_the_batchs_base(world, caplog):  # noqa: F811 — the imported fixture
    """A merge landing while the curator works leaves the batch on the tip the opening fetch saw (the control: the case above reads the tip the fetch did see). (F6, K12)"""
    w = world
    without_clone(w.t)
    _seed(w, "f1")
    opening = w.t.origin_main()
    moved = {}
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")},
                          before_commit=lambda _batch: moved.setdefault("tip", K.advance_main(w.t, "K1618-LATER-MARK")))

    _batch_id, branch, _number = _opened(w, writer, caplog)

    assert moved["tip"] != opening, "premise: main moved during the tick"
    [row] = _record(w)
    assert row.base == opening
    assert git(w.t.remote, "rev-parse", f"{branch}^") == opening, "the batch was rebased on a main the tick never fetched"


def test_1618_k4_a_tick_whose_forge_cannot_be_reached_at_its_opening_fetch_claims_nothing_and_makes_no_draft(world, caplog):  # noqa: F811 — the imported fixture
    """Forgejo refusing the connection at the opening fetch skips the tick before any claim or draft: items waiting, no batch. (K4, F6)"""
    w = world
    without_clone(w.t)
    _seed(w, "f1")
    assert [i.status for i in _work(w).values()] == ["waiting"], "premise: the item is due"
    K.forge_down(w.t)
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})

    rc = _tick(w, writer)

    assert rc == 0, f"an outage is a skipped tick (a transient refusal), not a fatal one: {critical_text(caplog)}"
    assert writer.served == [], "a curator ran on knowledge the tick could not fetch"
    assert _batches(w) == {}, "a batch was claimed before the opening fetch answered"
    assert [(i.status, i.attempts) for i in _work(w).values()] == [("waiting", 0)]
    assert list(drafts_dir(w.t).glob("*")) == [], "a draft was made with no fetch"


@own_store("the tick is the post-step's, whose store is the port over a real helper")
def test_1618_k7_a_tick_in_the_job_container_never_sweeps(world, post_step_helper, caplog):  # noqa: F811 — the imported fixture
    """A tick run as the post-step in its job container (a pid namespace in which host owners look dead) opens its batch and runs no sweep; the counter sees a sweep when one is made. (K7, F8)"""
    from defender.tests.learning.branch.test_1344_post_step import post_step_in_container
    from defender.tests.support.tenancy._host1214 import counting_calls

    w = world
    _seed(w, "f1")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    helper = post_step_helper()
    without_clone(w.t)
    sweep_dead_owners = importlib.import_module(K.SWEEP_MODULE).sweep_dead_owners  # FORCED: the name the shared support module (`K.sweep`) fixes

    drains = importlib.import_module("defender.learning.core.drains")
    box = BoxSpy()

    def container_tick(paths, *, store):
        # the drain as the container runs it (as `_relay_tick`): no `directory=` or `identity=` of the host's; its job
        # container is the real helper's, which answers records, `forge.token` and `batch.start`; only the forge's API client
        # is the fake's
        return drains.author_drain(paths, store=store, container=helper.container(), client=w.t.forge.client,
                                   trigger_author=writer, start_box=box.start, stop_box=box.stop)

    with counting_calls(sweep=sweep_dead_owners) as seen:
        rc = post_step_in_container(None, w.t.tenant_id, forward=helper.ask, author_tick=container_tick)
    assert (rc, bool(writer.served)) == (0, True), f"premise: the container's tick opened a batch ({critical_text(caplog)})"
    assert seen.counts["sweep"] == 0, "a tick in a job container swept, and would remove a live host owner's folder"

    with counting_calls(sweep=sweep_dead_owners) as control:
        K.sweep(w.t)
    assert control.counts["sweep"] == 1, "control: the counter does not see a sweep"


# --- #1618 B12, the container half: the drain's relay mode (`container=`: records, `forge.token` and `batch.start` are the helper's) --------


def _relay_tick(w, helper, ask, writer):
    """The author drain as the post-step's container runs it: over the real post-step helper (`helper.container(ask)`), with the
    helper's answers passing through `ask`. The container fetches and pushes by itself; only the forge's API client is the fake's."""
    drains = importlib.import_module("defender.learning.core.drains")
    box = BoxSpy()
    container = helper.container(ask)
    return drains.author_drain(w.paths, container=container, client=w.t.forge.client, trigger_author=writer,
                               start_box=box.start, stop_box=box.stop, store=container.tick_store())


@own_store("the tick is the post-step's, whose store is the port over a real helper")
def test_1618_b12_a_container_tick_builds_its_batch_on_the_base_the_helper_answered_and_pushes_with_a_forge_token(world, post_step_helper, caplog):  # noqa: F811 — the imported fixture
    """The helper's `batch.start` answers a `base` that is no longer `main`'s tip: the container fetches it by id, the batch's parent is that base, and the push is made with a `forge.token`. (F6 job lane, K12)"""
    w = world
    without_clone(w.t)
    _seed(w, "f1")
    helper = post_step_helper()
    asked, answered, moved = [], {}, {}
    watch = R.Watch(w.t)

    def ask(name, **fields):
        answer = helper.ask(name, **fields)
        asked.append(name)
        if name == "batch.start":
            answered["base"] = answer["base"]
            watch.arm()  # the helper's own draft repository (host side) is behind us: what follows is the container's
            moved["tip"] = K.advance_main(w.t, "K1618-AFTER-THE-HELPERS-ANSWER")  # main moves on after the helper answered
        return answer

    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    _relay_tick(w, helper, ask, writer)

    assert writer.served, f"premise: the container's tick served the batch ({critical_text(caplog)})"
    assert moved["tip"] != answered["base"], "premise: the helper's base is not main's tip any more"
    [(branch, _tip)] = remote_branches(w.t.remote).items()
    assert git(w.t.remote, "rev-parse", f"{branch}^") == answered["base"], "the container did not build on the helper's base"
    assert "forge.token" in asked, "the container pushed without a forge.token from the helper"
    assert w.t.server.pushes == ["landed"]
    # K7, container side: its private repository is in its own tmpfs, never an entry of the host's `.repo-scratch/` (whose sweep a
    # container never runs) and never under `<T>`; the fetch by id and the push both reached the listener while watched
    assert watch.snapshots, "premise: the container's fetch and push were not observed"
    assert all(snap["names"] == [] for snap in watch.snapshots), [snap["names"] for snap in watch.snapshots]
    assert all(snap["under_tenant"] == [] for snap in watch.snapshots), [snap["under_tenant"] for snap in watch.snapshots]


@own_store("the tick is the post-step's, whose store is the port over a real helper")
def test_1618_b12_a_container_tick_refuses_a_base_it_cannot_fetch_by_id_and_authors_nothing(world, post_step_helper, caplog):  # noqa: F811 — the imported fixture
    """A `base` Forgejo does not serve makes the container's tick refuse: no curator runs, nothing is pushed, no PR opens (the case above is the control that the same tick otherwise serves). (F6 job lane)"""
    w = world
    without_clone(w.t)
    _seed(w, "f1")
    helper = post_step_helper()
    before = remote_branches(w.t.remote, prefix="")
    asked = []

    def ask(name, **fields):
        answer = helper.ask(name, **fields)
        asked.append(name)
        return {**answer, "base": K.ABSENT_COMMIT} if name == "batch.start" else answer

    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    _relay_tick(w, helper, ask, writer)

    assert "batch.start" in asked, "premise: the helper answered the batch start (the tick did not die earlier)"
    refusal = critical_text(caplog)
    assert K.ABSENT_COMMIT in refusal, f"the tick did not refuse naming the base it could not fetch (K5): {refusal!r}"
    assert writer.served == [], f"a curator ran on a base the container does not hold ({critical_text(caplog)})"
    assert remote_branches(w.t.remote, prefix="") == before, "a batch branch was pushed"
    assert w.t.forge.creates == []
