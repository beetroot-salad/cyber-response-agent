"""#1278 the author tick over the learning store, through the real drain entry.

Every case drives `author_drain` through the CLI's stage runner over `p4_tenant` (a real clone, a
loopback origin, P3's forge fake), with the store at `DEFENDER_DATABASE_DSN` on a migrated database
holding the tenant's row. Work is seeded and observed through the store's verbs; the curator is
`LessonWriter`, which commits through the batch's own commit-maker. Forge state is changed as a person
would. A stop is delivered to a forked child running the post-step, never to the pytest worker.
Reconcile and feedback are in the feedback slice's files.
"""
from __future__ import annotations

import os
import signal
from datetime import timedelta
from pathlib import Path

import httpx
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
    forget_local_branch,
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
    remote_branches,
)
from defender.tests.tenancy.tenant_1108_p4._support import git

pytestmark = pytest.mark.postgres


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
    assert git(w.t.clone, "show", "--name-only", "--format=", writer.commits[0]).split() == [f"agent/lessons/{LESSON_NAME}"], \
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
    assert git(w.t.clone, "for-each-ref", "refs/heads/lessons/") == ""
    assert _record(w) == []
    [batch] = _batches(w).values()
    assert batch.phase == "working", "a holder past its lease cannot end its own batch"
    assert (_work(w)[("finding", "f1")].status, _work(w)[("finding", "f1")].batch_id) == ("in_batch", batch.id)


def test_o3_a_holder_that_lost_its_lease_after_committing_pushes_nothing_and_opens_no_pr(world, caplog):  # noqa: F811 — the imported fixture
    """The lease lapses past grace after the commit: no push, no PR; the next tick takes over and delivers, no rerun. (O3, P6, Renewal and stop)"""
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

    _tick(w, writer)

    assert writer.served == [batch_id], "a takeover only finishes delivery: no new authoring run"
    [(branch, tip)] = remote_branches(w.t.remote).items()
    assert tip == writer.commits[0]
    [pr] = [r for r in w.t.forge.prs if r["state"] == "open"]
    assert pr["head"]["ref"] == branch
    assert (_batches(w)[batch_id].phase, _batches(w)[batch_id].pr_number) == ("in_review", pr["number"])


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


def test_o1_a_lease_lapsed_within_grace_is_not_taken_over_and_one_past_it_is(world, caplog):  # noqa: F811 — the imported fixture
    """Within grace the next tick leaves the stranded batch alone (no PR, same batch, still working); past grace it opens the PR. (O1, P6, Crash recovery)"""
    w = world
    writer, batch_id, branch = _stranded(w, caplog)

    lapse_lease(w.dsn, batch_id, past_grace=False)
    _tick(w, writer)

    assert [r for r in w.t.forge.prs if r["state"] == "open"] == [], "taken over within grace"
    assert list(_batches(w)) == [batch_id]
    assert _batches(w)[batch_id].phase == "working"
    assert writer.served == [batch_id]
    assert lease_seconds_left(w.dsn, batch_id) < 0, "the tick revived the lapsed lease"

    lapse_lease(w.dsn, batch_id)
    _tick(w, writer)

    [pr] = [r for r in w.t.forge.prs if r["state"] == "open"]
    assert (pr["head"]["ref"], _batches(w)[batch_id].phase) == (branch, "in_review")


def test_o1_a_branch_only_on_the_forge_is_verified_against_the_record_and_gets_its_pr_from_a_fresh_clone(world, caplog):  # noqa: F811 — the imported fixture
    """The replacement host's clone has no local branch: the takeover fetches the tip, finds it is the recorded commit, opens the PR. (O1, D11b)"""
    w = world
    writer, batch_id, branch = _stranded(w, caplog)
    forget_local_branch(w.t.clone, branch, drafts=drafts_dir(w.t))
    assert git(w.t.clone, "for-each-ref", f"refs/heads/{branch}") == ""

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
    forget_local_branch(w.t.clone, branch, drafts=drafts_dir(w.t))

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


def _post_step_child(w, writer, *, how):
    """A forked child running the real post-step (a family-less one) whose tick is `author_drain` over `writer`.
    `how` is how the stop will be delivered: `cancel` sets the store's flag, `sigterm` signals the child."""
    from defender.learning.branch import post_step

    w.monkeypatch.setenv(RENEW_ENV, "0.2")

    def body():
        return post_step.main(["--tenant", w.t.tenant_id, "--parent-pid", str(os.getppid())],
                              author_tick=lambda _paths: author_drain(w.t, w.paths, trigger=writer, box=BoxSpy()),
                              still_waiting=lambda _paths: False, directory=w.t.directory)
    return TickChild(body, w.scratch / f"child-{how}.json")


def _stop(w, child, how):
    if how == "cancel":
        call(w.dsn, "request_cancel", w.t.tenant_id)
    else:
        child.terminate()


def test_control_a_sigterm_reaches_the_post_step_blocked_in_a_subprocess(world):  # noqa: F811 — the imported fixture
    """Harness control, no store: the post-step's tick blocked in `sleep` ends on SIGTERM as a KeyboardInterrupt. (Renewal and stop)"""
    from defender.learning.branch import post_step

    w = world
    marker = w.scratch / "sleeper"
    block = blocked_in_subprocess(marker)

    def body():
        return post_step.main(["--tenant", w.t.tenant_id, "--parent-pid", str(os.getppid())],
                              author_tick=lambda _paths: block(None) or 0,
                              still_waiting=lambda _paths: False, directory=w.t.directory)
    child = TickChild(body, w.scratch / "child-control.json")
    sleeper = int(await_file(marker))
    try:
        child.signal(signal.SIGTERM)
        assert child.wait(seconds=STOP_BOUND) == {"raised": "KeyboardInterrupt"}
    finally:
        kill_if_alive(sleeper)


@pytest.mark.parametrize("how", ["cancel", "sigterm"])
def test_stop_a_stop_while_the_curator_is_blocked_in_a_subprocess_ends_the_tick_and_abandons_a_batch_with_no_commits(world, how):  # noqa: F811 — the imported fixture
    """Cancel flag or SIGTERM while the step waits on a child process: the tick ends in time, the batch is abandoned cleanly, f1 waits, attempt forgiven, lane free. (Renewal and stop, D4, D8)"""
    w = world
    _seed(w, "f1")
    marker = w.scratch / "sleeper"
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")}, before_commit=blocked_in_subprocess(marker))
    child = _post_step_child(w, writer, how=how)
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


@pytest.mark.parametrize("how", ["cancel", "sigterm"])
def test_stop_a_stop_after_the_commit_leaves_the_batch_for_takeover_at_once_and_one_pr(world, caplog, how):  # noqa: F811 — the imported fixture
    """Stopped while blocked after committing: the batch is not abandoned and its own lease is expired, so the next tick delivers it at once, within grace, with no rerun. (Renewal and stop, D4)"""
    w = world
    _seed(w, "f1")
    marker = w.scratch / "sleeper"
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")}, after_commit=blocked_in_subprocess(marker))
    child = _post_step_child(w, writer, how=how)
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


def test_stop_a_lease_lost_while_the_curator_is_blocked_in_a_subprocess_ends_the_tick_and_pushes_nothing(world):  # noqa: F811 — the imported fixture
    """The lease lapses (by SQL) while the step waits on a child process: the renewer sees it lost, the tick ends in time, nothing is pushed, no PR opens. (P6, Renewal and stop)"""
    w = world
    _seed(w, "f1")
    marker = w.scratch / "sleeper"
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")}, after_commit=blocked_in_subprocess(marker))
    child = _post_step_child(w, writer, how="lease")
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


# --- Crash recovery under a forge that cannot be asked (H15, Crash recovery) -----------------------------------------


def _asked(forge, method, suffix):
    """The requests of `method` made to a path ending `suffix`, refused or not."""
    return [r for r in forge.requests if r.method == method and r.url.path.rstrip("/").endswith(suffix)]


@pytest.mark.parametrize("where", ["preflight", "pr_lookup"])
@pytest.mark.parametrize("failure", ["500", "503", "connect"])
@pytest.mark.parametrize("scene", ["stranded", "nothing_pushed"])
def test_o1_a_lapsed_batch_whose_forge_cannot_be_asked_waits_and_is_never_abandoned(world, caplog, scene, failure, where):  # noqa: F811 — the imported fixture
    """A forge answering 5xx or refusing the connection, on every request or on the recovery's PR lookup alone, is unknown, not empty: the batch stays working, opens no PR, its items stay. (Crash recovery, H15, R2-1)"""
    w = world
    if scene == "stranded":
        writer, batch_id, _branch = _stranded(w, caplog)
    else:
        _seed(w, "f1")
        writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
        batch_id = call(w.dsn, "claim", w.t.tenant_id, AUTHOR_LANE, owner="lost-host", thresholds=ONE).batch_id
    lapse_lease(w.dsn, batch_id)
    before = {k: (i.status, i.batch_id, i.attempts) for k, i in _work(w).items()}
    lookup = where == "pr_lookup"
    if failure == "connect":
        w.t.forge.fault = lambda r: (httpx.ConnectError("down", request=r)
                                     if not lookup or (r.method == "GET" and r.url.path.rstrip("/").endswith("/pulls"))
                                     else None)
    else:
        w.t.forge.refuse("/pulls" if lookup else "", int(failure), method="GET" if lookup else None)
    w.t.forge.requests.clear()
    creates = len(w.t.forge.creates)

    for _ in range(3):
        _tick(w, writer)

    assert w.t.forge.requests, "the tick never asked the forge, so the failure was not what it waited on"
    if lookup:
        assert _asked(w.t.forge, "GET", "/pulls"), "recovery never looked the PR up, so its lookup was not what failed"
    assert _asked(w.t.forge, "POST", "/pulls") == [], "a PR was opened though the lookup could not say none exists"
    batch = _batches(w)[batch_id]
    assert (batch.phase, batch.outcome) == ("working", None), "a forge that could not answer was read as 'nothing there'"
    assert (batch.refusals, len(w.t.forge.creates)) == (0, creates)
    assert {k: (i.status, i.batch_id, i.attempts) for k, i in _work(w).items()} == before


@pytest.mark.parametrize("where", ["preflight", "pr_lookup"])
@pytest.mark.parametrize("status", [401, 403])
def test_o5_repeated_refusals_on_a_takeover_send_the_batch_to_a_person_at_the_ceiling(world, caplog, status, where):  # noqa: F811 — the imported fixture
    """A forge that keeps refusing the bot (401, 403) on every request or on the takeover's PR lookup alone: three ticks count, at the ceiling the batch is needs_person, items kept, no PR. (H15, R2-1, Crash recovery)"""
    w = world
    writer, batch_id, _branch = _stranded(w, caplog)
    lapse_lease(w.dsn, batch_id)
    lookup = where == "pr_lookup"
    w.t.forge.refuse("/pulls" if lookup else "", status, method="GET" if lookup else None)
    w.t.forge.requests.clear()
    seen = []
    for _ in range(3):
        _tick(w, writer)
        seen.append((_batches(w)[batch_id].phase, _batches(w)[batch_id].refusals))

    assert seen == [("working", 1), ("working", 2), ("needs_person", 3)], seen
    if lookup:
        assert _asked(w.t.forge, "GET", "/pulls"), "recovery never looked the PR up, so its lookup was not what was refused"
    assert _asked(w.t.forge, "POST", "/pulls") == []
    assert _work(w)[("finding", "f1")].status == "in_batch", "the item is not lost"
    assert [r for r in w.t.forge.prs if r["state"] == "open"] == []


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
