"""#1278 sketch: the author tick over the learning store, through the real drain entry.

Every case drives `author_drain` through the CLI's stage runner over `p4_tenant` (a real clone, a
loopback origin, P3's forge fake extended with reviews, comments and PR close), with the store at
`DEFENDER_DATABASE_DSN` on a migrated database holding the tenant's row. Work is seeded and observed
through the store's verbs; the curator is `LessonWriter`, which commits through the batch's own
commit-maker. Forge state is changed as a person would: merge, close, a review, a comment.
"""
from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    DSN_ENV,
    LessonWriter,
    batches,
    call,
    files_under,
    finding,
    lapse_lease,
    lesson_citing,
    work,
)
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_delivery._support import (
    close_on_remote,
    comment_row,
    merge_on_remote,
    review_row,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSON_NAME,
    BoxSpy,
    author_drain,
    critical_text,
    drain_paths,
    product_repo,
    remote_branches,
)
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, git

pytestmark = pytest.mark.postgres

READ_ISSUE = {"write:repository", "read:issue"}


@pytest.fixture
def world(p4_tenant, migrated_database, monkeypatch, tmp_path):  # noqa: F811 — the imported fixture
    """The tenant bound to its forge, active in the database the tick's store reads, both curators
    waking at one item."""
    t = p4_tenant
    bind_forge(t)
    register_tenant(migrated_database, t.tenant_id)
    monkeypatch.setenv(DSN_ENV, migrated_database)
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    return SimpleNamespace(t=t, dsn=migrated_database, paths=drain_paths(t, product_repo(tmp_path)),
                           scratch=tmp_path)


def _seed(w, *fids):
    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", [finding(f) for f in fids])


def _tick(w, writer):
    return author_drain(w.t, w.paths, trigger=writer, box=BoxSpy())


def _work(w):
    return work(w.dsn, w.t.tenant_id)


def _batches(w):
    return {b.id: b for b in batches(w.dsn, w.t.tenant_id)}


def _opened(w, writer, caplog):
    """One tick that authors f1's lesson and opens its PR: `(batch id, branch, PR number)`."""
    rc = _tick(w, writer)
    assert writer.served, f"the tick served no batch (rc {rc}): {critical_text(caplog)}"
    [(branch, _tip)] = remote_branches(w.t.remote).items()
    [pr] = [r for r in w.t.forge.prs if r["head"]["ref"] == branch]
    return writer.served[-1], branch, pr["number"]


# --- P2', O3: the row before the commit; a lapsed holder commits nothing --------------------------


def test_p2_the_batch_row_and_its_items_exist_before_the_first_commit_and_its_pr_puts_it_in_review(world, caplog):
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
    assert (seen["work"]["f1"].status, seen["work"]["f1"].batch_id) == ("in_batch", batch_id)
    assert (seen["branches"], seen["creates"]) == ({}, [])
    after = _batches(w)[batch_id]
    assert (after.phase, after.pr_number) == ("in_review", number)
    assert _work(w)["f1"].status == "in_batch", "a finding stays in its batch until its lesson merges"
    # O10: a tick that claimed, committed and delivered wrote nothing under the learning state root.
    assert files_under(learning) == before


def test_o3_a_holder_whose_lease_lapsed_makes_no_commit_and_changes_no_item(world, caplog):
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
    [batch] = _batches(w).values()
    assert batch.phase == "working", "a holder past its lease cannot end its own batch"
    assert (_work(w)["f1"].status, _work(w)["f1"].batch_id) == ("in_batch", batch.id)


# --- O1, O5: crash recovery -----------------------------------------------------------------------


def test_o1_a_pushed_branch_with_no_pr_is_taken_over_and_gets_its_one_pr(world, caplog):
    """The PR open fails after the push; once the lease lapses, the next tick opens that branch's PR, no rerun. (O1, O5, Crash recovery)"""
    w = world
    _seed(w, "f1")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    w.t.forge.fail_create = True
    _tick(w, writer)
    assert writer.served, critical_text(caplog)
    [(branch, _tip)] = remote_branches(w.t.remote).items()
    assert [r for r in w.t.forge.prs if r["state"] == "open"] == []
    [batch_id] = _batches(w)

    w.t.forge.fail_create = False
    lapse_lease(w.dsn, batch_id)
    _tick(w, writer)

    assert writer.served == [batch_id], "a takeover only finishes delivery: no new authoring run"
    assert list(remote_branches(w.t.remote)) == [branch]
    [pr] = [r for r in w.t.forge.prs if r["state"] == "open"]
    assert pr["head"]["ref"] == branch
    [batch] = _batches(w).values()
    assert (batch.id, batch.phase, batch.pr_number) == (batch_id, "in_review", pr["number"])


def test_o1_a_lapsed_batch_with_nothing_anywhere_is_abandoned_and_its_item_authored_again(world, caplog):
    """A lost host's batch with no branch and no PR ends abandoned; its item returns and a new batch authors it. (O1, P3, Crash recovery)"""
    w = world
    _seed(w, "f1")
    lost = call(w.dsn, "claim", w.t.tenant_id, AUTHOR_LANE, owner="lost-host")
    lapse_lease(w.dsn, lost.batch_id)
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    _tick(w, writer)

    rows = _batches(w)
    assert (rows[lost.batch_id].phase, rows[lost.batch_id].outcome) == ("ended", "abandoned")
    assert writer.served, critical_text(caplog)
    assert lost.batch_id not in writer.served
    [fresh] = [b for b in rows.values() if b.id != lost.batch_id]
    assert fresh.phase == "in_review"
    assert (_work(w)["f1"].status, _work(w)["f1"].batch_id) == ("in_batch", fresh.id)


# --- Reconcile and Feedback (O4, H2, H3, H7) ---------------------------------------------------------


def test_reconcile_a_merged_pr_publishes_cited_items_and_holds_the_uncited(world, caplog):
    """Merged: f1, cited by the merged lesson, is published; f2, in the batch but uncited, is held. (Reconcile, P1)"""
    w = world
    _seed(w, "f1", "f2")
    batch_id, branch, _number = _opened(w, LessonWriter({LESSON_NAME: lesson_citing("f1")}), caplog)
    merge_on_remote(w.t.p3, w.scratch, branch)
    _tick(w, LessonWriter({}))

    items = _work(w)
    assert {k: i.status for k, i in items.items()} == {"f1": "published", "f2": "held"}
    assert (_batches(w)[batch_id].phase, _batches(w)[batch_id].outcome) == ("ended", "merged")


def test_feedback_a_pr_closed_without_feedback_holds_its_items_visibly(world, caplog):
    """Closed with no review or comment, after both were read: the item is held, named with its batch and PR. (H2, O2)"""
    w = world
    w.t.forge.scopes = set(READ_ISSUE)
    _seed(w, "f1")
    batch_id, branch, number = _opened(w, LessonWriter({LESSON_NAME: lesson_citing("f1")}), caplog)
    close_on_remote(w.t.p3, branch)
    _tick(w, LessonWriter({}))

    f1 = _work(w)["f1"]
    assert (f1.status, f1.batch_id, f1.pr_number) == ("held", batch_id, number)
    assert (_batches(w)[batch_id].phase, _batches(w)[batch_id].outcome) == ("ended", "closed")
    read = {r.url.path.split("/", 5)[-1] for r in w.t.forge.requests if r.method == "GET"}
    assert {f"pulls/{number}/reviews", f"issues/{number}/comments"} <= read, read


def test_feedback_a_pr_closed_with_a_comment_is_replaced_by_a_new_batch_whose_pr_links_it(world, caplog):
    """A plain comment on the closed PR: its batch ends closed, a replacement batch `replaces` it, its new PR links the old. (H3, H7, Feedback)"""
    w = world
    w.t.forge.scopes = set(READ_ISSUE)
    _seed(w, "f1")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    old_id, old_branch, old_number = _opened(w, writer, caplog)
    w.t.forge.comments[old_number] = [comment_row(501, "analyst", "cite the alert rule, not the host")]
    close_on_remote(w.t.p3, old_branch)
    _tick(w, writer)
    _tick(w, writer)

    rows = _batches(w)
    assert (rows[old_id].phase, rows[old_id].outcome) == ("ended", "closed")
    [new] = [b for b in rows.values() if b.id != old_id]
    assert (new.replaces, new.phase) == (old_id, "in_review")
    assert (_work(w)["f1"].status, _work(w)["f1"].batch_id) == ("in_batch", new.id)
    [_first, second] = w.t.forge.creates
    assert second["head"] != old_branch
    [old_url] = [r["html_url"] for r in w.t.forge.prs if r["number"] == old_number]
    assert f"#{old_number}" in second.get("body", "") or old_url in second.get("body", ""), second


def test_feedback_changes_requested_on_an_open_pr_closes_it_and_a_plain_comment_does_not(world, caplog):
    """A plain comment leaves the open PR alone; a live changes-requested review gets it closed by the reconciler. (H7, Feedback)"""
    w = world
    w.t.forge.scopes = set(READ_ISSUE)
    _seed(w, "f1")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    batch_id, _branch, number = _opened(w, writer, caplog)
    w.t.forge.comments[number] = [comment_row(502, "analyst", "interesting")]
    _tick(w, writer)
    assert w.t.forge.patches == [], "control: a plain comment on an open PR does not close it"

    w.t.forge.reviews[number] = [review_row(601, "owner", "REQUEST_CHANGES", body="wrong lane")]
    _tick(w, writer)

    assert w.t.forge.patches == [(number, {"state": "closed"})]
    assert (_batches(w)[batch_id].phase, _batches(w)[batch_id].outcome) == ("ended", "closed")


def test_feedback_a_refused_comment_read_is_unknown_not_no_feedback(world, caplog):
    """Without read:issue the comment read is 403: the closed PR's batch stays unresolved, its item not held; with it, held. (C23, Feedback)"""
    w = world
    _seed(w, "f1")
    batch_id, branch, number = _opened(w, LessonWriter({LESSON_NAME: lesson_citing("f1")}), caplog)
    close_on_remote(w.t.p3, branch)
    _tick(w, LessonWriter({}))

    refused = [r for r in w.t.forge.requests if r.url.path.endswith(f"/issues/{number}/comments")]
    assert refused, "the reconciler never asked for the closed PR's comments"
    assert _batches(w)[batch_id].phase == "in_review"
    assert _work(w)["f1"].status == "in_batch"

    w.t.forge.scopes.add("read:issue")
    _tick(w, LessonWriter({}))
    assert _work(w)["f1"].status == "held", "control: the same close, read in full, holds the item"


# --- Renewal and stop (O3, P6) -------------------------------------------------------------------------


#: How long the cancelled curator step waits for its stop before giving up (sketch bound).
STOP_WAIT_SECONDS = 45.0


def test_stop_a_cancel_mid_authoring_stops_the_step_and_a_batch_with_no_commits_is_abandoned(world, caplog):
    """Cancel set while the curator works: the step is stopped before committing, the batch ends abandoned, f1 waits, the lane is free. (Renewal and stop)"""
    w = world
    _seed(w, "f1")
    outcome = {}

    def cancel_then_wait(_batch):
        call(w.dsn, "request_cancel", w.t.tenant_id)
        deadline = time.monotonic() + STOP_WAIT_SECONDS
        while time.monotonic() < deadline:
            time.sleep(0.05)
        outcome["waited_out"] = True

    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")}, before_commit=cancel_then_wait)
    _tick(w, writer)

    assert writer.served, critical_text(caplog)
    assert "waited_out" not in outcome, "the stop never reached the curator step"
    assert writer.commits == []
    assert remote_branches(w.t.remote) == {}
    [batch] = _batches(w).values()
    assert (batch.phase, batch.outcome) == ("ended", "abandoned")
    assert _work(w)["f1"].status == "waiting"
    assert call(w.dsn, "claim", w.t.tenant_id, AUTHOR_LANE, owner="next-host") is not None
