"""#1278 feedback and reconcile: what a tick does with a batch's PR once people have acted on it.

Every case drives `author_drain` through the CLI's stage runner over `p4_tenant` (a real clone, a loopback
origin, P3's forge fake with reviews, comments, scripted refusals and PR close), the store at
`DEFENDER_DATABASE_DSN` on a migrated database holding the tenant's row. Forge state is changed as a person
would: merge (optionally editing the merge), close, a review, a comment. The curator is `FeedbackCurator`.
A crash between the reconcile's end and the replacement's claim is made by ending the batch by hand.
"""
from __future__ import annotations

import os

import httpx
import pytest

from defender.tests.support.learning.core._feedback1278 import (
    FeedbackCurator,
    Scene,
    claim_by_hand,
    end_closed_by_hand,
    framed,
    make_scene,
    opened,
    reviewer_removes_citation,
    tick,
    wake_at,
)
from defender.tests.support.learning.core._store1278 import (
    LEAD_LANE,
    RENEW_ENV,
    TickChild,
    await_file,
    blocked_in_subprocess,
    call,
    kill_if_alive,
    lapse_lease,
    lesson_citing,
)
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_delivery._support import (
    close_on_remote,
    comment_row,
    merge_on_remote,
    push_to_remote,
    review_row,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSON_NAME,
    LESSON_PATH,
    BoxSpy,
    PitfallsStep,
    critical_text,
    lead_author_drain,
    remote_branches,
)

pytestmark = pytest.mark.postgres

READ_ISSUE = {"write:repository", "read:issue"}
#: How long the forked post-step may take to end after its stop.
STOP_BOUND = 30.0


def _files(*finding_ids):
    return {f"lessons/{LESSON_NAME}": lesson_citing(*finding_ids)}


@pytest.fixture
def world(p4_tenant, migrated_database, monkeypatch, tmp_path):  # noqa: F811 — the imported fixture
    """The tenant bound to a forge whose token carries `read:issue`, active in the database, both curators waking at one item."""
    scene = make_scene(p4_tenant, migrated_database, tmp_path, monkeypatch)
    scene.t.forge.scopes = set(READ_ISSUE)
    return scene


def _end(w: Scene, batch_id):
    b = w.batch_rows()[batch_id]
    return b.phase, b.outcome


def _replacements(w: Scene, old_id):
    return [b for b in w.batch_rows().values() if b.replaces == old_id]


def _no_orphans(w: Scene):
    """D8: a batch that ended other than closed leaves no item in_batch."""
    rows = w.batch_rows()
    orphans = [k for k, i in w.items().items() if i.status == "in_batch"
               and rows[i.batch_id].phase == "ended" and rows[i.batch_id].outcome != "closed"]
    assert orphans == []


def _due(w: Scene, caplog, comment="cite the alert rule, not the host"):
    """f1 authored and in review, then closed by a person with `comment` and ended by the reconcile,
    its replacement not yet claimed: `(old batch id, old PR number)`."""
    w.seed("f1")
    old_id, branch, number = opened(w, FeedbackCurator(_files("f1")), caplog)
    w.t.forge.comments[number] = [comment_row(501, "analyst", comment)]
    close_on_remote(w.t.p3, branch)
    end_closed_by_hand(w, old_id)
    return old_id, number


# --- Reconcile: a merged PR (O4, H16, D7) --------------------------------------------------------------


@pytest.mark.parametrize("style", ["merge", "squash", "rebase"])
def test_reconcile_a_merge_publishes_the_cited_and_returns_the_never_cited_to_waiting(world, caplog, monkeypatch, style):
    """f1 cited, f2 never cited: f2 is back to waiting when the batch enters review, f1 published at the merge. (Reconcile, H16)"""
    w = world
    w.seed("f1", "f2")
    wake_at(monkeypatch, 2)
    batch_id, branch, _n = opened(w, FeedbackCurator(_files("f1")), caplog)
    assert w.statuses() == {"f1": "in_batch", "f2": "waiting"}, "uncited items return to waiting at review"
    merge_on_remote(w.t.p3, w.scratch, branch, style)
    tick(w, FeedbackCurator())

    assert w.statuses() == {"f1": "published", "f2": "waiting"}
    assert _end(w, batch_id) == ("ended", "merged")


def test_reconcile_reads_the_merge_commit_not_main(world, caplog):
    """After the merge a later commit on main deletes the lesson: the merge commit's tree still publishes f1. (Reconcile)"""
    w = world
    w.seed("f1")
    batch_id, branch, _n = opened(w, FeedbackCurator(_files("f1")), caplog)
    merge_on_remote(w.t.p3, w.scratch, branch)
    push_to_remote(w.t.p3, w.scratch, lambda co: (co / LESSON_PATH).unlink(), "a later change removes the lesson")
    tick(w, FeedbackCurator())

    assert w.statuses() == {"f1": "published"}
    assert _end(w, batch_id) == ("ended", "merged")


def test_reconcile_a_citation_the_reviewer_removed_before_merging_holds_the_item(world, caplog):
    """f2 is cited at the branch tip, absent from the merge commit's tree: held; f1 published. (H16, D7)"""
    w = world
    w.seed("f1", "f2")
    batch_id, branch, _n = opened(w, FeedbackCurator(_files("f1", "f2")), caplog)
    assert w.statuses() == {"f1": "in_batch", "f2": "in_batch"}
    merge_on_remote(w.t.p3, w.scratch, branch,
                    edit=reviewer_removes_citation(LESSON_NAME, lesson_citing("f1")))
    tick(w, FeedbackCurator())

    assert w.statuses() == {"f1": "published", "f2": "held"}
    assert _end(w, batch_id) == ("ended", "merged")
    assert w.items()["f2"].batch_id == batch_id


def test_reconcile_cited_means_the_kinds_own_corpus_directory(world, caplog, monkeypatch):
    """A questioner finding cited only from the lessons directory is not cited; one cited from the questioner directory is. (D7)"""
    w = world
    w.seed("f1")
    w.seed("q1", "q2", kind="questioner_finding")
    wake_at(monkeypatch, 3)
    files = {f"lessons/{LESSON_NAME}": lesson_citing("f1", "q2"),
             f"lessons-questioner/{LESSON_NAME}": lesson_citing("q1")}
    batch_id, branch, _n = opened(w, FeedbackCurator(files), caplog)
    merge_on_remote(w.t.p3, w.scratch, branch)
    tick(w, FeedbackCurator())

    assert w.statuses() == {"f1": "published", "q1": "published", "q2": "waiting"}
    assert _end(w, batch_id) == ("ended", "merged")


def test_reconcile_the_lead_lane_batch_of_a_merged_pr_publishes_every_committed_item(world, tmp_path, monkeypatch, caplog):
    """A merged lead-lane PR (no citation field) publishes the pitfalls its curator committed, reconciled by the author tick. (D9)"""
    from defender.tests.support.learning.core._declared870 import shim_row

    w = world
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    call(w.dsn, "add_pitfall", w.t.tenant_id, shim_row("p4-run:1"))
    pitfalls = PitfallsStep("- **Name the unnested column.**")
    rc = lead_author_drain(w.t, w.paths, box=BoxSpy(), run_lead_author=lambda *_a, **_k: None, run_pitfalls=pitfalls)
    assert rc == 0, critical_text(caplog)
    [(branch, _tip)] = remote_branches(w.t.remote, "lead-author/").items()
    [lead] = [b for b in w.batch_rows().values() if b.lane == LEAD_LANE]
    assert (lead.phase, w.statuses()) == ("in_review", {"p4-run:1": "in_batch"})

    merge_on_remote(w.t.p3, w.scratch, branch)
    tick(w, FeedbackCurator())

    assert w.statuses() == {"p4-run:1": "published"}
    assert _end(w, lead.id) == ("ended", "merged")


# --- Feedback: closed without words (H2, H7) -----------------------------------------------------------

SILENT = {
    "nothing": [],
    "approval": [review_row(601, "owner", "APPROVED")],
    "dismissed-changes-requested": [review_row(602, "owner", "REQUEST_CHANGES", dismissed=True)],
    "empty-comment-review": [review_row(603, "owner", "COMMENT")],
}


@pytest.mark.parametrize("reviews", SILENT.values(), ids=SILENT)
def test_feedback_a_pr_closed_without_words_holds_its_items_after_reading_both(world, caplog, reviews):
    """Closed with no words, reviews and comments both read: the item is held, named with its batch and PR. (H2, O2)"""
    w = world
    w.seed("f1")
    batch_id, branch, number = opened(w, FeedbackCurator(_files("f1")), caplog)
    w.t.forge.reviews[number] = reviews
    close_on_remote(w.t.p3, branch)
    tick(w, FeedbackCurator())

    f1 = w.items()["f1"]
    assert (f1.status, f1.batch_id, f1.pr_number) == ("held", batch_id, number)
    assert _end(w, batch_id) == ("ended", "closed")
    read = {r.url.path for r in w.t.forge.requests if r.method == "GET"}
    assert any(p.endswith(f"/pulls/{number}/reviews") for p in read), read
    assert any(p.endswith(f"/issues/{number}/comments") for p in read), read
    assert _replacements(w, batch_id) == []


def test_feedback_words_posted_after_the_read_start_nothing(world, caplog):
    """The silent close is held; a comment posted afterwards starts no replacement, however many ticks follow. (H14, H2)"""
    w = world
    w.seed("f1")
    batch_id, branch, number = opened(w, FeedbackCurator(_files("f1")), caplog)
    close_on_remote(w.t.p3, branch)
    tick(w, FeedbackCurator())
    w.t.forge.comments[number] = [comment_row(510, "analyst", "too late")]
    late = FeedbackCurator(_files("f1"))
    tick(w, late)
    tick(w, late)

    assert w.statuses() == {"f1": "held"}
    assert (late.served, _replacements(w, batch_id)) == ([], [])
    assert len(w.t.forge.creates) == 1, "no second PR"


# --- Feedback: closed with words -> replacement in the same tick (H3, H7, D7, D8) ----------------------

#: Stands for the tenant's real bot login (`bot-<tenant>-<salt>`), which a case knows only once its scene is built.
BOT = "<the tenant's bot login>"

WORDS = {
    "plain-comment": ([], [comment_row(501, "analyst", "cite the alert rule, not the host")]),
    "comment-by-the-bot-login": ([], [comment_row(502, BOT, "no bot exclusion")]),
    "review-with-text": ([review_row(611, "owner", "COMMENT", body="wrong lane")], []),
    "approval-with-text": ([review_row(612, "owner", "APPROVED", body="fine but rename it")], []),
    "live-changes-requested": ([review_row(613, "owner", "REQUEST_CHANGES")], []),
    "read-only-reviewers-changes-requested": ([review_row(614, "guest", "REQUEST_CHANGES", official=False)], []),
    "inline-comments-with-an-empty-body": ([review_row(615, "owner", "COMMENT", inline=2)], []),
}


@pytest.mark.parametrize(("reviews", "comments"), WORDS.values(), ids=WORDS)
def test_feedback_a_pr_closed_with_words_is_replaced_by_a_new_batch_in_the_same_tick(world, caplog, reviews, comments):
    """Closed with feedback: one tick ends the batch closed and opens a replacement that `replaces` it, its PR linking the old. (H3, H7, D7, D8)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    old_id, old_branch, old_number = opened(w, writer, caplog)
    assert w.bot_login().startswith("bot-"), "premise: the scene's bot login is the provisioned spelling"
    comments = [{**c, "user": {"login": w.bot_login()}} if c["user"]["login"] == BOT else c for c in comments]
    w.t.forge.reviews[old_number], w.t.forge.comments[old_number] = reviews, comments
    close_on_remote(w.t.p3, old_branch)
    tick(w, writer)

    assert _end(w, old_id) == ("ended", "closed")
    [new] = _replacements(w, old_id)
    assert (new.phase, new.generation) == ("in_review", 1)
    assert (w.items()["f1"].status, w.items()["f1"].batch_id) == ("in_batch", new.id)
    [_first, second] = w.t.forge.creates
    assert second["head"] != old_branch
    [old_url] = [r["html_url"] for r in w.t.forge.prs if r["number"] == old_number]
    assert f"#{old_number}" in second.get("body", "") or old_url in second.get("body", ""), second
    _no_orphans(w)


def test_feedback_words_only_on_the_last_page_of_reviews_start_the_replacement(world, caplog):
    """Sixty-nine approvals with no words and a seventieth review with some, past the forge's 50-row page: the closed PR is replaced and the curator is handed the late words. (C30, H13)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    old_id, old_branch, number = opened(w, writer, caplog)
    w.t.forge.reviews[number] = [review_row(800 + i, f"approver-{i}", "APPROVED") for i in range(69)] + [
        review_row(900, "late-reviewer", "COMMENT", body="the only words, on page two")]
    close_on_remote(w.t.p3, old_branch)
    tick(w, writer)

    assert len(_replacements(w, old_id)) == 1, "the words on the last page were not read"
    assert framed(writer.seen_text(), "the only words, on page two")


def test_feedback_the_replacement_is_made_once_whatever_follows(world, caplog):
    """Later ticks do not claim the replaced batch's items again. (D8)"""
    w = world
    old_id, _n = _due(w, caplog)
    writer = FeedbackCurator(_files("f1"))
    tick(w, writer)
    tick(w, writer)
    tick(w, writer)

    assert len(_replacements(w, old_id)) == 1
    assert len(w.t.forge.creates) == 2


# --- Feedback: an open PR (H7, C24, C25) ---------------------------------------------------------------

NOT_FEEDBACK = {
    "approval": [review_row(621, "owner", "APPROVED")],
    "review-with-text": [review_row(622, "owner", "COMMENT", body="looks plausible")],
    "dismissed-changes-requested": [review_row(623, "owner", "REQUEST_CHANGES", dismissed=True)],
    "changes-requested-then-approved-by-the-same-reviewer": [
        review_row(624, "owner", "REQUEST_CHANGES"), review_row(625, "owner", "APPROVED")],
}


@pytest.mark.parametrize("reviews", NOT_FEEDBACK.values(), ids=NOT_FEEDBACK)
def test_feedback_an_open_pr_is_left_alone_unless_a_live_review_requests_changes(world, caplog, reviews):
    """A plain comment, an approval, text without a request for changes and a superseded request leave the open PR alone. (H7, C24)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, number = opened(w, writer, caplog)
    w.t.forge.comments[number] = [comment_row(502, "analyst", "interesting")]
    w.t.forge.reviews[number] = reviews
    tick(w, writer)

    assert w.t.forge.patches == []
    assert _end(w, batch_id) == ("in_review", None)
    assert w.statuses() == {"f1": "in_batch"}


@pytest.mark.parametrize("reviews", [
    [review_row(631, "owner", "REQUEST_CHANGES", body="wrong lane")],
    [review_row(632, "guest", "REQUEST_CHANGES", official=False)],
    [review_row(633, "owner", "REQUEST_CHANGES"), review_row(634, "other", "APPROVED")],
], ids=["official", "read-only-reviewer", "another-reviewer-approved-later"])
def test_feedback_a_live_changes_requested_review_on_an_open_pr_gets_it_closed_and_replaced(world, caplog, reviews):
    """The reconciler closes the PR and the batch ends closed; its replacement follows in the same tick. (H7, C25, D8)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, number = opened(w, writer, caplog)
    w.t.forge.reviews[number] = reviews
    tick(w, writer)

    assert w.t.forge.patches == [(number, {"state": "closed"})]
    assert _end(w, batch_id) == ("ended", "closed")
    [new] = _replacements(w, batch_id)
    assert new.phase == "in_review"


def test_reconcile_an_open_pr_whose_batch_ended_is_closed(world, caplog):
    """A person abandons the in-review batch; the next tick closes its still-open PR and the items stay held. (Reconcile, O7)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, number = opened(w, writer, caplog)
    call(w.dsn, "abandon", w.t.tenant_id, batch_id, by="person")
    tick(w, writer)

    assert w.t.forge.patches == [(number, {"state": "closed"})]
    assert _end(w, batch_id) == ("ended", "abandoned")
    assert w.statuses() == {"f1": "held"}
    assert len(w.t.forge.creates) == 1


def test_feedback_close_then_crash_is_idempotent(world, caplog):
    """The close landed on the forge, the store still says in_review: the next tick rereads closed plus the review, closes nothing again, replaces once. (Feedback)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, branch, number = opened(w, writer, caplog)
    w.t.forge.reviews[number] = [review_row(641, "owner", "REQUEST_CHANGES", body="wrong lane")]
    close_on_remote(w.t.p3, branch)
    tick(w, writer)
    tick(w, writer)

    assert w.t.forge.patches == []
    assert _end(w, batch_id) == ("ended", "closed")
    assert len(_replacements(w, batch_id)) == 1
    assert len(w.t.forge.creates) == 2


# --- A2 H13, H14: the replacement re-reads the feedback live and hands it over -------------------------


def test_h13_the_replacement_hands_the_curator_the_feedback_in_an_untrusted_block(world, caplog):
    """The replacement tick reads the old PR's review and comment live and the curator sees both inside an untrusted frame. (H13)"""
    w = world
    old_id, number = _due(w, caplog, comment="cite the alert rule, not the host")
    w.t.forge.reviews[number] = [review_row(651, "owner", "REQUEST_CHANGES", body="wrong lane")]
    before = len(w.t.forge.requests)
    curator = FeedbackCurator(_files("f1"))
    tick(w, curator)

    assert curator.served, critical_text(caplog)
    seen = curator.seen_text()
    assert framed(seen, "cite the alert rule, not the host"), seen
    assert framed(seen, "wrong lane"), seen
    asked = [r.url.path for r in w.t.forge.requests[before:] if r.method == "GET"]
    assert any(p.endswith(f"/pulls/{number}/reviews") for p in asked), "the text is read live, not remembered"
    assert any(p.endswith(f"/issues/{number}/comments") for p in asked)
    assert [b.replaces for b in _replacements(w, old_id)] == [old_id]
    stored = w.stored_text()
    for words in ("cite the alert rule, not the host", "wrong lane"):
        assert words not in stored, f"review text {words!r} was stored in the database"


@pytest.mark.parametrize(("suffix", "status"), [("/comments", 403), ("/comments", 503), ("/reviews", 403), ("/reviews", 503)])
def test_h13_a_failed_read_at_replacement_waits_and_never_authors_blind(world, caplog, suffix, status):
    """The batch is already ended closed by hand and the forge refuses from the first request, so the replacement's own read is the only read: no claim, no curator run, the items still due; a good read then authors and stores no review text. (H13, GAP2)"""
    w = world
    old_id, number = _due(w, caplog, comment="cite the alert rule, found in runbook-7731")
    w.t.forge.reviews[number] = [review_row(661, "owner", "COMMENT", body="wrong lane, see runbook-8842")]
    before = len(w.t.forge.requests)
    w.t.forge.refuse(suffix, status)
    blind = FeedbackCurator(_files("f1"))
    tick(w, blind)

    asked = [r.url.path for r in w.t.forge.requests[before:] if r.method == "GET"]
    assert any(p.endswith(suffix) for p in asked), "the replacement never read the feedback"
    assert _end(w, old_id) == ("ended", "closed")
    assert (blind.served, _replacements(w, old_id), len(w.t.forge.creates)) == ([], [], 1)
    assert (w.items()["f1"].status, w.items()["f1"].batch_id) == ("in_batch", old_id), "still due"

    w.t.forge.clear_refusals()
    good = FeedbackCurator(_files("f1"))
    tick(w, good)
    assert good.served
    assert framed(good.seen_text(), "cite the alert rule, found in runbook-7731")
    assert len(_replacements(w, old_id)) == 1
    stored = w.stored_text()
    for words in ("runbook-7731", "runbook-8842"):
        assert words not in stored, f"review text {words!r} was stored in the database"


def test_h14_words_posted_after_the_reconcile_read_count_at_authoring(world, caplog):
    """A comment posted after the batch ended closed reaches the replacement's curator beside the first. (H14)"""
    w = world
    old_id, number = _due(w, caplog, comment="first words")
    w.t.forge.comments[number].append(comment_row(502, "latecomer", "second words, later"))
    curator = FeedbackCurator(_files("f1"))
    tick(w, curator)

    seen = curator.seen_text()
    assert framed(seen, "first words"), seen
    assert framed(seen, "second words, later"), seen
    assert len(_replacements(w, old_id)) == 1


# --- Replacement chain: replaces, abandon, ceiling (H3, D8, O7) ----------------------------------------


def test_replacement_that_commits_nothing_holds_its_items_and_opens_no_pr(world, caplog):
    """The replacement's curator authors nothing: its batch ends, the items are held, no second replacement or PR follows. (G-F4, G-C2, Feedback)"""
    w = world
    old_id, _number = _due(w, caplog)
    idle = FeedbackCurator()
    tick(w, idle)
    tick(w, idle)

    [new] = _replacements(w, old_id)
    assert new.phase == "ended"
    assert w.statuses() == {"f1": "held"}
    assert len(w.t.forge.creates) == 1, "no second PR"
    _no_orphans(w)


def test_replacement_for_questioner_findings_only_hands_the_feedback_to_the_questioner_curator(world, caplog):
    """Only a questioner finding is due: the questioner curator gets the framed feedback, no curator of the other kind does. (G-F5, H13)"""
    w = world
    w.seed("q1", kind="questioner_finding")
    files = {f"lessons-questioner/{LESSON_NAME}": lesson_citing("q1")}
    old_id, branch, number = opened(w, FeedbackCurator(files), caplog)
    w.t.forge.comments[number] = [comment_row(501, "analyst", "cite the world's rule")]
    close_on_remote(w.t.p3, branch)
    end_closed_by_hand(w, old_id)
    curator = FeedbackCurator(files)
    tick(w, curator)

    given = [(text, feedback) for text, feedback in curator.calls() if feedback is not None]
    assert given, critical_text(caplog)
    assert all("questioner" in text.lower() for text, _fb in given), "feedback reached a curator of another kind"
    assert all(framed(fb, "cite the world's rule") for _text, fb in given)
    assert [text for text, feedback in curator.calls() if feedback is None and "questioner" in text.lower()] == []
    assert len(_replacements(w, old_id)) == 1


def test_replacement_a_successor_abandoned_before_its_pr_passes_its_replaces_on(world, caplog):
    """The replacement's host is lost before any PR: it ends abandoned, the next replacement `replaces` the original, generation 1. (replacement flow)"""
    w = world
    old_id, number = _due(w, caplog)
    lost = claim_by_hand(w, "lost-host")
    assert (lost.replaces, lost.feedback_pr) == (old_id, number)
    lapse_lease(w.dsn, lost.batch_id)
    curator = FeedbackCurator(_files("f1"))
    tick(w, curator)

    rows = w.batch_rows()
    assert (rows[lost.batch_id].phase, rows[lost.batch_id].outcome) == ("ended", "abandoned")
    [fresh] = [b for b in rows.values() if b.id not in (old_id, lost.batch_id)]
    assert (fresh.replaces, fresh.generation, fresh.phase) == (old_id, 1, "in_review")
    assert curator.served == [fresh.id]
    assert framed(curator.seen_text(), "cite the alert rule, not the host")
    assert w.items()["f1"].batch_id == fresh.id
    _no_orphans(w)


@pytest.mark.parametrize("how", ["cancel", "sigterm"])
def test_replacement_a_stop_before_its_pr_keeps_the_items_due_with_the_generation_unchanged(world, caplog, monkeypatch, how):
    """The post-step, forked, is stopped while the replacement's curator is blocked in a subprocess: the batch ends abandoned, the items are due again, the next tick replaces. (O7, D4, D8)"""
    from defender.learning.branch import post_step

    w = world
    old_id, _number = _due(w, caplog)
    marker = w.scratch / "sleeper"
    blocked = FeedbackCurator(_files("f1"), before_commit=blocked_in_subprocess(marker))
    monkeypatch.setenv(RENEW_ENV, "0.2")

    def body():
        return post_step.main(["--tenant", w.t.tenant_id, "--parent-pid", str(os.getppid())],
                              author_tick=lambda _paths: tick(w, blocked),
                              still_waiting=lambda _paths: False, directory=w.t.directory)
    child = TickChild(body, w.scratch / f"child-{how}.json")
    sleeper = int(await_file(marker))
    try:
        if how == "cancel":
            call(w.dsn, "request_cancel", w.t.tenant_id)
        else:
            child.terminate()
        child.wait(seconds=STOP_BOUND)
    finally:
        kill_if_alive(sleeper)

    [stopped] = _replacements(w, old_id)
    assert (stopped.phase, stopped.outcome) == ("ended", "abandoned")
    assert (w.items()["f1"].status, w.items()["f1"].batch_id) == ("in_batch", old_id), "still due on the closed batch"
    _no_orphans(w)

    monkeypatch.setenv(RENEW_ENV, "600")
    again = FeedbackCurator(_files("f1"))
    tick(w, again)
    [fresh] = [b for b in _replacements(w, old_id) if b.id != stopped.id]
    assert (fresh.generation, fresh.phase) == (1, "in_review")


def test_replacement_a_persons_abandon_of_the_replacement_holds_its_items(world, caplog):
    """A person abandons a claimed replacement: its items are held, not due. (O7)"""
    w = world
    old_id, _number = _due(w, caplog)
    claim = claim_by_hand(w, "host-a")
    call(w.dsn, "abandon", w.t.tenant_id, claim.batch_id, by="person")

    assert w.statuses() == {"f1": "held"}
    tick(w, FeedbackCurator(_files("f1")))
    assert [b.id for b in _replacements(w, old_id)] == [claim.batch_id], "no further replacement"
    _no_orphans(w)


def test_replacement_the_generation_ceiling_holds_the_items(world, caplog):
    """Three replacement PRs are opened, each closed with feedback; the fourth close holds the items. (D8)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, branch, number = opened(w, writer, caplog)
    chain = [batch_id]
    for generation in (1, 2, 3):
        w.t.forge.comments[number] = [comment_row(700 + generation, "analyst", f"round {generation}")]
        close_on_remote(w.t.p3, branch)
        tick(w, writer)
        [new] = _replacements(w, chain[-1])
        assert (new.generation, new.phase) == (generation, "in_review")
        chain.append(new.id)
        branch, number = new.branch, new.pr_number
    w.t.forge.comments[number] = [comment_row(704, "analyst", "round 4")]
    close_on_remote(w.t.p3, branch)
    tick(w, writer)

    assert _end(w, chain[-1]) == ("ended", "closed")
    assert _replacements(w, chain[-1]) == []
    assert w.statuses() == {"f1": "held"}
    assert len(w.t.forge.creates) == 4


# --- A2 H15: refusals and unknowns ---------------------------------------------------------------------


def test_h15_a_closed_prs_refused_comment_read_is_unknown_not_no_feedback(world, caplog):
    """Without `read:issue` the comment read is 403: the closed PR's batch stays unresolved, its item not held; with it, held. (C23, Feedback)"""
    w = world
    w.t.forge.scopes = {"write:repository"}
    w.seed("f1")
    batch_id, branch, number = opened(w, FeedbackCurator(_files("f1")), caplog)
    close_on_remote(w.t.p3, branch)
    tick(w, FeedbackCurator())

    assert [r for r in w.t.forge.requests if r.url.path.endswith(f"/issues/{number}/comments")]
    assert _end(w, batch_id) == ("in_review", None)
    assert w.statuses() == {"f1": "in_batch"}

    w.t.forge.scopes.add("read:issue")
    tick(w, FeedbackCurator())
    assert w.statuses() == {"f1": "held"}, "control: the same close, read in full, holds the item"


@pytest.mark.parametrize("status", [401, 403, 422])
def test_h15_repeated_refusals_send_the_batch_to_a_person_at_the_ceiling(world, caplog, status):
    """Three consecutive refusals (401, 403, a persistent 4xx) count; at the ceiling the batch is needs_person with its items kept. (H15, D7)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, _number = opened(w, writer, caplog)
    w.t.forge.refuse("/reviews", status)
    seen = []
    for _ in range(3):
        tick(w, writer)
        b = w.batch_rows()[batch_id]
        seen.append((b.phase, b.refusals))

    assert seen == [("in_review", 1), ("in_review", 2), ("needs_person", 3)]
    assert w.statuses() == {"f1": "in_batch"}


def test_h15_refused_comment_reads_count_toward_the_ceiling_too(world, caplog):
    """A closed PR whose comments the token may not read: three ticks send its batch to a person, the item kept. (G-F7, H15)"""
    w = world
    w.t.forge.scopes = {"write:repository"}
    w.seed("f1")
    batch_id, branch, _number = opened(w, FeedbackCurator(_files("f1")), caplog)
    close_on_remote(w.t.p3, branch)
    seen = []
    for _ in range(3):
        tick(w, FeedbackCurator())
        b = w.batch_rows()[batch_id]
        seen.append((b.phase, b.refusals))

    assert seen == [("in_review", 1), ("in_review", 2), ("needs_person", 3)]
    assert w.statuses() == {"f1": "in_batch"}


@pytest.mark.parametrize("failure", ["500", "502", "503", "connect"])
def test_h15_a_server_error_or_a_lost_connection_is_unknown_and_never_counts(world, caplog, failure):
    """5xx and network faults leave the batch in review with no refusal counted, however many ticks. (H15, D7)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, number = opened(w, writer, caplog)
    if failure == "connect":
        w.t.forge.fault = lambda r: (httpx.ConnectError("down", request=r)
                                     if r.url.path.endswith(f"/pulls/{number}/reviews") else None)
    else:
        w.t.forge.refuse("/reviews", int(failure))
    before = len(w.t.forge.requests)
    for _ in range(5):
        tick(w, writer)

    asked = [r for r in w.t.forge.requests[before:] if r.method == "GET" and r.url.path.endswith(f"/pulls/{number}/reviews")]
    assert len(asked) >= 5, "the reconcile never asked for the reviews, so nothing was refused or counted"
    b = w.batch_rows()[batch_id]
    assert (b.phase, b.refusals) == ("in_review", 0)


def test_h15_a_good_read_resets_the_refusals(world, caplog):
    """Two refusals, one good read, two more: the count restarts and the batch stays in review. (H15)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, _number = opened(w, writer, caplog)
    counts = []
    for refusing in (True, True, False, True, True):
        w.t.forge.clear_refusals()
        if refusing:
            w.t.forge.refuse("/reviews", 403)
        tick(w, writer)
        b = w.batch_rows()[batch_id]
        counts.append((b.phase, b.refusals))

    assert counts == [("in_review", 1), ("in_review", 2), ("in_review", 0), ("in_review", 1), ("in_review", 2)]
