"""#1278 feedback and reconcile: what a tick does with a batch's PR once people have acted on it.

Every case drives `author_drain` through the CLI's stage runner over `p4_tenant` (a real clone, a loopback
origin, P3's forge fake with reviews, comments, scripted refusals and PR close), the store at
`DEFENDER_DATABASE_DSN` on a migrated database holding the tenant's row. Forge state is changed as a person
would: merge (optionally editing the merge), close, a review, a comment. The curator is `FeedbackCurator`.
A crash between the reconcile's end and the replacement's claim is made by ending the batch by hand.
"""
from __future__ import annotations


import httpx
import pytest

from defender.tests.support.learning.core._feedback1278 import (
    FeedbackCurator,
    Scene,
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
    call,
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
    without_clone,
)
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_delivery._support import set_pull_state
from defender.tests.tenancy.tenant_1108_p4._support import git

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

READ_ISSUE = {"write:repository", "write:issue"}  # the integration's scopes (A4); `read:issue` alone also reads
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
    wake_at(monkeypatch, 1)  # thresholds are per kind (D8): both kinds are due, so one batch takes all three
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
        review_row(900, "late-reviewer", "COMMENT", body="the only words, past the first 50 of 70 reviews")]
    close_on_remote(w.t.p3, old_branch)
    tick(w, writer)

    assert len(_replacements(w, old_id)) == 1, "the words on the last page were not read"
    assert framed(writer.seen_text(), "the only words, past the first 50 of 70 reviews")


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
    [review_row(635, "owner", "REQUEST_CHANGES"), review_row(636, "owner", "COMMENT", body="one more thought")],
], ids=["official", "read-only-reviewer", "another-reviewer-approved-later", "same-reviewer-commented-later"])
def test_feedback_a_live_changes_requested_review_on_an_open_pr_gets_it_closed_and_replaced(world, caplog, reviews):
    """The reconciler closes the PR and the batch ends closed, its replacement following in the same tick; a later COMMENT review does not displace the reviewer's request (Forgejo 17 keeps both rows). (H7, C25, D8)"""
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




def batch_row_of(w, batch_id):
    from defender.tests.support.learning.core._release1537 import row

    return row(w.dsn, batch_id)


@pytest.mark.parametrize("passes", [1, 3], ids=["one_pass", "to_the_ceiling"])
def test_feedback_a_close_that_never_takes_is_counted_to_the_ceiling_and_goes_to_a_person(world, caplog, passes):
    """Each pass's close the forge takes but never applies counts like a refusal: the batch reaches a person at the
    ceiling instead of looping behind a clean check. (H15; #1558 review)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, _number = opened(w, writer, caplog)
    w.t.forge.reviews[_number] = [review_row(638, "owner", "REQUEST_CHANGES", body="wrong lane")]
    w.t.forge.respond = lambda request: httpx.Response(201, json={}) if request.method == "PATCH" else None
    for _ in range(passes):
        tick(w, writer)
    got = batch_row_of(w, batch_id)
    assert got["refusals"] == passes
    assert got["phase"] == ("needs_person" if passes == 3 else "in_review")
    if passes == 3:
        assert got["cause"] == "forge_refused", got
        assert "still reads open" in got["reason"], got


def test_feedback_a_close_for_changes_requested_that_does_not_take_ends_nothing_and_is_made_again_next_pass(world, caplog):
    """The forge accepts the close but the PR reads open again: the batch is not ended closed beside a PR still open (no
    replacement opens over it, nothing would close it later); it stays in review and the next pass closes and replaces.
    (H7, D8; #1558 review: the same rule as an abandon's close)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, number = opened(w, writer, caplog)
    w.t.forge.reviews[number] = [review_row(637, "owner", "REQUEST_CHANGES", body="wrong lane")]
    w.t.forge.respond = lambda request: httpx.Response(201, json={}) if request.method == "PATCH" else None
    tick(w, writer)
    assert [p["state"] for p in w.t.forge.prs if p["number"] == number] == ["open"], "premise: the close did not take"
    assert _end(w, batch_id) == ("in_review", None), "the batch ended closed beside its open PR"
    assert _replacements(w, batch_id) == []
    assert batch_row_of(w, batch_id)["refusals"] == 1, "a close that did not take was not counted"
    w.t.forge.respond = None
    tick(w, writer)
    assert _end(w, batch_id) == ("ended", "closed")
    [new] = _replacements(w, batch_id)
    assert new.phase == "in_review"


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


# --- #1618 K12: a reconcile reads only what the tick fetched, by branch, pull ref or id; no clone on the host ------------


def _cut_by_a_squash_of_the_reviewers_own(w, branch):
    """A person merges the batch's PR as a squash whose result cites f1 alone, deleting the branch: the merge commit is on
    `main`, the branch tip (citing f1 and f2) is reachable from no branch, only from the PR's `refs/pull/<n>/head`."""
    def edit(checkout):
        (checkout / LESSON_PATH).write_text(lesson_citing("f1"), encoding="utf-8")
    merge = push_to_remote(w.t.p3, w.scratch, edit, "squash of the reviewer's own")
    set_pull_state(w.t.remote, branch, merged=True, delete_branch=True, merge_commit=merge)
    return merge


def _two_cited_in_review(w, caplog):
    w.seed("f1", "f2")
    batch_id, branch, number = opened(w, FeedbackCurator(_files("f1", "f2")), caplog)
    assert w.statuses() == {"f1": "in_batch", "f2": "in_batch"}
    return batch_id, branch, number


def test_1618_k12_a_merge_whose_branch_was_deleted_is_read_through_the_prs_pull_ref_with_no_clone(world, caplog):
    """The branch is gone after the merge: the tick fetches `refs/pull/<n>/head` and holds f2, which the tip cites and the merge dropped. (K12, F6)"""
    w = world
    batch_id, branch, number = _two_cited_in_review(w, caplog)
    without_clone(w.t)
    _cut_by_a_squash_of_the_reviewers_own(w, branch)
    assert K.remote_ref(w.t, f"refs/heads/{branch}") is None, "premise: the branch is deleted"
    assert K.remote_ref(w.t, f"refs/pull/{number}/head"), "premise: the pull ref stays (C-F5)"

    tick(w, FeedbackCurator())

    assert w.statuses() == {"f1": "published", "f2": "held"}, critical_text(caplog)
    assert _end(w, batch_id) == ("ended", "merged")


def test_1618_k12_a_branch_tip_no_ref_names_any_more_is_fetched_by_id_not_assumed_from_the_record(world, caplog):
    """The pull ref is gone too: the tip the record and the PR name is fetched by id, so f2 is still held. (K12, K5)"""
    w = world
    batch_id, branch, number = _two_cited_in_review(w, caplog)
    without_clone(w.t)
    _cut_by_a_squash_of_the_reviewers_own(w, branch)
    git(w.t.remote, "update-ref", "-d", f"refs/pull/{number}/head")

    tick(w, FeedbackCurator())

    assert w.statuses() == {"f1": "published", "f2": "held"}, critical_text(caplog)
    assert _end(w, batch_id) == ("ended", "merged")


def test_1618_k12_a_tip_forgejo_no_longer_serves_is_never_read_from_what_the_tick_did_not_fetch(world, caplog):
    """The tip is neither on a ref nor fetchable: the merge is not settled from an object the tick never held; the batch stays in review. (K12)"""
    w = world
    batch_id, branch, number = _two_cited_in_review(w, caplog)
    without_clone(w.t)
    _cut_by_a_squash_of_the_reviewers_own(w, branch)
    git(w.t.remote, "update-ref", "-d", f"refs/pull/{number}/head")
    git(w.t.remote, "reflog", "expire", "--expire=now", "--all")
    git(w.t.remote, "gc", "--prune=now", "--quiet")

    tick(w, FeedbackCurator())

    assert [r.url.path for r in w.t.forge.requests if r.method == "GET" and r.url.path.rstrip("/").endswith(f"/pulls/{number}")], \
        "premise: the tick opened and read the merged PR"
    assert _end(w, batch_id) == ("in_review", None), "the merge was settled with no tip to read"
    assert w.statuses() == {"f1": "in_batch", "f2": "in_batch"}


def test_1618_k12_a_merge_that_lands_after_the_tick_opened_is_found_by_one_more_fetch(world, caplog):
    """The PR is merged while the tick is already open (its first read of the PR): the reconcile fetches again and publishes f1, holds f2. (K12, F6)"""
    w = world
    batch_id, branch, number = _two_cited_in_review(w, caplog)
    without_clone(w.t)
    merged = {}

    def merge_when_the_pr_is_first_read(request):
        if not merged and request.method == "GET" and request.url.path.rstrip("/").endswith(f"/pulls/{number}"):
            merged["main"] = merge_on_remote(w.t.p3, w.scratch, branch,
                                             edit=reviewer_removes_citation(LESSON_NAME, lesson_citing("f1")))
        return None

    w.t.forge.fault = merge_when_the_pr_is_first_read

    tick(w, FeedbackCurator())

    assert merged, "premise: the merge landed during the tick"
    assert w.statuses() == {"f1": "published", "f2": "held"}, critical_text(caplog)
    assert _end(w, batch_id) == ("ended", "merged")
