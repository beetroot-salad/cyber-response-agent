"""#1278 feedback: the replacement batch re-reads the feedback live and hands it over (A2 H13, H14), and its own
ends. Split from `test_1278_feedback.py` (one file's CI cost), whose scene, fixture and helpers these cases use.
"""
from __future__ import annotations


import pytest

from defender.tests.support.learning.core._feedback1278 import (
    FeedbackCurator,
    claim_by_hand,
    end_closed_by_hand,
    framed,
    opened,
    tick,
)
from defender.tests.support.learning.core._store1278 import (
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
    review_row,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSON_NAME,
    BoxSpy,
    critical_text,
    author_drain,
    own_store,
    remote_branches,
    without_clone,
)
from defender.tests.tenancy.tenant_1108_p4.test_1278_feedback import (
    STOP_BOUND,
    _due,
    _end,
    _files,
    _no_orphans,
    _replacements,
)
from defender.tests.tenancy.tenant_1108_p4 import test_1278_feedback as _1278_feedback

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

world = _1278_feedback.world  # the fixture, from `test_1278_feedback`

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


@own_store("the tick is the post-step's: its store is the port over the child's job socket")
@pytest.mark.parametrize("how", ["cancel", "sigterm"])
def test_replacement_a_stop_before_its_pr_keeps_the_items_due_with_the_generation_unchanged(world, post_step_helper, caplog, monkeypatch, how):
    """The post-step, forked, is stopped while the replacement's curator is blocked in a subprocess: the batch ends abandoned, the items are due again, the next tick replaces. (O7, D4, D8)"""
    from defender.tests.learning.branch.test_1344_post_step import post_step_in_container

    w = world
    old_id, _number = _due(w, caplog)
    marker = w.scratch / "sleeper"
    blocked = FeedbackCurator(_files("f1"), before_commit=blocked_in_subprocess(marker))
    monkeypatch.setenv(RENEW_ENV, "0.2")
    helper = post_step_helper()

    def body():
        return post_step_in_container(None, w.t.tenant_id, forward=helper.ask,
                                      author_tick=lambda _paths, *, store: author_drain(
                                          w.t, w.paths, trigger=blocked, box=BoxSpy(), store=store))
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


def test_1618_f7_a_closed_prs_feedback_is_authored_into_a_replacement_with_no_clone_on_the_host(world, caplog):
    """With no clone, the tick that finds feedback on a closed PR authors, pushes and opens its replacement from a private repository. (F7, F6)"""
    w = world
    old_id, _number = _due(w, caplog, comment="cite the alert rule, not the host")
    without_clone(w.t)
    curator = FeedbackCurator(_files("f1"))

    tick(w, curator)

    assert curator.served, critical_text(caplog)
    [replacement] = _replacements(w, old_id)
    assert [pr["head"]["ref"] for pr in w.t.forge.prs if pr["state"] == "open"] == [replacement.branch]
    assert replacement.branch in dict(remote_branches(w.t.remote))
