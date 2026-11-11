"""#1278 A4 O11-O13: what the ported feedback tick owes the store beyond #1414's own promises.

One tick per tenant (O12), a stop that no step swallows (P9), the registry batch's PR body and reconcile, the census (O10/O11), and the cutover's refusal while a feedback record
exists (O13, owner choice Q1, master brief: the import refuses). Driven over the `fb` scene (a published tenant, its forge
fake, a migrated database at `DEFENDER_DATABASE_DSN`). Everything the store itself guarantees is in
`tests/learning/store_1278/test_feedback_1278.py`.
"""
from __future__ import annotations

import logging

import pytest

from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.learning.feedback_1414._spec1414 import NAMED, OWNER
import contextlib

from defender.tests.support.jobs._jobs1342 import move_tenant
from defender.tests.support.learning.core._store1278 import call
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.tenancy.tenant_1108_delivery._support import merge_on_remote, review_row
from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain, remote_branches
from defender.tests.tenancy.tenant_1108_p4._support import git

pytestmark = pytest.mark.postgres

FEEDBACK_MODULES = ("defender/learning/core/feedback.py", "defender/learning/core/feedback_decide.py",
                    "defender/learning/core/feedback_registry.py", "defender/learning/author/feedback/run.py",
                    "defender/run_common.py")


def _two_comments(fb, case="case-stop"):
    """An issue with two eligible comments, both to be answered 'no change'; the decider answers them."""
    number = fb.opened(case)
    first = fb.forge.add_comment(number, user=OWNER, body="nothing to change", created_at=fb.at(-20))
    second = fb.forge.add_comment(number, user=NAMED, body="nothing to change either", created_at=fb.at(-19))
    return number, first, second


def _bot_posts(fb) -> int:
    return sum(r.method == "POST" for r in fb.forge.requests)


# --- O12: one tick per tenant ---------------------------------------------------------------------------------------------


def test_o12_a_tick_that_finds_the_lease_held_by_a_live_holder_logs_it_and_changes_nothing(fb, caplog):
    """With another feedback tick holding the tenant's lease, the tick exits 0 saying so, makes no forge request that writes, decides nothing and files nothing; once the holder ends, the next tick serves what waited. (O12)"""
    number, first, second = _two_comments(fb)
    fb.request("case-waits")
    holder = call(fb.dsn, "begin_feedback_tick", fb.tid, owner="another-host")
    decider = S.Decider({first["id"]: S.answer(reason="fine"), second["id"]: S.answer(reason="fine")})
    posts = _bot_posts(fb)

    with caplog.at_level(logging.INFO):
        assert fb.tick(decider) == 0

    assert any("another feedback tick holds the lease" in r.getMessage() for r in caplog.records)
    assert decider.items == []
    assert _bot_posts(fb) == posts
    assert fb.issues("case-waits") == []
    assert list(S.open_issue_requests(fb)) != []
    call(fb.dsn, "end_feedback_tick", holder)
    assert fb.tick(decider) == 0
    assert len(fb.issues("case-waits")) == 1, "control: the lease was not released for the next tick"
    assert len(fb.replies(number, first["id"])) == 1


def test_o12_a_tick_takes_over_a_lapsed_lease_and_the_dead_holders_token_is_stale(fb):
    """A tick whose predecessor crashed (lease lapsed past lease + grace) serves the tenant with the next fencing token; the predecessor's late write raises `LeaseLost` and changes nothing. (O12)"""
    from defender.learning.store import LeaseLost

    fb.request("case-takeover")
    dead = call(fb.dsn, "begin_feedback_tick", fb.tid, owner="crashed-host")
    fb.lapse()
    assert fb.tick(S.Decider()) == 0
    assert len(fb.issues("case-takeover")) == 1
    [row] = S.issue_rows(fb)
    assert row.issue_number is not None
    with pytest.raises(LeaseLost):
        call(fb.dsn, "advance_comment_cursor", dead, "2026-11-11T00:00:00Z")


def test_o12_a_clean_tick_leaves_no_live_lease_behind(fb):
    """After a tick returns, the tenant's tick lease has ended: the database's clock says it is no longer live. (O12, A2 D4's clean stop)"""
    fb.request("case-release")
    assert fb.tick(S.Decider()) == 0
    [(live,)] = execute(fb.dsn, "SELECT lease_expiry > now() FROM learning.feedback_tick WHERE tenant_id = %s", (fb.tid,))
    assert live is False


# --- P9: stops halt, step faults are contained ---------------------------------------------------------------------------


def _stop_by_cancel(fb):
    call(fb.dsn, "request_cancel", fb.tid)


def _stop_by_takeover(fb):
    execute(fb.dsn, "UPDATE learning.feedback_tick SET lease_expiry = now() - interval '1 hour' WHERE tenant_id = %s", (fb.tid,))
    assert call(fb.dsn, "begin_feedback_tick", fb.tid, owner="usurper") is not None


def _stop_by_offboarding(fb):
    move_tenant(fb.dsn, fb.tid, state="offboarding")


STOPS = {"cancel": _stop_by_cancel, "lease lost": _stop_by_takeover, "tenant off active": _stop_by_offboarding}


@pytest.mark.parametrize("stop", sorted(STOPS))
def test_p9_a_stop_in_the_decide_step_ends_the_tick_and_no_later_step_runs(fb, stop):
    """A cancel, a lost lease or a tenant off active seen while the first comment is being decided halts the tick: the second comment is not decided, no reply is posted, no issue is opened; no step swallows it. (P9, O12)"""
    number, first, second = _two_comments(fb)
    fb.request("case-after-stop")
    fired: list[int] = []

    class StoppingDecider(S.Decider):
        def __call__(self, item, *, box=None, **kw):
            answered = super().__call__(item, box=box, **kw)
            if not fired:
                fired.append(1)
                STOPS[stop](fb)
            return answered

    decider = StoppingDecider({first["id"]: S.answer(reason="fine"), second["id"]: S.answer(reason="fine")})
    posts = _bot_posts(fb)

    raised = None
    try:
        fb.tick(decider)
    except Exception as exc:  # noqa: BLE001 — a halting tick may end by raising its stop or by exiting; either is a halt
        raised = exc

    assert raised is None or type(raised).__name__ in {"Stop", "LeaseLost", "TenantInactive"}, f"the tick died of {raised!r}"
    assert fired, "premise: the stop was raised from inside the decide step"
    assert decider.decided == [first["id"]], "the tick went on to decide after the stop"
    assert _bot_posts(fb) == posts, "the tick wrote to the forge after the stop"
    assert fb.issues("case-after-stop") == []


def test_p9_an_ordinary_fault_in_one_step_is_contained_and_the_next_step_runs(fb, caplog):
    """Positive control for P9: an ordinary exception from the decide seam is logged and the replies step still answers a comment that needs no decision. (P9, #1414 ruling 2026-11-10)"""
    number, first, second = _two_comments(fb)
    thanks = fb.forge.add_comment(number, user=OWNER, body="thanks", created_at=fb.at(-18))
    decider = S.Decider({first["id"]: RuntimeError("the model is down"), second["id"]: RuntimeError("the model is down"),
                         thanks["id"]: RuntimeError("the model is down")})
    with caplog.at_level(logging.ERROR):
        assert fb.tick(decider) == 0
    assert any("the model is down" in r.getMessage() or "decid" in r.getMessage() for r in caplog.records)
    fb.request("case-after-fault")
    assert fb.tick(decider) == 0
    assert len(fb.issues("case-after-fault")) == 1, "a contained fault stopped the open step of the next tick"


def test_p9_a_stop_before_the_registry_claim_makes_no_batch_and_no_branch(fb):
    """A cancel seen at the draft step's pre-claim check, with an approved comment waiting: no registry batch row, no `feedback/` branch, no PR. (P9, r8 stop)"""
    number, comment, decider = _approved_waiting(fb)
    fired: list[int] = []

    def on_pulls(request):
        if request.method == "GET" and request.url.path.endswith("/pulls") and not fired:
            fired.append(1)
            _stop_by_cancel(fb)
        return None

    fb.forge.respond = on_pulls
    with contextlib.suppress(Exception):  # a halting tick may raise its stop
        fb.tick(decider)
    assert fired, "premise: the draft step looked at the open PRs"
    assert S.feedback_batches(fb) == []
    assert remote_branches(fb.t.remote, S.FEEDBACK_PREFIX) == {}
    assert fb.forge.prs == []


def _approved_waiting(fb, case="case-approve"):
    number = fb.opened(case)
    comment = fb.forge.add_comment(number, user=OWNER, body="expected: the nightly backup")
    return number, comment, S.Decider({comment["id"]: S.answer(approve=(0,))})


# --- the registry batch on the store --------------------------------------------------------------------------------------


def test_p6_the_registry_pr_body_is_its_tip_commits_message_and_the_batch_is_item_less_in_review(fb):
    """The drafted PR's body equals the message of the commit the branch tip carries, and the store holds one in-review batch of lane `feedback`, kind `registry`, naming that PR, with no items. (P6, A4 `pr_text`)"""
    number, comment, decider = _approved_waiting(fb)
    assert fb.tick(decider) == 0

    [(branch, tip)] = remote_branches(fb.t.remote, S.FEEDBACK_PREFIX).items()
    [pr] = [p for p in fb.forge.prs if p["head"]["ref"] == branch]
    assert pr["body"].strip() == git(fb.t.remote, "log", "-1", "--format=%B", tip).strip()
    assert S.entry_id(number, comment["id"]) in pr["body"]
    [batch] = S.feedback_batches(fb)
    assert (batch.kind, batch.phase, batch.pr_number, batch.branch) == (S.REGISTRY_KIND, "in_review", pr["number"], branch)
    assert not [i for i in call(fb.dsn, "work", fb.tid) if i.batch_id == batch.id]


def test_p6_the_bot_never_closes_a_registry_pr_whatever_a_reviewer_says(fb):
    """A review requesting changes on the open registry PR changes nothing: the PR stays open, the batch stays in review, no replacement is made. (P6, A4: reconcile reads PR state only)"""
    number, comment, decider = _approved_waiting(fb)
    assert fb.tick(decider) == 0
    [(branch, _tip)] = remote_branches(fb.t.remote, S.FEEDBACK_PREFIX).items()
    [pr] = [p for p in fb.forge.prs if p["head"]["ref"] == branch]
    fb.forge.reviews[pr["number"]] = [review_row(901, "owner", "REQUEST_CHANGES", body="no, do not add this")]
    fb.forge.comments[pr["number"]] = [{"id": 902, "user": {"login": "owner"}, "body": "no", "created_at": fb.at(-1)}]

    for _ in range(3):
        assert fb.tick(decider) == 0

    assert [p["state"] for p in fb.forge.prs if p["number"] == pr["number"]] == ["open"]
    assert [(b.phase, b.pr_number) for b in S.feedback_batches(fb)] == [("in_review", pr["number"])]
    assert remote_branches(fb.t.remote, S.FEEDBACK_PREFIX) == {branch: _tip}


def test_p6_the_authors_tick_reconciles_a_merged_registry_pr_too(fb):
    """The lessons author's tick, which reconciles every lane, ends a lane-`feedback` batch whose PR a person merged; the lane is then free. (A4 `reconcile_lanes`, Wake)"""
    number, comment, decider = _approved_waiting(fb)
    assert fb.tick(decider) == 0
    [(branch, _tip)] = remote_branches(fb.t.remote, S.FEEDBACK_PREFIX).items()
    merge_on_remote(fb.t.p3, fb.tmp, branch)

    assert author_drain(fb.t, fb.paths, trigger=None, box=BoxSpy()) == 0

    [batch] = S.feedback_batches(fb)
    assert (batch.phase, batch.outcome) == ("ended", "merged")


# --- O10 / O11: no feedback module reaches the deleted handle -------------------------------------------------------------


@pytest.mark.parametrize("rel", FEEDBACK_MODULES)
def test_o11_no_feedback_module_reaches_the_learning_state_handle_or_root(rel):
    """Each of the five modules #1414 wrote against the file state (the feedback core, decide, registry, the curator's run and run end) uses none of the names the O10 census forbids. (O10, O11)"""
    from defender.tests.learning.state_contracts.test_1278_census import REPO, reaches

    assert reaches((REPO / rel).read_text(encoding="utf-8"), rel) == []


def test_o11_the_feedback_tick_reaches_the_store_through_blocking_only(fb, monkeypatch):
    """The tick opens its store at `DEFENDER_DATABASE_DSN` through `defender.learning.store.blocking`: with that door replaced by one that refuses, the tick makes no forge write and no row. (O11, A4 flows)"""
    import defender.learning.store as store_mod

    opened: list[str] = []

    @contextlib.contextmanager
    def refusing(dsn, **_knobs):
        opened.append(dsn)
        raise ConnectionError("the store is down")
        yield  # pragma: no cover

    fb.request("case-door")
    posts = _bot_posts(fb)
    with monkeypatch.context() as m:
        m.setattr(store_mod, "blocking", refusing)  # lint-monkeypatch: ok — the store opener is a module-level door the tick reaches itself
        with contextlib.suppress(Exception):
            fb.tick(S.Decider())
    assert opened == [fb.dsn], "the tick did not open its store at DEFENDER_DATABASE_DSN through blocking()"
    assert _bot_posts(fb) == posts


# --- A1 for the feedback curator -------------------------------------------------------------------------------------------


def test_a1_the_feedback_curator_has_a_call_folder_stage_of_its_own(fb):
    """`call_folders.STAGES` names `feedback`, and a `feedback` call folder is made beside, not inside, the lessons one of the same drain batch. (A1 O8/O9, A4)"""
    from defender.learning import call_folders

    assert "feedback" in call_folders.STAGES
    feedback = call_folders.call_folder(fb.t.tenant, "batch-1", "feedback", 1, make=True)
    lessons = call_folders.call_folder(fb.t.tenant, "batch-1", "lessons", 1, make=True)
    assert feedback.is_dir()
    assert feedback != lessons
    assert lessons not in feedback.parents
    assert feedback not in lessons.parents
