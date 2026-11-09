"""#1414 F2 steps 1-2 and Replies: the tick opens one issue per case, reads only eligible comments (D13's record,
D12's close rule), frames each by its run, and replies once where the person spoke.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging

import httpx
import pytest

from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.learning.feedback_1414._spec1414 import LOOKUP, LOOKUP_2, NAMED, OUTSIDER, OWNER
from defender.tests.tenancy.tenant_1108_p4._drain_support import remote_branches


def _loud(caplog, *words: str) -> bool:
    return any(r.levelno >= logging.WARNING and all(w in r.getMessage().lower() for w in words)
               for r in caplog.records)


# ---------------------------------------------------------------- F2 step 1: open (O2, A6)

def test_1414_a_request_opens_one_labelled_bot_issue_and_a_rerun_comments_on_it(fb):
    """The first request creates one labelled issue whose first line names the case; a rerun comments on it; a closed one gets nothing. O2/F2.1."""
    number = fb.opened("case-db07")

    [issue] = fb.issues("case-db07")
    assert issue["user"]["login"] == fb.bot
    assert len(fb.forge.issue_creates()) == 1
    assert S.open_issue_requests(fb.paths) == {}, "the served request was not released"

    fb.request("case-db07")
    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 1, "a rerun of an open case opened a second issue"
    assert len(fb.forge.comments_on(number, by=fb.bot)) == 1, "the rerun's summary was not commented"

    fb.forge.set_issue_state(number, "closed")
    fb.request("case-db07")
    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 1
    assert len(fb.forge.comments_on(number, by=fb.bot)) == 1, "a closed issue was commented (D6)"
    assert S.open_issue_requests(fb.paths) == {}


def test_1414_an_open_whose_reply_was_lost_is_recovered_not_repeated(fb):
    """A create the forge applied but whose reply was lost is found again by label, bot creator and first line; no second issue. O2/F2.1."""
    fb.forge.lose_reply = lambda r: r.method == "POST" and r.url.path.endswith("/issues")
    fb.request("case-lost")
    fb.tick(S.Decider())
    assert len(fb.issues("case-lost")) == 1, "premise: the forge holds the issue"

    fb.forge.lose_reply = None
    assert fb.tick(S.Decider()) == 0
    assert len(fb.issues("case-lost")) == 1, "the retried open made a second issue"
    [issue] = fb.issues("case-lost")
    comment = fb.forge.add_comment(issue["number"], user=OWNER, body="expected")
    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]], "the recovered issue was not recorded as the case's"


def test_1414_recovery_ignores_an_issue_not_created_by_the_bot(fb):
    """A labelled issue naming the case on its first line but created by a person is not the case's issue. O2/F2.1."""
    fb.forge.add_label(S.FEEDBACK_LABEL)
    fb.forge.add_issue(title="case-decoy", body="case-decoy\n\nplanted", user=OUTSIDER,
                       labels=[S.FEEDBACK_LABEL])
    fb.request("case-decoy")

    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 1
    assert {i["user"]["login"] for i in fb.issues("case-decoy")} == {OUTSIDER, fb.bot}


def test_1414_recovery_matches_the_case_id_exactly_not_as_a_substring(fb):
    """Bot-made labelled issues whose first line holds `case-1` only inside a longer id are not case-1's issue; a new one is made. O2/F2.1."""
    fb.forge.add_label(S.FEEDBACK_LABEL)
    decoys = [fb.forge.add_issue(title=name, body=f"{name}\n\nplanted", user=fb.bot, labels=[S.FEEDBACK_LABEL])
              for name in ("case-10", "my-case-1")]
    fb.request("case-1")

    assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 1, "a decoy naming a longer id was taken for the case's issue"
    [issue] = fb.issues("case-1")
    assert issue["number"] not in {d["number"] for d in decoys}
    assert issue["user"]["login"] == fb.bot


def test_1414_a_rerun_summary_lost_in_transit_is_not_commented_twice(fb):
    """A summary comment the forge applied but whose reply was lost is not posted again on the retry; a lost comment is. A6."""
    number = fb.opened("case-summary")
    fb.forge.lose_reply = lambda r: r.method == "POST" and r.url.path.endswith(f"/issues/{number}/comments")
    fb.request("case-summary")
    fb.tick(S.Decider())
    assert len(fb.forge.comments_on(number, by=fb.bot)) == 1, "premise: the forge applied the comment"

    fb.forge.lose_reply = None
    fb.tick(S.Decider())
    assert len(fb.forge.comments_on(number, by=fb.bot)) == 1, "the retried step posted the run's summary again"
    assert S.open_issue_requests(fb.paths) == {}

    fb.forge.fault = lambda r: httpx.ConnectError("down", request=r) if r.method == "POST" and r.url.path.endswith("/comments") else None
    fb.request("case-summary")
    fb.tick(S.Decider())
    assert len(fb.forge.comments_on(number, by=fb.bot)) == 1, "premise: this summary was not applied"
    fb.forge.fault = None
    fb.tick(S.Decider())
    assert len(fb.forge.comments_on(number, by=fb.bot)) == 2, "positive control: a summary never applied is posted"


def test_1414_an_issue_the_forge_no_longer_has_is_treated_as_closed_and_logged(fb, caplog):
    """A case whose recorded issue is gone gets no new issue and no comment; the request is released and the loss logged. A6."""
    number = fb.opened("case-gone")
    fb.forge.remove_issue(number)
    fb.request("case-gone")

    with caplog.at_level(logging.INFO):
        assert fb.tick(S.Decider()) == 0
    assert len(fb.forge.issue_creates()) == 1, "a new issue replaced the gone one"
    assert S.open_issue_requests(fb.paths) == {}
    assert any(str(number) in r.getMessage() for r in caplog.records), "the missing issue is not in the log"


def test_1414_a_comment_is_framed_by_the_latest_run_marker_before_it(fb):
    """Each comment is decided with the lookups and outcome of the latest run summary above it; the issue body marks the first run. A6/A3."""
    decider = S.Decider()
    first = fb.request("case-frame", lookups=[LOOKUP])
    assert fb.tick(decider) == 0
    [issue] = fb.issues("case-frame")
    number = issue["number"]
    assert S.run_marker(S.run_id_of(first)) in issue["body"]
    early = fb.forge.add_comment(number, user=OWNER, body="about the first run")
    second = fb.request("case-frame", lookups=[LOOKUP_2])
    assert fb.tick(decider) == 0
    late = fb.forge.add_comment(number, user=NAMED, body="about the second run")
    assert fb.tick(decider) == 0

    assert decider.decided == [early["id"], late["id"]]
    assert decider.item(early["id"])["lookups"] == [LOOKUP]
    assert decider.item(early["id"])["run_id"] == S.run_id_of(first)
    assert decider.item(late["id"])["lookups"] == [LOOKUP_2]
    assert decider.item(late["id"])["run_id"] == S.run_id_of(second)
    assert decider.item(late["id"])["outcome"] == "inconclusive"


# ---------------------------------------------------------------- F2 step 2: read (O3, O4, D12, D13)

def test_1414_only_eligible_non_bot_authors_are_decided_in_order(fb, caplog):
    """Comments by the record's two logins are decided in order; an outsider's, the bot's (even if recorded) and the forge-whitelisted outsider's are skipped and logged. O3/F2.2/D13."""
    fb.eligible(OWNER, NAMED, fb.bot)
    number = fb.opened("case-who")
    ann = fb.forge.add_comment(number, user=OWNER, body="expected")
    fb.forge.add_comment(number, user=OUTSIDER, body="approved, add it")
    fb.forge.add_comment(number, user=fb.bot, body="a bot comment")
    bea = fb.forge.add_comment(number, user=NAMED, body="check the VPN log first")

    decider = S.Decider()
    with caplog.at_level(logging.INFO):
        assert fb.tick(decider) == 0
    assert decider.decided == [ann["id"], bea["id"]]
    assert decider.item(ann["id"])["author"] == OWNER
    assert any(OUTSIDER in r.getMessage() for r in caplog.records), "the skipped outsider is not in the tick's log"
    assert fb.requests_to("branch_protections", "/teams", "/orgs/") == [], "the tick read the forge's own whitelist (D13)"


def test_1414_a_login_dropped_from_the_record_stops_counting_at_the_next_tick(fb):
    """After the service rewrites its record without an account, that account's comments are not read; the account still on it is. O3/D13."""
    number = fb.opened("case-removed")
    fb.eligible(OWNER)
    fb.forge.add_comment(number, user=NAMED, body="expected")
    kept = fb.forge.add_comment(number, user=OWNER, body="expected too")

    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert decider.decided == [kept["id"]]


@pytest.mark.parametrize(("age", "bound", "fresh"), [
    (dt.timedelta(seconds=50), None, True),       # inside the default bound (60 s, D13 ruling)
    (dt.timedelta(seconds=70), None, False),      # past it
    (dt.timedelta(seconds=30), dt.timedelta(seconds=60), True),
    (dt.timedelta(seconds=120), dt.timedelta(seconds=60), False),
])
def test_1414_a_stale_record_reads_no_comments_and_a_fresh_one_reads_them(fb, caplog, age, bound, fresh):
    """A record older than the bound makes the tick read nothing and log why; the comment is read once it is fresh. D13."""
    number = fb.opened("case-stale")
    comment = fb.forge.add_comment(number, user=OWNER, body="expected")
    fb.eligible(OWNER, NAMED, age=age)
    seams = {} if bound is None else {"eligibility_max_age": bound}

    decider = S.Decider()
    with caplog.at_level(logging.INFO):
        assert fb.tick(decider, **seams) == 0
    assert decider.decided == ([comment["id"]] if fresh else [])
    if not fresh:
        assert _loud(caplog, "eligib"), "a stale record is not logged"
        fb.eligible(OWNER, NAMED)
        assert fb.tick(decider, **seams) == 0
        assert decider.decided == [comment["id"]], "the position moved past a comment read under a stale record"
        assert fb.replies(number, comment["id"]), "the comment's outcome was not delivered once fresh"


def test_1414_an_absent_record_reads_no_comments_and_counts_nothing(fb, caplog):
    """A tenant whose row holds no eligibility record is read as stale: nothing decided, logged, and a comment two attempts into its ceiling is still decided normally once fresh. D13/A4."""
    number = fb.opened("case-absent")
    comment = fb.forge.add_comment(number, user=OWNER, body="expected")
    decider = S.Decider({comment["id"]: [S.answer(approve=(9,)), S.answer(approve=(9,)),
                                         S.answer(reason="nothing to learn")]})
    for _ in range(2):  # two refused answers: the comment stands at 2 of 3
        assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]] * 2
    bare = fb.t.directory_with()  # a tenant row the service never wrote a record to

    with caplog.at_level(logging.INFO):
        for _ in range(5):
            assert fb.tick(decider, directory=bare) == 0
    assert decider.decided == [comment["id"]] * 2, "a comment was read under an absent record"
    assert _loud(caplog, "eligib")
    assert fb.replies(number, comment["id"]) == []

    assert fb.tick(decider) == 0  # the scene's directory holds a fresh record
    assert decider.decided == [comment["id"]] * 3
    [reply] = fb.replies(number, comment["id"])
    assert "could not be processed" not in reply["body"], "stale ticks were counted as attempts"
    assert "nothing to learn" in reply["body"]


def test_1414_a_comment_is_decided_once_across_ticks(fb):
    """A decided comment is not decided again on a later tick; a later comment is. O4/P5."""
    number = fb.opened("case-once")
    first = fb.forge.add_comment(number, user=OWNER, body="no change needed")
    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert fb.tick(decider) == 0
    second = fb.forge.add_comment(number, user=OWNER, body="one more thing")
    assert fb.tick(decider) == 0

    assert decider.decided == [first["id"], second["id"]]


def test_1414_comments_before_the_close_are_decided_after_it_are_ignored_and_a_reopen_reads_on(fb):
    """On a closed issue, comments dated before closed_at are decided and replied to, later ones never read, even after a reopen. D12/O4."""
    number = fb.opened("case-closed")
    before = fb.forge.add_comment(number, user=OWNER, body="said before the close", created_at=fb.at(-20))
    after = fb.forge.add_comment(number, user=OWNER, body="said while closed", created_at=fb.at(-5))
    fb.forge.set_issue_state(number, "closed", at=fb.at(-10))
    decider = S.Decider()
    assert fb.tick(decider) == 0
    assert decider.decided == [before["id"]]
    assert len(fb.replies(number, before["id"])) == 1, "the pre-close comment's reply was not posted on the closed issue"

    fb.forge.set_issue_state(number, "open")
    later = fb.forge.add_comment(number, user=OWNER, body="read after the reopen")
    assert fb.tick(decider) == 0
    assert decider.decided == [before["id"], later["id"]]
    assert after["id"] not in decider.decided


def test_1414_a_decision_recorded_before_a_close_is_still_replied_to(fb):
    """A reply that could not be posted before the issue closed is posted on the closed issue. D12/O5."""
    number = fb.opened("case-late-reply")
    comment = fb.forge.add_comment(number, user=OWNER, body="nothing to change")
    fb.forge.respond = lambda r: (httpx.Response(503, json={}) if r.method == "POST" and r.url.path.endswith(f"/issues/{number}/comments") else None)
    decider = S.Decider({comment["id"]: S.answer(reason="nothing to learn")})
    fb.tick(decider)
    assert decider.decided == [comment["id"]]
    assert fb.replies(number, comment["id"]) == [], "premise: the reply was refused"

    fb.forge.respond = None
    fb.forge.set_issue_state(number, "closed")
    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]], "the recorded decision was taken again"
    assert len(fb.replies(number, comment["id"])) == 1


def test_1414_a_refused_comment_read_loses_nothing(fb):
    """A refused comment listing leaves the position where it was; the next tick reads the comment. O9."""
    number = fb.opened("case-fault")
    comment = fb.forge.add_comment(number, user=OWNER, body="expected")

    def refuse(request):
        if request.method == "GET" and request.url.path.endswith("/comments"):
            return httpx.ConnectError("refused", request=request)
        return None

    fb.forge.fault = refuse
    decider = S.Decider()
    fb.tick(decider)
    assert decider.decided == []

    fb.forge.fault = None
    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]]


# ---------------------------------------------------------------- Replies (O5)

def test_1414_a_no_change_gets_one_reply_with_its_marker_and_the_reason(fb):
    """A comment the model answers with a reason gets exactly one bot reply carrying its marker and that reason, however many ticks run. O5."""
    number = fb.opened("case-nochange")
    comment = fb.forge.add_comment(number, user=OWNER, body="thanks")
    decider = S.Decider({comment["id"]: S.answer(reason="a thanks, nothing to learn from it")})

    for _ in range(3):
        assert fb.tick(decider) == 0
    [reply] = fb.replies(number, comment["id"])
    assert "no change" in reply["body"].lower()
    assert "a thanks, nothing to learn from it" in reply["body"]
    assert reply["user"]["login"] == fb.bot


def test_1414_a_reply_already_on_the_issue_is_not_posted_again(fb):
    """Whether a reply is owed is read from the issue: a bot comment carrying the marker already settles it. O5/P5."""
    number = fb.opened("case-owed")
    comment = fb.forge.add_comment(number, user=OWNER, body="nothing to change here")
    fb.forge.add_comment(number, user=fb.bot, body=f"no change {S.marker(comment['id'])}")
    decider = S.Decider({comment["id"]: S.answer(reason="nothing to learn")})

    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]], "premise: the comment was decided"
    assert len(fb.replies(number, comment["id"])) == 1


def test_1414_a_lost_reply_is_posted_again_but_a_seen_one_is_settled_for_good(fb):
    """A reply that never reached the issue is posted by a later tick; once seen, deleting it does not bring it back (the decision is settled). O5/A1."""
    number = fb.opened("case-settle")
    lost = fb.forge.add_comment(number, user=OWNER, body="one")
    fb.forge.respond = lambda r: (httpx.Response(503, json={}) if r.method == "POST" and r.url.path.endswith("/comments") else None)
    decider = S.Decider({lost["id"]: S.answer(reason="r1")})
    fb.tick(decider)
    assert fb.replies(number, lost["id"]) == []
    fb.forge.respond = None
    assert fb.tick(decider) == 0
    [reply] = fb.replies(number, lost["id"])

    assert fb.tick(decider) == 0  # the tick that sees the reply on the issue
    fb.forge.remove_comment(number, reply["id"])
    assert fb.tick(decider) == 0
    assert fb.replies(number, lost["id"]) == [], "a settled decision was read again and its reply re-posted"
    assert decider.decided == [lost["id"]]
    assert remote_branches(fb.t.remote, S.FEEDBACK_PREFIX) == {}


# ---------------------------------------------------------------- a rotated tenant (D13: every generation's bot)

def _rotated(fb):
    """The tenant after a rotation: its first generation destroyed, the fixture's bot live; the directory and the old bot's login."""
    from defender.tenancy import TenantDirectory
    from defender.tests.support.tenancy._active1214 import generation_fields
    from defender.tests.support.tenancy._proxied1391 import with_sign_login

    tid = fb.t.tenant_id
    old = with_sign_login(tid, generation_fields(tid, fb.tmp / "secrets", salt="g0", status="destroyed"))
    new = with_sign_login(tid, generation_fields(tid, fb.tmp / "secrets", salt="g1"))
    assert new["bot_login"] == fb.bot, "premise: the live generation is the forge's login"
    twin = fb.t.repository_with(generations=[old, new])
    asyncio.run(twin.record_merge_eligibility(
        tid, logins=frozenset({OWNER, NAMED, old["bot_login"]}), read_at=dt.datetime.now(dt.UTC)))
    return TenantDirectory(lambda: twin), old["bot_login"]


def test_1414_what_the_old_generations_bot_made_is_still_the_bots(fb):
    """After a rotation the old bot's issue is recovered, its run summaries and replies are seen, and its comments are never decided. D13/O2/O3/A6."""
    directory, old_bot = _rotated(fb)
    case = "case-rotated"
    first, second = fb.request(case), fb.run("case-rotated-2")
    fb.forge.add_label(S.FEEDBACK_LABEL)
    issue = fb.forge.add_issue(title=case, body=f"{case}\n\n{S.run_marker(S.run_id_of(first))}", user=old_bot,
                               labels=[S.FEEDBACK_LABEL])
    number = issue["number"]
    fb.forge.add_comment(number, user=old_bot, body=f"a later run {S.run_marker(S.run_id_of(second))}")
    spoken = fb.forge.add_comment(number, user=OWNER, body="nothing to change")
    fb.forge.add_comment(number, user=old_bot, body=f"no change {S.marker(spoken['id'])}")
    chatter = fb.forge.add_comment(number, user=old_bot, body="a note the old bot left")
    decider = S.Decider({spoken["id"]: S.answer(reason="nothing to learn")})
    posted = len(fb.forge.comments_on(number))

    assert fb.tick(decider, directory=directory) == 0
    S.queue_open_issue(fb.paths, case_id=case, tenant_id=fb.t.tenant_id, run_id=S.run_id_of(second),
                       outcome="inconclusive", lookups=[S.LOOKUP])
    assert fb.tick(decider, directory=directory) == 0

    assert fb.forge.issue_creates() == [], "the old bot's issue was not recognised and a second was made"
    assert [i["number"] for i in fb.issues(case)] == [number]
    assert S.open_issue_requests(fb.paths) == {}
    assert len(fb.forge.comments_on(number)) == posted, "a summary or reply the old bot already made was posted again"
    assert decider.decided == [spoken["id"]], "the old bot's comment was decided, or the person's was not"
    assert chatter["id"] not in decider.decided
    positive = fb.forge.add_comment(number, user=NAMED, body="control: a person's later comment")
    assert fb.tick(decider, directory=directory) == 0
    assert decider.decided == [spoken["id"], positive["id"]]
    assert len(fb.replies(number, positive["id"])) == 1
