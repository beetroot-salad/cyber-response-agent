"""#1414 F2 step 3 and D11's hand-off: the decide answer's schema (A3), retries and the ceiling (A4/O9), and the
lessons row an instruction becomes (O7).
"""
from __future__ import annotations

import contextlib
import datetime as dt
import logging

import httpx
import pytest

from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.learning.feedback_1414._spec1414 import LOOKUP, LOOKUP_2, NAMED, OWNER, today
from defender.tests.tenancy.tenant_1108_p4._drain_support import remote_branches

CEILING = 3


def _drafts(fb):
    return remote_branches(fb.t.remote, S.FEEDBACK_PREFIX)


def _open(fb, case, *, lookups=None):
    """The issue for `case`, opened by one tick with no comment on it yet; its number."""
    fb.request(case, lookups=lookups)
    assert fb.tick(S.Decider()) == 0
    [issue] = fb.issues(case)
    return issue["number"]


def _scene(fb, case, *, lookups=None, by=OWNER, body="expected: the nightly backup"):
    number = _open(fb, case, lookups=lookups)
    return number, fb.forge.add_comment(number, user=by, body=body)


# ---------------------------------------------------------------- A3: the answer schema

_ANSWERS = {
    "index past the lookups": S.answer(approve=(0, 2)),
    "negative index": S.answer(approve=(-1,)),
    "approve not a list": {"approve": "0", "review_by": None, "instruction": None, "reason": None},
    "unparsable date": S.answer(approve=(0,), review_by="after the next audit"),
    "date before the comment": S.answer(
        approve=(0,), review_by=(today() - dt.timedelta(days=1)).isoformat()),
    "not an object": ["approve", 0],
}


@pytest.mark.parametrize("name", sorted(_ANSWERS))
def test_1414_an_invalid_answer_is_refused_whole_and_the_comment_asked_again(fb, name):
    """An invalid answer records no decision, no draft, no lesson and no reply, even for its valid part; the next tick asks again. A3."""
    number, comment = _scene(fb, "case-bad", lookups=[LOOKUP, LOOKUP_2])
    bad = _ANSWERS[name]
    if isinstance(bad, dict):  # an instruction rides along: the valid part must not be kept either
        bad = {**bad, "instruction": "check the VPN log first"}
    decider = S.Decider({comment["id"]: [bad]})

    assert fb.tick(decider) == 0
    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]] * 2, "the refused comment was not asked again"
    assert _drafts(fb) == {}
    assert S.lessons_rows(fb.paths) == []
    assert fb.replies(number, comment["id"]) == []


@pytest.mark.parametrize(("given", "expect"), [
    (400, 180),    # later than +180: capped
    (30, 30),      # earlier: kept
    (0, 0),        # the comment's own day: not before it
])
def test_1414_the_review_date_is_the_earlier_of_the_named_and_added_plus_180(fb, given, expect):
    """A date after added_at + 180 is capped, one within is kept, one on the comment's day is accepted. A3/O6."""
    number, comment = _scene(fb, "case-date")
    named = (today() + dt.timedelta(days=given)).isoformat()
    decider = S.Decider({comment["id"]: S.answer(approve=(0,), review_by=named)})
    assert fb.tick(decider) == 0

    [(_, tip)] = _drafts(fb).items()
    from defender.tests.learning.feedback_1414.test_1414_feedback_draft import _entries_at

    [entry] = _entries_at(fb, tip)
    assert entry["review_by"] == (today() + dt.timedelta(days=expect)).isoformat()


def test_1414_one_comment_may_approve_and_instruct_and_gets_both(fb):
    """A comment answered with an approval and an instruction drafts the entry and writes the lessons row. A3/O6/O7."""
    number, comment = _scene(fb, "case-both")
    decider = S.Decider({comment["id"]: S.answer(approve=(0,), instruction="check the VPN log first")})
    assert fb.tick(decider) == 0

    assert len(_drafts(fb)) == 1
    [row] = S.lessons_rows(fb.paths)
    assert row["comment_id"] == str(comment["id"])


# ---------------------------------------------------------------- D11 hand-off: the lessons row

def test_1414_an_instruction_becomes_one_keyed_lessons_row_and_never_a_draft(fb):
    """Instruction text becomes one feedback-channel row keyed by the comment, no registry draft, and one reply saying so. O7/O5/D11."""
    instruction = "check the VPN log first for svc-backup"
    number, comment = _scene(fb, "case-lesson", body=instruction)
    decider = S.Decider({comment["id"]: S.answer(instruction=instruction)})

    assert fb.tick(decider) == 0
    assert fb.tick(decider) == 0
    assert S.lessons_rows(fb.paths) == [S.feedback_lesson_row(
        comment_id=comment["id"], issue=number, author=OWNER, case_id="case-lesson", instruction=instruction)]
    assert _drafts(fb) == {}
    [reply] = fb.replies(number, comment["id"])
    assert "lessons author" in reply["body"]


def test_1414_a_lessons_row_that_faulted_after_the_decision_is_written_once_later(fb):
    """The row write faults once after the decision is recorded: the next tick writes it identically, without asking again; a present row is not duplicated. D11."""
    instruction = "ask the owner of the host first"
    number, comment = _scene(fb, "case-row", body=instruction)
    decider = S.Decider({comment["id"]: S.answer(instruction=instruction)})
    queue_file = S.lessons_queue_file(fb.paths)
    queue_file.unlink(missing_ok=True)
    queue_file.mkdir(parents=True)  # the row cannot be appended: a real fault at the write

    with contextlib.suppress(Exception):
        fb.tick(decider)
    assert decider.decided == [comment["id"]], "premise: the decision was taken before the write faulted"
    queue_file.rmdir()
    assert S.lessons_rows(fb.paths) == []

    assert fb.tick(decider) == 0
    [row] = S.lessons_rows(fb.paths)
    assert row["comment_id"] == str(comment["id"])
    assert decider.decided == [comment["id"]], "the recorded decision was asked again"
    assert fb.tick(decider) == 0
    assert S.lessons_rows(fb.paths) == [row], "positive control: a present row was duplicated"


def test_1414_a_framing_run_with_no_lookups_records_a_no_change_and_still_sends_the_instruction(fb):
    """An approval over a run with no captured lookups is not refused: the host records its own no-change reason, and the instruction goes to lessons. A9."""
    instruction = "check the VPN log first"
    number, comment = _scene(fb, "case-nolookups", lookups=[], body=instruction)
    decider = S.Decider({comment["id"]: S.answer(approve=(0,), instruction=instruction)})

    for _ in range(2):
        assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]], "the answer was refused instead of recorded"
    [reply] = fb.replies(number, comment["id"])
    assert "no change" in reply["body"].lower()
    assert "the run made no registry lookup this could approve" in reply["body"]
    assert "could not be processed" not in reply["body"]
    assert _drafts(fb) == {}
    [row] = S.lessons_rows(fb.paths)
    assert (row["comment_id"], row["instruction"]) == (str(comment["id"]), instruction)


# ---------------------------------------------------------------- A4: retries and the ceiling

def test_1414_a_comment_refused_three_times_ends_as_a_replied_no_change_and_stops_there(fb, caplog):
    """The ceiling is three invalid answers: then the host records 'no change: could not be processed', replies, and never asks again. A4/O9."""
    number, comment = _scene(fb, "case-ceiling")
    decider = S.Decider({comment["id"]: [S.answer(approve=(9,))]})

    with caplog.at_level(logging.INFO):
        for tick in range(CEILING + 2):
            assert fb.tick(decider) == 0
            if tick < CEILING - 1:
                assert fb.replies(number, comment["id"]) == [], "the ceiling came early"
    assert decider.decided == [comment["id"]] * CEILING
    [reply] = fb.replies(number, comment["id"])
    assert "could not be processed" in reply["body"]
    assert _drafts(fb) == {}
    assert any(r.levelno >= logging.WARNING and str(comment["id"]) in r.getMessage()
               for r in caplog.records), "the exhausted comment is not logged with its reason"


def test_1414_a_failing_comment_stops_its_issues_later_comments_but_not_other_issues(fb):
    """While a comment is failing, the issue's later comments wait (order) and another issue's comment is decided; each comment has its own count. A4/O4."""
    number = _open(fb, "case-order")
    other_number = _open(fb, "case-other")
    first = fb.forge.add_comment(number, user=OWNER, body="first")
    second = fb.forge.add_comment(number, user=NAMED, body="second")
    other = fb.forge.add_comment(other_number, user=OWNER, body="elsewhere")
    decider = S.Decider({first["id"]: [S.answer(approve=(9,))], second["id"]: S.answer(reason="fine"),
                         other["id"]: S.answer(reason="fine")})

    assert fb.tick(decider) == 0
    assert decider.decided.count(second["id"]) == 0, "a later comment was decided past a failing one"
    assert other["id"] in decider.decided, "positive control: another issue's comment waited"

    for _ in range(CEILING):
        fb.tick(decider)
    assert decider.decided.count(first["id"]) == CEILING
    assert decider.decided.count(second["id"]) == 1, "the later comment inherited the failing one's count"
    assert len(fb.replies(number, second["id"])) == 1


def test_1414_an_unreachable_forge_is_never_counted_against_a_request(fb):
    """Transport faults and 5xx on the open, many ticks over, leave the request to succeed later; a refusal (422) three times quarantines it. A4/O9."""
    fb.request("case-down")
    fb.forge.fault = lambda r: (httpx.ConnectError("down", request=r)
                                if r.method == "POST" and r.url.path.endswith("/issues") else None)
    for _ in range(CEILING + 1):
        fb.tick(S.Decider())
    fb.forge.fault = None
    fb.forge.respond = lambda r: httpx.Response(503, json={}) if r.method == "POST" and r.url.path.endswith("/issues") else None
    for _ in range(CEILING + 1):
        fb.tick(S.Decider())
    assert fb.issues("case-down") == []
    fb.forge.respond = None
    assert fb.tick(S.Decider()) == 0
    assert len(fb.issues("case-down")) == 1, "unreachable ticks were counted and the request quarantined"
    assert S.quarantined_requests(fb.paths, "case-down") == []

    fb.request("case-refused")
    fb.forge.respond = lambda r: httpx.Response(422, json={"message": "refused"}) if r.method == "POST" and r.url.path.endswith("/issues") else None
    for _ in range(CEILING + 1):
        fb.tick(S.Decider())
    fb.forge.respond = None
    fb.tick(S.Decider())
    assert fb.issues("case-refused") == [], "a refused request was retried forever"
    assert S.open_issue_requests(fb.paths) == {}
    [kept] = S.quarantined_requests(fb.paths, "case-refused")
    assert kept.is_file(), "the quarantined request is not kept in a quarantine folder (A8)"


def test_1414_an_unreachable_forge_is_never_counted_against_a_comment_decision(fb):
    """A reply the forge refuses for many ticks does not spend the comment's attempts: the decision stands and its own reply is posted once the forge answers. A4."""
    number, comment = _scene(fb, "case-down-comment")
    decider = S.Decider({comment["id"]: S.answer(reason="a thanks, nothing to learn")})
    fb.forge.respond = lambda r: (httpx.Response(502, json={}) if r.method == "POST" and r.url.path.endswith(f"/issues/{number}/comments") else None)
    for _ in range(CEILING + 2):
        fb.tick(decider)
    assert fb.replies(number, comment["id"]) == [], "premise: the forge refused the reply"
    assert decider.decided == [comment["id"]], "the recorded decision was taken again"

    fb.forge.respond = None
    assert fb.tick(decider) == 0
    [reply] = fb.replies(number, comment["id"])
    assert "a thanks, nothing to learn" in reply["body"]
    assert "could not be processed" not in reply["body"], "refused replies were counted as failed attempts"
    assert decider.decided == [comment["id"]]
