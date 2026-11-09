"""#1414 F2 step 3 and D11's hand-off: the decide answer's schema (A3), retries and the ceiling (A4/O9), and the
lessons row an instruction becomes (O7).
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import logging
from pathlib import Path

import httpx
import pytest

from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.learning.feedback_1414._spec1414 import LOOKUP, LOOKUP_2, NAMED, OWNER, today
from defender.tests.support.shared._locations_1210 import location_path
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

_GOOD = {"approve": [0], "review_by": None, "instruction": "check the VPN log first", "reason": None}
_UNMADE = {"actor": "svc-backup", "host": "db-07.prod", "pattern": "drop table users"}  # a lookup the run never made


def _wrong(**fields):
    """A valid answer (an approval and an instruction) with `fields` replaced: only the replaced part is wrong."""
    return {**_GOOD, **fields}


_ANSWERS = {
    "index past the lookups": S.answer(approve=(0, 2)),
    "negative index": S.answer(approve=(-1,)),
    "approve not a list": _wrong(approve="0"),
    "approve a bare int": _wrong(approve=1),
    "approve a dict": _wrong(approve={"0": True}),
    "bool True as an index": _wrong(approve=[True]),
    "bool False as an index": _wrong(approve=[False]),
    "valid index then a bool": _wrong(approve=[0, True]),
    "float index": _wrong(approve=[0.0]),
    "fractional float index": _wrong(approve=[1.5]),
    "string index": _wrong(approve=["0"]),
    "nested list index": _wrong(approve=[[0]]),
    "none as an index": _wrong(approve=[None]),
    "unmade lookup by value": _wrong(approve=[_UNMADE]),
    "valid index then an unmade lookup": _wrong(approve=[0, _UNMADE]),
    "made lookup by value": _wrong(approve=[dict(LOOKUP)]),
    "lookup with extra key": _wrong(approve=[{**_UNMADE, "index": 0}]),
    "unparsable date": _wrong(review_by="after the next audit"),
    "date before the comment": _wrong(review_by=(today() - dt.timedelta(days=1)).isoformat()),
    "date as a compact int": _wrong(review_by=int((today() + dt.timedelta(days=9)).strftime("%Y%m%d"))),
    "date as a date object": _wrong(review_by=today() + dt.timedelta(days=9)),
    "date as a list": _wrong(review_by=[(today() + dt.timedelta(days=9)).isoformat()]),
    "date as a dict": _wrong(review_by={"date": (today() + dt.timedelta(days=9)).isoformat()}),
    "date as a bool": _wrong(review_by=True),
    "instruction an int": _wrong(instruction=5),
    "instruction a list": _wrong(instruction=["check the VPN log first"]),
    "instruction a dict": _wrong(instruction={"text": "check the VPN log first"}),
    "instruction True": _wrong(instruction=True),
    "instruction False": _wrong(instruction=False),
    "reason an int": _wrong(reason=7),
    "reason a list": _wrong(reason=["no"]),
    "reason a dict": _wrong(reason={"why": "no"}),
    "reason a bool": _wrong(reason=True),
    "not an object": ["approve", 0],
    "text": "approve 0",
    "null": None,
}


@pytest.mark.parametrize("name", sorted(_ANSWERS))
def test_1414_an_invalid_answer_is_refused_whole_and_counted_to_the_ceiling(fb, name):
    """Any answer off A3's exact shape is refused whole: its valid part (an approval, an instruction) is kept nowhere, the comment is asked again, and the 3rd refusal ends it as a replied 'could not be processed'. A3/A4."""
    number, comment = _scene(fb, "case-bad", lookups=[LOOKUP, LOOKUP_2])
    decider = S.Decider({comment["id"]: [_ANSWERS[name]]})

    for tick in range(CEILING):
        assert fb.tick(decider) == 0
        assert decider.decided == [comment["id"]] * (tick + 1), "the refused comment was not asked again"
        if tick < CEILING - 1:
            assert fb.replies(number, comment["id"]) == [], "the ceiling came early"
        assert _drafts(fb) == {}, "an entry was drafted from a refused answer"
        assert S.lessons_rows(fb.paths) == [], "a lessons row was written from a refused answer"
    [reply] = fb.replies(number, comment["id"])
    assert "could not be processed" in reply["body"]
    assert fb.tick(decider) == 0
    assert decider.decided == [comment["id"]] * CEILING, "an exhausted comment was asked again"
    assert _drafts(fb) == {}
    assert S.lessons_rows(fb.paths) == []


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


_REFUSED = range(400, 500)
_UNREACHABLE = range(500, 600)


def _request_case(request) -> str | None:
    """The case an issue-open POST is for (read from the title the host wrote), else None."""
    if request.method == "POST" and request.url.path.endswith("/issues"):
        return json.loads(request.content)["title"].split()[3]
    return None


def _live_cases(fb) -> set[str]:
    return {r["case_id"] for r in S.open_issue_requests(fb.paths).values()}


def _set_aside_cases(fb) -> set[str]:
    root = Path(location_path(fb.paths.state_root))
    live = root / S.REQUEST_QUEUE
    kept = set()
    for p in root.rglob("*.json"):
        name = str(p.relative_to(root)).lower()
        if p.parent != live and ("fail" in name or "quarantin" in name):
            with contextlib.suppress(ValueError, AttributeError):
                kept.add(json.loads(p.read_text(encoding="utf-8"))["case_id"])
    return kept


def test_1414_every_4xx_on_a_request_is_counted_to_the_3rd_tick_and_no_5xx_or_fault_ever_is(fb):
    """For each status 400-599 and a transport fault on the issue open: a 4xx sets the request aside at exactly the 3rd tick, a 5xx or fault never, and once the forge answers the kept ones open their issue. A4/O9."""
    cases = {f"s{status}": status for status in (*_REFUSED, *_UNREACHABLE)}
    for case in (*cases, "fault", "healthy"):
        fb.request(case)
    fb.forge.respond = lambda r: (httpx.Response(cases[c], json={"message": "no"})
                                  if (c := _request_case(r)) in cases else None)
    fb.forge.fault = lambda r: httpx.ConnectError("down", request=r) if _request_case(r) == "fault" else None
    refused = {c for c, status in cases.items() if status < 500}
    kept = set(cases) - refused | {"fault"}

    assert fb.tick(S.Decider()) == 0
    assert len(fb.issues("healthy")) == 1, "a failing request held back the one after it"
    for _ in range(CEILING - 2):
        fb.tick(S.Decider())
    assert _live_cases(fb) == set(cases) | {"fault"}, "a request was set aside before the ceiling"
    assert _set_aside_cases(fb) == set()
    fb.tick(S.Decider())
    assert _set_aside_cases(fb) == refused, "the 4xx requests were not set aside at exactly the 3rd refusal"
    assert _live_cases(fb) == kept
    for _ in range(CEILING + 3):
        fb.tick(S.Decider())
    assert _live_cases(fb) == kept, "an unreachable forge was counted against a request"
    assert _set_aside_cases(fb) == refused

    fb.forge.respond = fb.forge.fault = None
    assert fb.tick(S.Decider()) == 0
    assert _live_cases(fb) == set()
    assert {c for c in (*cases, "fault") if fb.issues(c)} == kept, "a kept request lost its issue, or a refused one got one"
    assert len(fb.issues("healthy")) == 1


def _sweep(fb, *, step):
    """One issue with a comment per status of a spread of 5xx classes (the request test sweeps them all) and a transport fault."""
    cases = {f"c{status}": status for status in (500, 501, 502, 503, 504, 507, 511, 599)} | {"cfault": None}
    for case in cases:
        fb.request(case)
    assert fb.tick(S.Decider()) == 0
    numbers = {case: fb.issues(case)[0]["number"] for case in cases}
    comments = {case: fb.forge.add_comment(number, user=OWNER, body="a note") for case, number in numbers.items()}
    status_of = {number: cases[case] for case, number in numbers.items()}

    def trouble(r):
        parts = r.url.path.split("/")
        if "issues" in parts and r.method == step[0] and r.url.path.endswith(step[1]):
            number = int(parts[parts.index("issues") + 1])
            if number in status_of:
                return status_of[number]
        return False

    fb.forge.respond = lambda r: (httpx.Response(t, json={}) if (t := trouble(r)) else None)
    fb.forge.fault = lambda r: httpx.ConnectError("down", request=r) if trouble(r) is None else None
    return numbers, comments


@pytest.mark.parametrize("step", [("POST", "/comments"), ("GET", "/comments")], ids=["reply", "listing"])
def test_1414_no_5xx_or_fault_on_a_comment_step_is_counted_and_nothing_past_it_is_lost(fb, step):
    """For a spread of 5xx statuses and a transport fault on a comment's reply POST or its issue's comment listing: after many ticks the comment is still live and never ended 'could not be processed', and once the forge answers it and a comment added meanwhile are each decided and replied to once. A4/O9."""
    numbers, comments = _sweep(fb, step=step)
    decider = S.Decider({c["id"]: S.answer(reason="a thanks") for c in comments.values()})
    for _ in range(CEILING + 3):
        fb.tick(decider)
    later = {case: fb.forge.add_comment(numbers[case], user=NAMED, body="and then") for case in numbers}
    decider.script |= {c["id"]: S.answer(reason="a thanks") for c in later.values()}
    for _ in range(CEILING + 2):
        fb.tick(decider)
    assert not any("could not be processed" in c["body"] for n in numbers.values() for c in fb.forge.comments_on(n, by=fb.bot))

    fb.forge.respond = fb.forge.fault = None
    for _ in range(2):
        assert fb.tick(decider) == 0
    for case, number in numbers.items():
        for c in (comments[case], later[case]):
            assert len(fb.replies(number, c["id"])) == 1, f"{case}: a comment was lost or answered twice"
            assert decider.decided.count(c["id"]) == 1, f"{case}: a failed forge call spent a decision"


def test_1414_a_request_the_forge_refuses_is_set_aside_with_its_reason_in_a_kept_file(fb):
    """A request refused three times (422) is kept in a quarantine folder with a non-empty reason and never retried. A4/A8."""
    fb.request("case-refused")
    fb.forge.respond = lambda r: httpx.Response(422, json={"message": "refused"}) if _request_case(r) else None
    for _ in range(CEILING + 1):
        fb.tick(S.Decider())
    fb.forge.respond = None
    fb.tick(S.Decider())
    assert fb.issues("case-refused") == [], "a refused request was retried forever"
    assert S.open_issue_requests(fb.paths) == {}
    [kept] = S.quarantined_requests(fb.paths, "case-refused")
    assert kept.is_file(), "the quarantined request is not kept in a quarantine folder (A8)"
    reason = json.loads(kept.read_text(encoding="utf-8")).get("failed")  # as the lead-author lane's `failed/` records
    assert isinstance(reason, str), "the quarantined request carries no reason it failed (A8)"
    assert reason.strip(), "the quarantined request's reason is empty (A8)"
