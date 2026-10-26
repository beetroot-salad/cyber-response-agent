"""Forks rerun a tool-calling response without injecting an opening message."""
from __future__ import annotations

import logging

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    ToolReturnPart,
)

from defender._io import read_jsonl_rows  # noqa: E402
from defender.records import RunPaths  # noqa: E402
from defender.tests.support.runtime.state import _1255_snapshot as S
from defender.tests.support.storage._session_head_754 import message_ids  # noqa: E402
from defender.tests.support.storage._session_store_705 import store_mod  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    VerbRecorder,
    answer_hits,
    elastic_backend,
    hit,
)
from defender.tests.e2e._replay_harness import Turn, messages_text  # noqa: E402

pytestmark = pytest.mark.e2e

CHUNKS = S.chunks(3)

SOURCE_SCRIPT = (S.append(CHUNKS[0]), S.echo("one"), S.append(CHUNKS[1]), S.done())


def _returns(request: list) -> list[str]:
    """Project the last request message to tool-return texts, normalizing frame salts."""
    (*_head, parts), = S.project([request[-1]])
    return [part[3] for part in parts if part[0] == "return"]


def _arm_launched(arm: S.Driven) -> None:
    refused = S.refused_at_launch(arm)
    assert refused is None, (
        f"the arm was refused at launch ({refused}) — a MAIN response that called tools is "
        "exactly D1's branch point, and resuming it is U2's executed behaviour")


def test_d1_p4_an_arm_resumes_a_tool_calling_response_with_no_user_message(tmp_path):
    source = S.drive_source(tmp_path, SOURCE_SCRIPT)
    assert source.summary.get("truncated_by") is None, source.summary
    _r1, r2, _r3 = S.tool_calling_responses(source.store)
    assert len(source.main.requests) >= 3, "the source never made its third request"

    arm = S.drive_arm(tmp_path, S.spec_for(source, r2), S.Recorder([S.append(CHUNKS[1]), S.done()]))
    _arm_launched(arm)

    first = arm.main.requests[0]
    natural = source.main.requests[2]   # the request the source sent right after R2's calls ran
    tail = first[-1]
    assert isinstance(tail, ModelRequest), f"the arm's first request ends on {type(tail).__name__}"
    assert tail.parts, (f"the arm's first request ends on a message carrying {[type(p).__name__ for p in tail.parts]}"
        " — a natural run's request after a tool-calling turn carries only that turn's answers")
    assert all(isinstance(p, ToolReturnPart | RetryPromptPart) for p in tail.parts), (f"the arm's first request ends on a message carrying {[type(p).__name__ for p in tail.parts]}"
        " — a natural run's request after a tool-calling turn carries only that turn's answers")
    assert {p.tool_call_id for p in tail.parts} == {
        c.tool_call_id for c in S.calls_of(S.message_at(source.store, r2))}, (
        "the arm answered calls other than the ones R2 left dangling")
    assert "one" in messages_text([tail]), "R2's `echo one` did not run in the arm"

    assert S.user_prompts(natural), "the source's request carries no opening at all"
    assert S.user_prompts(first) == S.user_prompts(natural), (
        f"the arm's request carries {len(S.user_prompts(first))} user message(s), the natural "
        f"continuation {len(S.user_prompts(natural))} — the instrument added an opening")
    text, natural_text = messages_text(first), messages_text(natural)
    for marker in ("run_dir:", "alert:"):
        assert text.count(marker) == natural_text.count(marker), (
            f"`{marker}` appears {text.count(marker)} time(s) in the arm's request and "
            f"{natural_text.count(marker)} in the natural one — a second coordinates block")
    assert sum(line.startswith("now:") for line in text.splitlines()) == 0, (
        "the arm's request carries a `now:` line, which no natural run is ever sent")

    assert S.project(first) == S.project(natural), (
        "the arm's first request is not the source's own next request")


    ss = store_mod()
    source_path = [rid for rid, _m in S.main_rows(source.store)]
    prefix = source_path[: source_path.index(r2) + 1]

    children = S.child_sessions(source.store)
    assert len(children) == 1, f"the arm did not fork exactly one child session: {children}"
    child = children[0]
    assert ss.branch_point(source.store, child) == r2
    child_path = ss.path_row_ids(source.store, child)
    assert child_path[: len(prefix)] == prefix, "the child's path does not open on the prefix through R2"
    owned = message_ids(source.store, child)
    assert owned == child_path[len(prefix):], "the child owns rows that are not past the branch point"
    assert owned, "the arm appended nothing, so 'appended nothing twice' would be vacuous"
    rows = dict(S.main_rows(source.store, child))
    first_owned = rows[owned[0]]
    assert isinstance(first_owned, ModelRequest), (
        f"the first row the arm owns is a {type(first_owned).__name__}; the dangling response "
        "was appended again instead of being answered")
    dangling = {c.tool_call_id for c in S.calls_of(rows[r2])}
    repeats = [rid for rid in owned if isinstance(rows[rid], ModelResponse)
               and {c.tool_call_id for c in S.calls_of(rows[rid])} & dangling]
    assert repeats == [], f"R2's calls were stored again under the child: rows {repeats}"


def test_d1_the_branch_responses_own_writes_are_rerun_once_not_inherited(tmp_path):
    source = S.drive_source(tmp_path, SOURCE_SCRIPT)
    _r1, _r2, r3 = S.tool_calling_responses(source.store)
    final = source.document
    assert final.count(CHUNKS[1].strip()) == 1, "the source did not land its second fence once"

    arm = S.drive_arm(tmp_path, S.spec_for(source, r3), S.Recorder([S.done()]))
    _arm_launched(arm)

    assert arm.document == final, (
        "the arm's document after re-running R3's append is not the source's document after "
        "the same append")
    answer = _returns(arm.main.requests[0])
    natural = _returns(source.main.requests[3])
    assert natural, "the source's request after R3 carries no tool answer"
    assert answer == natural, (
        "the arm's answer to R3's append is not the one the source received")


SOURCE_WORLD = [hit(ts="2026-05-25T15:20:00.000Z", message="SOURCE-WORLD login")]
ARM_WORLD = [hit(ts="2026-05-25T15:20:00.000Z", message="ARM-WORLD login")]
LEAD = "l-001"
QUERY = Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                    "params": {"native_query": "user.name:dev.dana"}})])


def test_d1_a_gather_dispatched_at_the_branch_turn_reruns_fresh_against_the_arms_world(tmp_path):
    source_rec = VerbRecorder()
    source = S.drive_source(
        tmp_path, (S.append(CHUNKS[0]), S.dispatch(LEAD), S.done()),
        leads={LEAD: (QUERY, Turn(text="SOURCE-SUMMARY for l-001"))},
        verbs=elastic_backend(source_rec, answer_hits(SOURCE_WORLD)))
    _r1, r2 = S.tool_calling_responses(source.store)
    source_rows = [r for r in read_jsonl_rows(RunPaths(source.run_dir).executed_queries)
                   if r.get("lead_id") == LEAD]
    assert source_rows, "the source's l-001 captured nothing — nothing below discriminates"
    assert "SOURCE-WORLD" in S.read_text(RunPaths(source.run_dir).payload(LEAD, 0)), (
        "the source's l-001 payload does not hold the source's answer")

    arm_rec = VerbRecorder()
    arm = S.drive_arm(
        tmp_path, S.spec_for(source, r2), S.Recorder([S.done()]),
        leads={LEAD: (QUERY, Turn(text="ARM-SUMMARY for l-001"))},
        verbs=elastic_backend(arm_rec, answer_hits(ARM_WORLD)))
    _arm_launched(arm)

    assert arm_rec.calls, "the re-run lead never reached the arm's backend"
    arm_lead = arm.gather.leads[LEAD]
    assert arm_lead.requests, "the arm never ran l-001's gather sub-agent"
    assert len(arm_lead.requests[0]) == 1, (
        f"the arm's l-001 started on {len(arm_lead.requests[0])} messages, not a fresh dispatch")
    assert S.project(arm_lead.requests[0]) == S.project(
        source.gather.leads[LEAD].requests[0]), (
        "the arm's l-001 dispatch is not the one the source's lead started from")
    returned = messages_text([arm.main.requests[0][-1]])
    assert "ARM-SUMMARY" in returned, "the arm's main request does not carry the arm's own l-001 summary"
    assert "SOURCE-SUMMARY" not in returned, "the arm's main request does not carry the arm's own l-001 summary"
    arm_rows = [r for r in read_jsonl_rows(RunPaths(arm.run_dir).executed_queries)
                if r.get("lead_id") == LEAD]
    assert len(arm_rows) == 1, (
        f"the arm holds {len(arm_rows)} l-001 row(s); exactly its own one query belongs there")
    assert "ARM-WORLD" in S.read_text(RunPaths(arm.run_dir).payload(LEAD, 0)), (
        "the arm's l-001 payload is not what the arm's world answered")
    summary = S.read_text(RunPaths(arm.run_dir).gather_summary(LEAD))
    assert "ARM-SUMMARY" in summary
    assert "SOURCE-SUMMARY" not in summary


def _row_after(source: S.Driven, row_id: int) -> int:
    path = [rid for rid, _m in S.main_rows(source.store)]
    return path[path.index(row_id) + 1]


@pytest.mark.parametrize("point", ["tool-calling response", "its tool return", "text-only response"])
def test_d1_only_a_tool_calling_main_response_is_a_branch_point(tmp_path, point):
    source = S.drive_source(tmp_path, SOURCE_SCRIPT)
    _r1, r2, _r3 = S.tool_calling_responses(source.store)
    row = {"tool-calling response": r2,
           "its tool return": _row_after(source, r2),
           "text-only response": S.responses(source.store)[-1]}[point]
    message = S.message_at(source.store, row)
    if point == "text-only response":
        assert isinstance(message, ModelResponse), message
        assert not S.calls_of(message), message
    if point == "its tool return":
        assert isinstance(message, ModelRequest), message

    arm = S.drive_arm(tmp_path, S.spec_for(source, row), S.Recorder([S.done()]))

    if point == "tool-calling response":
        _arm_launched(arm)
        assert len(S.child_sessions(source.store)) == 1
        return
    assert not S.launched(arm), f"the arm launched at a {point}, which is not a D1 branch point"
    assert arm.summary.get("exit_reason") == "BranchError", arm.summary
    assert S.child_sessions(source.store) == [], "a refused branch still forked a child session"


REFUSED_BASH = Turn(tool_calls=[("bash", {"command": "curl http://example.invalid/x"})])

REFUSED_READ = Turn(tool_calls=[("read_file", {"path": "no-such-notes-1255.md"})])

REFUSED_APPEND = S.append("```yaml\nverdict: benign\n```\n")


STREAKS = {
    "previous bash call refused": (
        (S.append(CHUNKS[0]), REFUSED_BASH, S.echo("two"), S.echo("three"), S.done()), 2, True,
        "bash"),
    "bash refused two steps back": (
        (S.append(CHUNKS[0]), REFUSED_BASH, S.append(CHUNKS[1]), S.echo("x"), S.done()), 3, True,
        "bash"),
    "another tool carries a retry": (
        (S.append(CHUNKS[0]), REFUSED_BASH, S.append(CHUNKS[1]), S.append(CHUNKS[2]), S.done()),
        3, True, "bash"),
    "previous bash call ran": (
        (S.append(CHUNKS[0]), REFUSED_BASH, S.echo("two"), S.echo("three"), S.done()), 3, False,
        "bash"),
    "read_file refused, bash at the branch point": (
        (S.append(CHUNKS[0]), REFUSED_READ, S.echo("x"), S.done()), 2, True, "read_file"),
    "append_block refused, bash ran twice since": (
        (S.append(CHUNKS[0]), REFUSED_APPEND, S.echo("x"), S.echo("y"), S.done()), 3, True,
        "append_block"),
    "append_block refused, then an append landed": (
        (S.append(CHUNKS[0]), REFUSED_APPEND, S.append(CHUNKS[1]), S.echo("x"), S.done()), 3,
        False, "append_block"),
}


@pytest.mark.parametrize("point", list(STREAKS))
def test_d2_a_branch_point_inside_a_retry_streak_is_refused_at_launch(tmp_path, caplog, point):
    script, index, refused, carrier = STREAKS[point]
    source = S.drive_source(tmp_path, script)
    responses = S.tool_calling_responses(source.store)
    rows = dict(S.main_rows(source.store))
    (refused_call,) = S.calls_of(S.message_at(source.store, responses[1]))
    assert refused_call.tool_name == carrier, f"the fixture's refused call moved: {refused_call}"
    answered = rows[_row_after(source, responses[1])]
    assert any(isinstance(p, RetryPromptPart) and p.tool_name == carrier
               for p in answered.parts), (
        f"the fixture's `{carrier}` call was not refused for retry — the streak arm would be "
        f"vacuous: {[(type(p).__name__, getattr(p, 'tool_name', None)) for p in answered.parts]}")
    for between in responses[2:index]:
        reply = rows[_row_after(source, between)]
        assert not any(isinstance(p, RetryPromptPart) for p in reply.parts), (
            "a call between the refusal and the branch point was refused too — the scenario "
            "is no longer the one it names")

    caplog.set_level(logging.INFO)
    arm = S.drive_arm(tmp_path, S.spec_for(source, responses[index]), S.Recorder([S.done()]))

    if not refused:
        _arm_launched(arm)
        return
    assert not S.launched(arm), "an arm was launched inside a retry streak it cannot reproduce"
    assert arm.summary.get("exit_reason") == "BranchError", arm.summary
    assert S.child_sessions(source.store) == []
    assert "retry" in caplog.text.lower(), (
        f"the refusal does not name the retry streak: {caplog.text[-400:]!r}")
