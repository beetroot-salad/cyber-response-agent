"""#1255 slice A — the branch point (D1) and the instrument that adds nothing (P4).

Design rev 4, "No injected opening (P4)": the branch point is a MAIN model response that called
tools whose answers are not yet in the history. The arm resumes with NO user message; the
framework runs those dangling calls against the arm's world and continues, so the model's next
request is exactly the one a natural run would have sent (U2, executed). Gather calls at the
branch turn are re-run, never inherited — a gather sub-agent always starts fresh, so the re-run
lead queries the arm's world. Today's code refuses exactly this branch point in three places
(branch validation, conversation loading, the store fork's bookkeeping); all three flip.

Every source here is a REAL run driven through the replay harness (`_1255_snapshot.drive_source`)
and every arm is `run_investigation(resume=…)` — the call `run.py --episode … --world …`
composes (that composition is driven in `tests/test_1255_snapshot_instrument.py`, P3: what an
arm's run folder holds). Nothing reads, plants or names the fork snapshot: it exists only as
what the arm restores.

OBSERVATION CHANNEL: the raw message lists the scripted model receives (`Recorder.requests`)
and the source's session store. The natural continuation is not imagined: it is the SOURCE's own
request at the same point, because the arm is scripted to make exactly the calls the source made
after the branch.

RED TODAY (expected): `branch.validate` refuses a response whose call is unanswered, so every arm
taken at a D1 branch point is refused at launch, and the assertions past "the arm launched" are
masked until that flips.

WHAT THESE ARE EVIDENCE FOR (contract review R1-7, recheck RC-8c): D1, P4 and the retry rule —
each test here passes once those land, fork snapshot or not, so it is not evidence for the
snapshot (P2), with ONE exception: `test_d1_the_branch_responses_own_writes_are_rerun_once_not_
inherited` is P2 evidence (the document restored by content as of the branch point) — a
D1-only lift over today's document seed failed it. The rest of P2 is
`test_1255_snapshot_restore.py`'s.
"""
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
from defender.run_repository import RunPaths  # noqa: E402
from defender.tests import _1255_snapshot as S  # noqa: E402
from defender.tests._session_head_754 import message_ids  # noqa: E402
from defender.tests._session_store_705 import store_mod  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    VerbRecorder,
    answer_hits,
    elastic_backend,
    hit,
)
from defender.tests.e2e._replay_harness import Turn, messages_text  # noqa: E402

pytestmark = pytest.mark.e2e

CHUNKS = S.chunks(3)

#: The source every D1 scenario forks: the correlation lead (one capture), then MAIN writes a
#: fence, runs a pathless command, writes a second fence and stops. Tool-calling responses:
#: R1 (append), R2 (echo), R3 (append); R4 is text-only.
SOURCE_SCRIPT = (S.append(CHUNKS[0]), S.echo("one"), S.append(CHUNKS[1]), S.done())


def _replace(*runs: S.Driven) -> dict[str, str]:
    """Host spellings of the run folders, mapped to one placeholder.

    The ONE normalisation the request comparison makes beyond O4's frame salts: today the
    source's and the arm's folders are different host paths, and a tool result that names its
    own folder differs on that alone. That is slice B's channel (the model view renders both as
    `/runs/current`), not this slice's — so it is masked here, and named."""
    return {str(r.run_dir): "<RUN_DIR>" for r in runs}


def _arm_launched(arm: S.Driven) -> None:
    refused = S.refused_at_launch(arm)
    assert refused is None, (
        f"the arm was refused at launch ({refused}) — a MAIN response that called tools is "
        "exactly D1's branch point, and resuming it is U2's executed behaviour")


# --------------------------------------------------------------------------------------
# D1 + P4: the arm's first request is the natural one.
# --------------------------------------------------------------------------------------


def test_d1_p4_an_arm_resumes_a_tool_calling_response_with_no_user_message(tmp_path):
    """D1, P4, O1 (U2): branched at R2 — a response whose `bash` call has no answer in the
    history — the arm's FIRST model request is exactly the source's own next request: the
    inherited history through R2, then one `ModelRequest` carrying only the answers to R2's
    calls. No user message is added: no operator continuation text, no second `run_dir:` /
    `alert:` block, no `now:` line.

    The comparison is the whole request (every message, every part, tool results included),
    minus part timestamps (never sent) and frame salts (O4). A violation it rejects: today's
    opening — a new `UserPromptPart` carrying the continuation prompt, the coordinates and a
    `now:` line — or a re-sent call, or a dropped branch response.

    Regression over the new branch point (D1): it passes once D1 lands, fork snapshot or not,
    so it is not evidence for the snapshot (P2)."""
    source = S.drive_source(tmp_path, SOURCE_SCRIPT)
    assert source.summary.get("truncated_by") is None, source.summary
    r1, r2, r3 = S.tool_calling_responses(source.store)
    assert len(source.main.requests) >= 3, "the source never made its third request"

    arm = S.drive_arm(tmp_path, S.spec_for(source, r2), S.Recorder([S.append(CHUNKS[1]), S.done()]))
    _arm_launched(arm)

    first = arm.main.requests[0]
    natural = source.main.requests[2]   # the request the source sent right after R2's calls ran
    tail = first[-1]
    assert isinstance(tail, ModelRequest), f"the arm's first request ends on {type(tail).__name__}"
    assert tail.parts and all(isinstance(p, ToolReturnPart | RetryPromptPart) for p in tail.parts), (
        f"the arm's first request ends on a message carrying {[type(p).__name__ for p in tail.parts]}"
        " — a natural run's request after a tool-calling turn carries only that turn's answers")
    assert {p.tool_call_id for p in tail.parts} == {
        c.tool_call_id for c in S.calls_of(S.message_at(source.store, r2))}, (
        "the arm answered calls other than the ones R2 left dangling")
    assert "one" in messages_text([tail]), "R2's `echo one` did not run in the arm"

    # P4, on the same channel: the source's opening is in both (the positive control), and the
    # arm adds no second one.
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

    assert S.project(first, replace=_replace(source, arm)) == S.project(
        natural, replace=_replace(source, arm)), (
        "the arm's first request is not the source's own next request")


def test_d1_the_branch_responses_own_writes_are_rerun_once_not_inherited(tmp_path):
    """D1 + the clean cut (slice A.2): branched at R3 — the response whose `append_block` wrote
    the second fence — the arm's document holds that fence exactly ONCE, written by the arm's
    re-run of R3's call, and the arm's answer to it is the source's own answer ("appended N
    bytes (M total)"). A snapshot taken after R3's call ran, or a document cut from the finished
    run, would hand the arm a document already holding the fence: the re-run then lands it twice
    (or is refused), and the total in the answer moves.

    EVIDENCE FOR P2 (the document restored by content as of the branch point), not a D1-only
    regression: the recheck review's partial lazy D1 lift, which kept today's document seed,
    failed it (RC-8c) — that seed is not the document as it stood when R3 arrived."""
    source = S.drive_source(tmp_path, SOURCE_SCRIPT)
    _r1, _r2, r3 = S.tool_calling_responses(source.store)
    final = source.document
    assert final.count(CHUNKS[1].strip()) == 1, "the source did not land its second fence once"

    arm = S.drive_arm(tmp_path, S.spec_for(source, r3), S.Recorder([S.done()]))
    _arm_launched(arm)

    assert arm.document == final, (
        "the arm's document after re-running R3's append is not the source's document after "
        "the same append")
    answer = [p for p in arm.main.requests[0][-1].parts if isinstance(p, ToolReturnPart)]
    natural = [p for p in source.main.requests[3][-1].parts if isinstance(p, ToolReturnPart)]
    assert [p.content for p in answer] == [p.content for p in natural], (
        "the arm's answer to R3's append is not the one the source received")


def test_d1_the_store_holds_the_branch_response_once(tmp_path):
    """D1, third flipped site (the store fork's bookkeeping): the arm's session forks AT the
    dangling response, inherits it as the last row of its prefix, and the first row the arm
    owns is the request answering it — the response is never appended a second time under the
    child, and no inherited row is copied into the child.

    Regression over the new branch point (D1): it passes once D1 lands, fork snapshot or not,
    so it is not evidence for the snapshot (P2)."""
    ss = store_mod()
    source = S.drive_source(tmp_path, SOURCE_SCRIPT)
    _r1, r2, _r3 = S.tool_calling_responses(source.store)
    source_path = [rid for rid, _m in S.main_rows(source.store)]
    prefix = source_path[: source_path.index(r2) + 1]

    arm = S.drive_arm(tmp_path, S.spec_for(source, r2), S.Recorder([S.append(CHUNKS[1]), S.done()]))
    _arm_launched(arm)

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


# --------------------------------------------------------------------------------------
# Gather at the branch turn: re-run, fresh, against the arm's world.
# --------------------------------------------------------------------------------------

SOURCE_WORLD = [hit(ts="2026-05-25T15:20:00.000Z", message="SOURCE-WORLD login")]
ARM_WORLD = [hit(ts="2026-05-25T15:20:00.000Z", message="ARM-WORLD login")]
LEAD = "l-001"
QUERY = Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                    "params": {"native_query": "user.name:dev.dana"}})])


def test_d1_a_gather_dispatched_at_the_branch_turn_reruns_fresh_against_the_arms_world(tmp_path):
    """D1: branched at the response that dispatched `l-001`, the arm RE-RUNS the dispatch: its
    gather sub-agent starts fresh (its first request is the dispatch alone, the same request
    the source's lead started from), its query reaches the ARM's backend, and the arm's main
    request carries the arm's summary. Nothing of the source's `l-001` is inherited: no rows,
    no payload, no summary — they were written by the branch response's own call, after the
    cut.

    Positive controls on each channel: the source's lead reached the source's backend and its
    rows/summary exist, so "the arm holds none of them" is measured against a source that does.

    Regression over the new branch point (D1): it passes once D1 lands, fork snapshot or not,
    so it is not evidence for the snapshot (P2)."""
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
    rep = _replace(source, arm)
    assert S.project(arm_lead.requests[0], replace=rep) == S.project(
        source.gather.leads[LEAD].requests[0], replace=rep), (
        "the arm's l-001 dispatch is not the one the source's lead started from")
    returned = messages_text([arm.main.requests[0][-1]])
    assert "ARM-SUMMARY" in returned and "SOURCE-SUMMARY" not in returned, (
        "the arm's main request does not carry the arm's own l-001 summary")
    arm_rows = [r for r in read_jsonl_rows(RunPaths(arm.run_dir).executed_queries)
                if r.get("lead_id") == LEAD]
    assert len(arm_rows) == 1, (
        f"the arm holds {len(arm_rows)} l-001 row(s); exactly its own one query belongs there")
    assert "ARM-WORLD" in S.read_text(RunPaths(arm.run_dir).payload(LEAD, 0)), (
        "the arm's l-001 payload is not what the arm's world answered")
    summary = S.read_text(RunPaths(arm.run_dir).gather_summary(LEAD))
    assert "ARM-SUMMARY" in summary and "SOURCE-SUMMARY" not in summary


# --------------------------------------------------------------------------------------
# What is NOT a branch point.
# --------------------------------------------------------------------------------------


def _row_after(source: S.Driven, row_id: int) -> int:
    path = [rid for rid, _m in S.main_rows(source.store)]
    return path[path.index(row_id) + 1]


@pytest.mark.parametrize("point", ["tool-calling response", "its tool return", "text-only response"])
def test_d1_only_a_tool_calling_main_response_is_a_branch_point(tmp_path, point):
    """D1: of three neighbouring rows of one source, only the response that called tools is
    admitted; the request that answers it and the closing text-only response are refused at
    launch — the model is never asked for a turn and nothing is forked. Today's rule is the
    mirror image (a complete pair is admitted, the dangling response refused), so each arm
    rejects one direction of it.

    Regression over the new branch point (D1): it passes once D1 lands, fork snapshot or not,
    so it is not evidence for the snapshot (P2)."""
    source = S.drive_source(tmp_path, SOURCE_SCRIPT)
    _r1, r2, _r3 = S.tool_calling_responses(source.store)
    row = {"tool-calling response": r2,
           "its tool return": _row_after(source, r2),
           "text-only response": S.responses(source.store)[-1]}[point]
    message = S.message_at(source.store, row)
    if point == "text-only response":
        assert isinstance(message, ModelResponse) and not S.calls_of(message), message
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


#: A command MAIN's gate refuses (only the defender-* shims and the inert programs run); the
#: refusal reaches the model as a retry prompt for `bash`.
REFUSED_BASH = Turn(tool_calls=[("bash", {"command": "curl http://example.invalid/x"})])


#: Each retry-streak scenario: the source's MAIN script, which of its tool-calling responses is
#: the branch point, and whether rev 4 + rev 5 C1 refuse it. One refused `curl` (a RETRY of
#: `bash`) is in every script; what differs is what ran between it and the branch point.
STREAKS = {
    # The response right after the refusal, on the same tool.
    "previous bash call refused": (
        (S.append(CHUNKS[0]), REFUSED_BASH, S.echo("two"), S.echo("three"), S.done()), 2, True),
    # C1, non-adjacent: `bash` still carries its retry count two steps later, because the call
    # between was another tool's (`append_block`), and a count clears only when ITS tool succeeds.
    "bash refused two steps back": (
        (S.append(CHUNKS[0]), REFUSED_BASH, S.append(CHUNKS[1]), S.echo("x"), S.done()), 3, True),
    # C1, other tool: ANY tool's carried count refuses — the branch response calls
    # `append_block`, whose own count is clear, while `bash`'s is not.
    "another tool carries a retry": (
        (S.append(CHUNKS[0]), REFUSED_BASH, S.append(CHUNKS[1]), S.append(CHUNKS[2]), S.done()),
        3, True),
    # The clean-history control: `bash` ran (`echo two`) after its refusal, so nothing is carried
    # at `echo three`.
    "previous bash call ran": (
        (S.append(CHUNKS[0]), REFUSED_BASH, S.echo("two"), S.echo("three"), S.done()), 3, False),
}


@pytest.mark.parametrize("point", list(STREAKS))
def test_d2_a_branch_point_inside_a_retry_streak_is_refused_at_launch(tmp_path, caplog, point):
    """Design "Fork snapshot" + rev 5 C1: the framework's per-tool retry counts cannot be
    seeded, and the framework keeps a tool's count across later steps until THAT tool succeeds,
    so a branch point is refused at launch whenever ANY tool carries a retry count at the
    branch step — not only when the immediately previous call was refused. Four branch points,
    each after the same refused `bash` call (`curl`): right after it (refused); two steps later
    with an `append_block` between (refused: `bash` still carries it); at an `append_block`
    response after a successful append (refused: another tool carries it); and after `bash`
    itself ran again (admitted — the control on the same tool and source shape). The refusal
    names the retry streak (a refusal names its reason; today's refusal at these points is for
    D1's reason, which is not this one).

    Regression over the new branch point (D1) and the retry rule; not evidence for the fork
    snapshot (P2) — it passes once D1 and C1 land, snapshot or not."""
    script, index, refused = STREAKS[point]
    source = S.drive_source(tmp_path, script)
    responses = S.tool_calling_responses(source.store)
    rows = dict(S.main_rows(source.store))
    answered = rows[_row_after(source, responses[1])]
    assert any(isinstance(p, RetryPromptPart) for p in answered.parts), (
        "the fixture's `curl` was not refused for retry — the streak arm would be vacuous")
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
