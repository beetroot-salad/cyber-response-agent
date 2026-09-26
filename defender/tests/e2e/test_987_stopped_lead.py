"""#987 — a STOPPED lead writes its own summary, through the REAL gather agent.

THE DEFECT. When the harness stopped a gather lead — a guard's dead end, or the request ceiling
— it did so by raising out of the run, authored a stand-in notice, and main never saw the
answers the sub-agent had already retrieved: they lived in the gather run's own context, which
unwound with the run. Main may not read `gather_raw/` (policy, not accident) and the queries
table carries digests, not answers, so a lead that answered six queries and then repeated one
read to main as empty.

THE CHANGE. The lead is not cut. Two stops, two seams, because they are facts about two
different things — and ONE RECORD (`LeadStop`, on the deps), written by whichever stop
happens at the moment it happens. A GUARD's stop is a fact about one tool call: the query
tool CLOSES THE LEAD'S DOOR and says so in that call's own result — the guard's reason, then
the instruction to write the summary now — and refuses every later `query` the same way. The
CEILING is a fact about the round: `RequestCeiling`, on every gather agent, adds one sentence
to the last request the ceiling allows — whatever tools that round used, or none — saying the
summary is what this request is for, sends that request with `tool_choice: none` (the tools
stay DEFINED on the wire; the model may not call one), and drops any tool call a provider let
through from the response. So on the final request a tool call is not a thing that happens:
nothing is refused, nothing is rowed, and text written beside a stray call is the summary.
Either way the model's next turn is its summary, the run ends the way a finished lead's does,
and `_run_gather` reads the record afterwards — never a request count — to put the notice
ABOVE the summary and stamp the terminator. Nothing is replayed, no second run is made, and
the ceiling is one number, the run's own `UsageLimits`, read by every hook off the context.

There is no grace turn to forfeit. A model that queries again after a dead end is refused
and keeps its turns; the ceiling bounds it and still marks its final request. A model that
writes NO TEXT on its marked final request has written nothing: the run ends in the
framework's empty-response fault, and main receives the notice with a fixed no-summary
sentence.

WHAT LIVES HERE. Everything that needs the real graph: the failed tool result the guard
produces (from the execute hook AND the validate hook), the sibling of a tripping call, the
final request's sentence on every round shape (a query round, a non-query round, a rejected
call, two siblings), the dead end met on the way to the ceiling, the roster on the summary
turn, the session store's rows, and the sweep for main's idiom over everything the gather
model was ever shown. `tests/test_987_query_door.py` holds what is decidable without a model.

No `monkeypatch.setattr`: the model enters through `make_model`, the verb registry through
`verbs=`, the store through `extra_capabilities`, the agent through `gather_factory`.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

# `driver` FIRST: entering the `tools_gather` <-> `tools` cycle at `tools_gather` raises on a
# partially initialized module.
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.tests import _tenants1106 as T1106  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.hooks import budget_enforcer  # noqa: E402
from defender.runtime import driver, observe, session_store, tools_gather  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.query_tool import (  # noqa: E402
    QUERY_DOOR_CLOSED,
    QUERY_NOT_RUN,
)
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import PAYLOAD  # noqa: E402
from defender.tests.e2e.test_repeat_breaker_807 import GrantScopedVerbs  # noqa: E402
from defender.runtime.request_ceiling import FINAL_REQUEST  # noqa: E402
from defender.runtime.tools_gather import (  # noqa: E402
    NO_SUMMARY_FAILED,
    GatherRequest,
)
from defender.tests._session_store_705 import runs_base, sql  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    VerbRecorder,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import elastic_ok  # noqa: E402
from defender.tests.test_987_query_door import (  # noqa: E402
    HEADER_DEAD_END,
    HEADER_REQUEST_LIMIT,
    INCOMPLETE_IDIOM,
    frame_body,
    split,
)

pytestmark = pytest.mark.e2e

LEAD = "l-001"

PARAMS = {"native_query": "FROM logs | WHERE user.name == \"dev.dana\""}

#: The roster the production gather factory contributes, as the model is offered it. Restated
#: rather than derived: the claim below is that the SUMMARY turn's roster is THIS one, and a
#: roster derived from the first call would make "unchanged" unobservable.
GATHER_ROSTER = ["bash", "list_verbs", "query", "read_file", "template_search"]


def _query(i: int | None = None) -> ModelResponse:
    """One `query` call. `i` makes it DISTINCT (the repeat guard trips on the third identical
    request); omit it to repeat."""
    params = dict(PARAMS) if i is None else {"native_query": f"{PARAMS['native_query']} AND i:{i}"}
    return ModelResponse(parts=[ToolCallPart(
        tool_name="query", args={"system": "elastic", "verb": "query", "params": params})])


def _two_queries(a: int | None, b: int | None) -> ModelResponse:
    return ModelResponse(parts=[
        _query(a).parts[0], _query(b).parts[0],
    ])


def _bad_args() -> ModelResponse:
    """A `query` call the SCHEMA refuses (`params` is not an object) — the placement whose
    dead end is raised from the validate hook, not the execute hook."""
    return ModelResponse(parts=[ToolCallPart(
        tool_name="query", args={"system": "elastic", "verb": "query", "params": "not-a-dict"})])


def _list_verbs() -> ModelResponse:
    """A round spent on a tool that is NOT `query` — the round shape a door closed from inside
    `query` could never see."""
    return ModelResponse(parts=[ToolCallPart(tool_name="list_verbs", args={"system": "elastic"})])


def _text(body: str) -> ModelResponse:
    return ModelResponse(parts=[TextPart(content=body)])


SUMMARY = "measured: dev.dana reached two hosts (db-1, web-2); the third obligation is unestablished."


class GatherModel:
    """The gather side of a `FunctionModel`, replaying explicit responses and recording, per
    call, the roster it was offered and the message list it was handed."""

    __name__ = "GatherModel"

    def __init__(self, responses: list[ModelResponse]):
        self._responses = responses
        self.calls = 0
        self.rosters: list[list[str]] = []
        self.tool_choices: list = []
        self.inbound: list[list] = []

    def __call__(self, messages, info) -> ModelResponse:
        self.rosters.append(sorted(t.name for t in info.function_tools))
        self.tool_choices.append((info.model_settings or {}).get("tool_choice"))
        self.inbound.append(list(messages))
        i = self.calls
        self.calls += 1
        if i < len(self._responses):
            return self._responses[i]
        return _text("(script exhausted)")

    @property
    def last_inbound(self) -> list:
        return self.inbound[-1]


class _Lead:
    def __init__(self, run_dir: Path, model: GatherModel, rec: VerbRecorder, out: str):
        self.run_dir, self.model, self.rec, self.out = run_dir, model, rec, out

    @property
    def rows(self) -> list[dict]:
        return read_jsonl_rows(RunPaths(self.run_dir).executed_queries)

    @property
    def persisted(self) -> str:
        return (self.run_dir / "gather_summaries" / f"{LEAD}.md").read_text(encoding="utf-8")


def run_lead(  # noqa: PLR0913 — one parameter per thing a scenario varies
    root: Path, responses: list[ModelResponse], *, ceiling: int = 6,
    extra=(), session_id: str | None = None, stamps: list | None = None, verbs=None,
) -> _Lead:
    """Drive the REAL `_run_gather` over an agent the PRODUCTION factory built. Only the
    provider is replaced: `build_gather_agent`'s own `make_model` seam hands back a
    `FunctionModel`; the tools, capabilities, instructions and retry policy are the shipped
    ones."""
    run_dir = materialize(root, GOLDEN_AB3)
    budget_enforcer.open_budget(run_dir, budget_enforcer.DEFAULT_LIMITS)
    deps = bind(MAIN_DEF, run_dir, defender_dir=DEFENDER)
    rec = VerbRecorder()
    model = GatherModel(responses)
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")

    def factory(agent_id: str, system: str, request_limit: int):
        return driver.build_gather_agent(
            DEFENDER, logger, agent_id,
            make_model=lambda name, effort: BuiltModel(FunctionModel(model), None),
            verbs=verbs if verbs is not None else elastic_ok(rec),
            extra_capabilities=extra, session_id=session_id,
        )

    try:
        with override_allow_model_requests(False):
            out = asyncio.run(tools_gather._run_gather(
                deps, factory, ceiling,
                GatherRequest(LEAD, "elastic", "measure this lead",
                              ("which hosts dev.dana reached",)),
                T1106.playground_grants().gather,
                (lambda agent_id, reason: stamps.append((agent_id, reason)))
                if stamps is not None else None,
                catalog=None,
            ))
    finally:
        logger.close()
    return _Lead(run_dir, model, rec, out)


def tool_returns(messages: list) -> list[ToolReturnPart]:
    return [p for m in messages if isinstance(m, ModelRequest)
            for p in m.parts if isinstance(p, ToolReturnPart)]


def retry_prompts(messages: list) -> list[RetryPromptPart]:
    return [p for m in messages if isinstance(m, ModelRequest)
            for p in m.parts if isinstance(p, RetryPromptPart)]


def flat(messages: list) -> str:
    out: list[str] = []
    for m in messages:
        for p in getattr(m, "parts", []):
            c = getattr(p, "content", None)
            if c is not None:
                out.append(c if isinstance(c, str) else str(c))
    return "\n".join(out)


def failed(part: ToolReturnPart) -> bool:
    return part.outcome == "failed"


def user_parts(request: ModelRequest) -> list[str]:
    return [str(p.content) for p in request.parts if isinstance(p, UserPromptPart)]


def marked(messages: list) -> list[int]:
    """Indexes of the requests that carry the final-request sentence."""
    return [i for i, m in enumerate(messages)
            if isinstance(m, ModelRequest) and FINAL_REQUEST in user_parts(m)]


# =========================================================================================
# The dead end — a guard's stop is a tool result, and the next turn is the summary.
# =========================================================================================


def test_the_tripping_call_is_answered_with_the_guards_reason_and_the_summary_follows(tmp_path):
    """The defect, end to end. Three identical queries: the third trips the repeat guard.
    The gather model's fourth turn is its summary, and main receives it under the dead-end
    notice — the header `_run_gather` composed before #987, byte for byte, with the lead's own
    words below it after a blank line.

    The tripping call is ANSWERED, as a failed tool result carrying the guard's reason and the
    closing sentence — not raised out of the run. The two earlier queries executed (rows with
    exit 0); the trip wrote its own row; nothing else reached the backend."""
    stamps: list = []
    lead = run_lead(tmp_path, [_query(), _query(), _query(), _text(SUMMARY)], stamps=stamps)

    assert lead.model.calls == 4, "three query turns and one summary turn"
    header, body = split(lead.out)
    trip = next(r for r in lead.rows if r["exit_code"] != 0)
    assert header.startswith(f"gather for {LEAD} hit a dead end: ")
    assert "repeats the one already issued at seq 0" in header
    assert header.endswith(INCOMPLETE_IDIOM)
    assert body == SUMMARY, "main did not receive the lead's own summary under the notice"
    assert [r["exit_code"] for r in lead.rows] == [0, 0, trip["exit_code"]]
    assert len(lead.rec.calls) == 2, "the tripping call reached the backend"
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]

    # What the model was told, on the turn it wrote the summary.
    closing = tool_returns(lead.model.last_inbound)[-1]
    assert failed(closing), "the guard's stop is not a FAILED tool result"
    assert "repeats the one already issued at seq 0" in str(closing.content)
    assert str(closing.content).endswith(QUERY_DOOR_CLOSED)
    assert INCOMPLETE_IDIOM not in flat(lead.model.last_inbound), \
        "main's idiom reached the gather model (#807 G19)"
    assert lead.persisted == lead.out


def test_the_summary_turn_is_offered_the_same_tools_as_every_other_turn(tmp_path):
    """The reason the single-run shape is load-bearing and not a preference. A history that
    carries tool calls and tool results must be sent WITH tool definitions — the Anthropic
    Messages API refuses one that is not ("Requests which include `tool_use` or `tool_result`
    blocks must define tools"). A design that stripped the tools for the summary turn worked
    only on providers that do not check. Here the roster is the production roster on EVERY
    request, the summary turn included; what stops the model querying after a dead end is
    the tool's answer, not its absence — and no request here was the ceiling's, so none
    had its tools withheld."""
    lead = run_lead(tmp_path, [_query(), _query(), _query(), _text(SUMMARY)])
    assert lead.model.rosters == [GATHER_ROSTER] * 4
    assert lead.model.tool_choices == [None] * 4


def test_a_schema_refused_repeat_is_answered_from_the_validate_hook(tmp_path):
    """The other placement. A `query` call the schema refuses never reaches the execute hook,
    so its guard's dead end is raised from `wrap_tool_validate` — where a tool result cannot be
    RETURNED. It is a `ToolFailed` there, which the framework turns into the same failed tool
    result, without charging the tool's retry budget or appending "try again"; and the fourth
    turn is the summary, under the same notice."""
    lead = run_lead(tmp_path, [_bad_args(), _bad_args(), _bad_args(), _text(SUMMARY)])

    assert lead.model.calls == 4
    header, body = split(lead.out)
    assert "repeats the one already turned back at seq 0" in header
    assert body == SUMMARY
    assert lead.rec.calls == [], "a schema-refused call reached the backend"
    assert [r["exit_code"] for r in lead.rows] == [64, 64, 64]

    last = lead.model.last_inbound
    closing = tool_returns(last)[-1]
    assert failed(closing)
    assert str(closing.content).endswith(QUERY_DOOR_CLOSED)
    assert "try again" not in str(closing.content).lower(), \
        "the stop went out as a retry prompt — the model is told to try again and to stop"
    assert len(retry_prompts(last)) == 2, "the first two refusals are still corrections"


# =========================================================================================
# Siblings — a concurrent call is answered for what IT did, never with another call's reason.
# =========================================================================================


def test_a_sibling_of_the_tripping_call_is_never_told_it_was_a_repeat(tmp_path):
    """One round carries two `query` calls: a NEW request and the third repeat. The repeat
    trips. The sibling is answered for what happened to IT — either it ran (a row with exit 0,
    and its own result in its tool return) or it was refused because the door had already
    closed in this round (`SIBLING_NOT_RUN`) — and in neither case is it told that it "repeats
    the one already issued". Which of the two happens is the interleaving's to decide; that
    the sibling's return carries the repeat's reason is the defect this test exists for."""
    lead = run_lead(tmp_path, [
        _query(), _query(), _two_queries(99, None), _text(SUMMARY),
    ])
    assert lead.model.calls == 4
    header, body = split(lead.out)
    assert "repeats the one already issued at seq 0" in header
    assert body == SUMMARY

    returns = tool_returns(lead.model.last_inbound[-1:])
    assert len(returns) == 2, "one of the round's two calls was left unanswered"
    by_id = {p.tool_call_id: p for p in returns}
    calls = [p for p in lead.model.inbound[-1][-2].parts if isinstance(p, ToolCallPart)]
    sibling = next(c for c in calls if "i:99" in str(c.args))
    repeat = next(c for c in calls if "i:99" not in str(c.args))

    assert "repeats the one already issued" in str(by_id[repeat.tool_call_id].content)
    sibling_answer = str(by_id[sibling.tool_call_id].content)
    assert "repeats the one already issued" not in sibling_answer, \
        "the sibling was answered with the tripping call's reason"
    ran = any("i:99" in str(r.get("params")) and r["exit_code"] == 0 for r in lead.rows)
    if ran:
        assert not failed(by_id[sibling.tool_call_id])
        assert sibling_answer.startswith("exit=0")
    else:
        assert sibling_answer == QUERY_NOT_RUN
        assert not any("i:99" in str(c) for c in lead.rec.calls), \
            "a call answered 'not executed' reached the backend"


def test_a_sibling_listed_after_a_schema_refused_trip_is_refused_not_told_it_repeated(tmp_path):
    """The DETERMINISTIC placement of the sibling case: the trip is a schema-refused repeat, so
    it closes the door in the VALIDATE phase — the framework validates every call of a round
    before it executes any — and the good sibling meets the closed door at its own execution,
    whichever order they were listed in. Refused with `QUERY_NOT_RUN`, never with the
    repeat's reason; no row, no backend call."""
    lead = run_lead(tmp_path, [
        _bad_args(), _bad_args(),
        ModelResponse(parts=[_query(99).parts[0], _bad_args().parts[0]]),
        _text(SUMMARY),
    ])
    assert lead.model.calls == 4
    header, body = split(lead.out)
    assert "repeats the one already turned back at seq 0" in header
    assert body == SUMMARY
    returns = tool_returns(lead.model.last_inbound[-1:])
    assert len(returns) == 2
    calls = [p for p in lead.model.inbound[-1][-2].parts if isinstance(p, ToolCallPart)]
    sibling = next(c for c in calls if "i:99" in str(c.args))
    answer = next(p for p in returns if p.tool_call_id == sibling.tool_call_id)
    assert failed(answer)
    assert str(answer.content) == QUERY_NOT_RUN
    assert lead.rec.calls == [], "the refused sibling reached the backend"
    assert [r["exit_code"] for r in lead.rows] == [64, 64, 64]


# =========================================================================================
# The ceiling — the final request is marked, whatever the round before it did.
# =========================================================================================


def test_the_final_request_is_marked_and_is_the_summary(tmp_path):
    """Ceiling 3. Two distinct queries, then the summary. Both queries RUN and their results
    are reported as results (not failures, nothing appended to them). The THIRD request — the
    last the ceiling allows — carries the final-request sentence as a user part after the
    second query's return, and nothing before it does. Main receives the request-limit notice
    — naming the lead's OWN ceiling, not the framework's — with the summary under it. #808
    d21/F6: three requests, no more, and the ceiling was never lowered to buy the turn."""
    stamps: list = []
    lead = run_lead(tmp_path, [_query(0), _query(1), _text(SUMMARY)], ceiling=3, stamps=stamps)

    assert lead.model.calls == 3
    header, body = split(lead.out)
    assert header == HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=3)
    assert body == SUMMARY
    assert [r["exit_code"] for r in lead.rows] == [0, 0], "the second query did not run"
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_REQUEST_LIMIT)]

    last = lead.model.last_inbound
    returns = tool_returns(last)
    assert not failed(returns[-1]), "the last permitted query's result was reported as a failure"
    assert str(returns[-1].content).startswith("exit=0"), "the result itself was withheld"
    assert FINAL_REQUEST not in str(returns[-1].content), \
        "the sentence was pasted onto a tool result instead of being the round's own"
    assert marked(last) == [len(last) - 1], "the sentence is on a request other than the last"
    assert isinstance(last[-1].parts[-1], UserPromptPart)
    assert marked(lead.model.inbound[1]) == [], "the sentence came a round early"
    assert INCOMPLETE_IDIOM not in flat(last)


def test_a_round_with_no_query_in_it_is_told_all_the_same(tmp_path):
    """THE ROUND SHAPE A DOOR COULD NOT SEE. Ceiling 3: the model spends its first two rounds
    on `list_verbs` — no `query` call anywhere before the final request — and its third on
    a query. The final request is marked regardless of which tools the round before it used;
    a lead told nothing here was the defect a `query`-only stop re-created."""
    lead = run_lead(tmp_path, [_list_verbs(), _list_verbs(), _text(SUMMARY)], ceiling=3)
    assert lead.model.calls == 3
    assert split(lead.out) == (HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=3), SUMMARY)
    assert marked(lead.model.last_inbound) == [len(lead.model.last_inbound) - 1]


def test_the_final_request_withholds_the_tools_and_no_other_request_does(tmp_path):
    """The tools are DEFINED on every request — the summary turn's roster is the production
    roster — and the final request alone says none may be chosen. On a provider that honours
    it, the model's only possible answer to its final request is text."""
    lead = run_lead(tmp_path, [_query(0), _query(1), _text(SUMMARY)], ceiling=3)
    assert lead.model.rosters == [GATHER_ROSTER] * 3
    assert lead.model.tool_choices == [None, None, "none"]


def test_a_summary_written_beside_a_stray_query_on_the_final_request_is_kept(tmp_path):
    """Ceiling 3: `list_verbs`, then a query, then — on the final request, from a provider
    that ignored `tool_choice` — the summary AND one more query in one response. The call is
    dropped before the framework sees it (no row, no backend call, no refusal to answer),
    the text is the summary, and main receives it under the request-limit notice. The one
    query that ran is in the table. A design that refused the call and let the framework
    end the run lost this very text."""
    stamps: list = []
    both = ModelResponse(parts=[TextPart(content=SUMMARY), _query(1).parts[0]])
    lead = run_lead(tmp_path, [_list_verbs(), _query(0), both], ceiling=3, stamps=stamps)
    assert lead.model.calls == 3
    assert split(lead.out) == (HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=3), SUMMARY)
    assert [r["exit_code"] for r in lead.rows] == [0], "the final request's query ran"
    assert len(lead.rec.calls) == 1
    assert marked(lead.model.last_inbound) == [len(lead.model.last_inbound) - 1]
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_REQUEST_LIMIT)]


def test_a_final_request_answered_with_only_a_query_is_a_lead_with_no_summary(tmp_path):
    """Ceiling 3: the model answers its marked final request with a tool call and NO text.
    The call is dropped (no row, no backend call), what remains is an empty response, and
    the gather agent's retry policy (no output retries) ends the run on it. Main receives the
    REQUEST-LIMIT notice — the record says the ceiling was marked, and that is what main
    reasons from — with the fixed no-summary sentence, and the session is stamped with the
    ceiling that cut it off, not the framework's retry count. No fourth request was made."""
    stamps: list = []
    lead = run_lead(tmp_path, [_list_verbs(), _query(0), _query(1), _text("too late")],
                    ceiling=3, stamps=stamps)
    assert lead.model.calls == 3
    assert split(lead.out) == (HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=3), NO_SUMMARY_FAILED)
    assert "too late" not in lead.out
    assert "Exceeded maximum" not in lead.out, "the framework's text reached main over the stop"
    assert [r["exit_code"] for r in lead.rows] == [0], "the final request's query ran"
    assert len(lead.rec.calls) == 1
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_REQUEST_LIMIT)]


def _unknown_verb() -> ModelResponse:
    """A `query` call the GRANT CHECK turns back (no such verb) — a rejection raised from the
    execute hook, where the schema-refused call's is raised from the validate hook."""
    return ModelResponse(parts=[ToolCallPart(
        tool_name="query", args={"system": "elastic", "verb": "no-such-verb", "params": {}})])


@pytest.mark.parametrize(("placement", "rejected"), [
    ("validate", _bad_args()), ("execute", _unknown_verb()),
])
def test_a_rejection_before_the_final_request_is_a_correction_and_the_round_is_still_marked(
        tmp_path, placement, rejected):
    """Ceiling 3; the second round's call is REJECTED. The rejection goes out as the retry
    prompt it is at either placement — the tool's answer is about the call — and the request
    that carries it is the final one, so it ALSO carries the final-request sentence, after the
    retry. The model's third request is the summary, under the request-limit notice. The
    ceiling neither swallows the correction nor forgets to mark the round."""
    lead = run_lead(tmp_path, [_query(0), rejected, _text(SUMMARY)], ceiling=3)
    assert lead.model.calls == 3
    assert split(lead.out) == (HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=3), SUMMARY)
    last = lead.model.last_inbound
    assert len(retry_prompts(last)) == 1, f"the {placement} rejection was not a correction"
    assert marked(last) == [len(last) - 1]
    assert isinstance(last[-1].parts[-1], UserPromptPart), \
        "the sentence does not come after the correction"
    assert len(lead.rec.calls) == 1, "the rejected call reached the backend"


def test_two_queries_on_the_last_permitted_round_both_run_though_one_is_refused(tmp_path):
    """Ceiling 3. The second round — the last one whose calls run — lists a good query and a
    schema-refused one. The schema refusal is a correction; the good query RUNS and its
    result is shown — nothing in the ceiling closes a door on siblings, because the ceiling
    is not a door. Main receives the summary under the request-limit notice, and the table
    holds both calls."""
    lead = run_lead(tmp_path, [
        _query(0), ModelResponse(parts=[_query(1).parts[0], _bad_args().parts[0]]),
        _text(SUMMARY),
    ], ceiling=3)
    assert lead.model.calls == 3
    assert split(lead.out) == (HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=3), SUMMARY)
    assert sorted(r["exit_code"] for r in lead.rows) == [0, 0, 64]
    assert len(lead.rec.calls) == 2, "the good sibling did not reach the backend"
    last = lead.model.last_inbound
    ok = [p for p in tool_returns(last[-1:]) if not failed(p)]
    assert len(ok) == 1
    assert str(ok[0].content).startswith("exit=0")
    assert marked(last) == [len(last) - 1]


def test_a_dead_end_met_before_the_ceiling_is_what_main_is_told(tmp_path):
    """Ceiling 4. Three identical queries: the third trips the guard on round 3 and the
    fourth request is BOTH the closing tool result and the marked final request. The model
    writes its summary there; main receives it under the DEAD-END notice — the guard's
    sentence names the request that stopped the lead, the ceiling's could only count — with
    the dead-end terminator. The dead end is never lost to the ceiling."""
    stamps: list = []
    lead = run_lead(tmp_path, [_query(), _query(), _query(), _text(SUMMARY)],
                    ceiling=4, stamps=stamps)
    assert lead.model.calls == 4
    header, body = split(lead.out)
    assert "repeats the one already issued at seq 0" in header
    assert body == SUMMARY
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]
    last = lead.model.last_inbound
    assert str(tool_returns(last)[-1].content).endswith(QUERY_DOOR_CLOSED)
    assert marked(last) == [len(last) - 1]


def test_a_lead_that_finishes_inside_its_ceiling_is_not_relabelled(tmp_path):
    """The positive control. Ceiling 6, one query, then the summary: no notice, no header,
    no idiom, no stamp — the text main receives is the lead's own, alone, and the gather model
    was never told to stop."""
    stamps: list = []
    lead = run_lead(tmp_path, [_query(0), _text(SUMMARY)], ceiling=6, stamps=stamps)
    assert lead.model.calls == 2
    assert stamps == []
    assert frame_body(lead.out) == SUMMARY
    assert INCOMPLETE_IDIOM not in lead.out
    assert all(marked(m) == [] for m in lead.model.inbound)
    assert QUERY_DOOR_CLOSED not in flat(lead.model.last_inbound)


# =========================================================================================
# After a dead end — the door stays closed, the model keeps its turns, the ceiling bounds it.
# =========================================================================================


def test_querying_again_after_a_dead_end_is_refused_and_the_summary_still_arrives(tmp_path):
    """Three repeats trip the guard; the fourth turn is ANOTHER query. It is never executed
    (no row, no backend call), answered `QUERY_NOT_RUN`, and the FIFTH turn's text is the
    summary main receives under the dead-end notice. No grace turn is forfeited: the summary
    is the point, and refusing a call costs nothing."""
    stamps: list = []
    lead = run_lead(tmp_path, [_query(), _query(), _query(), _query(7), _text(SUMMARY)],
                    stamps=stamps)
    assert lead.model.calls == 5
    header, body = split(lead.out)
    assert "repeats the one already issued at seq 0" in header
    assert body == SUMMARY
    assert len(lead.rows) == 3, "the refused query wrote a row"
    assert not any("i:7" in str(c) for c in lead.rec.calls), "the refused query ran"
    closing = tool_returns(lead.model.last_inbound)[-1]
    assert failed(closing)
    assert str(closing.content) == QUERY_NOT_RUN
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]


def test_a_summary_written_alongside_a_stray_query_is_not_thrown_away(tmp_path):
    """Tool-happy gather models emit text and a tool call in one response. After a dead end,
    the response carrying BOTH the summary and one more `query` is not the end of anything:
    the query is refused, and the model's next turn — the text alone — is what main receives.
    A design that ended the run on the stray call discarded the summary in that very
    response."""
    both = ModelResponse(parts=[TextPart(content=SUMMARY), _query(7).parts[0]])
    lead = run_lead(tmp_path, [_query(), _query(), _query(), both, _text(SUMMARY)])
    assert lead.model.calls == 5
    header, body = split(lead.out)
    assert "repeats the one already issued at seq 0" in header
    assert body == SUMMARY
    assert not any("i:7" in str(c) for c in lead.rec.calls)


def test_a_model_that_never_stops_querying_after_a_dead_end_is_bounded_by_the_ceiling(tmp_path):
    """Ceiling 5: the guard trips on round 3, the model queries on rounds 4 AND 5. Round 4's
    call is refused at the door (three rows in the table, two backend calls); the fifth
    request is the marked, tool-less final request; its query is dropped, no text remains,
    and the run ends on the empty response. Main receives the DEAD-END notice — the guard's
    reason is what it reasons from — over the no-summary sentence, and the session is stamped
    with the dead end: the stop outranks the ceiling, and both outrank the fault."""
    stamps: list = []
    lead = run_lead(tmp_path, [_query(), _query(), _query(), _query(7), _query(8), _text("x")],
                    ceiling=5, stamps=stamps)
    assert lead.model.calls == 5
    header, body = split(lead.out)
    assert "repeats the one already issued at seq 0" in header
    assert body == NO_SUMMARY_FAILED
    assert len(lead.rows) == 3
    assert len(lead.rec.calls) == 2
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]


def _withheld_verb(rec: VerbRecorder) -> GrantScopedVerbs:
    """`query` granted, `withheld` declared but NOT granted — the registry shape that reaches
    the grant check's DENIED outcome."""

    def query(ctx: VerbContext, *, native_query: str, limit: int = 10) -> list[dict]:
        rec.record("query", ctx, {"native_query": native_query, "limit": limit})
        return PAYLOAD

    def withheld(ctx: VerbContext, *, native_query: str) -> list[dict]:  # pragma: no cover
        rec.record("withheld", ctx, {"native_query": native_query})
        return PAYLOAD

    return GrantScopedVerbs(
        {"elastic": {"query": query, "withheld": withheld}},
        VerbGrant(role="gather", entries=(("elastic", "query", "r"),)),
    )


def test_a_denied_verb_after_a_dead_end_still_leaves_its_denial_record(tmp_path):
    """The grant check sits ABOVE the door: a call against a verb outside the lead's grant,
    issued after the door closed, is answered as the DENIAL it is and writes its
    policy-denial record — the invariant the grant check's own docstring states (§7 R3/R23:
    a denied call always produces its denial record, whatever else is wrong with it). A door
    that refused first would leave an out-of-grant attempt with no audit trail. The evidence
    table still has no row for it, and the summary still arrives."""
    rec = VerbRecorder()
    denied = ModelResponse(parts=[ToolCallPart(
        tool_name="query",
        args={"system": "elastic", "verb": "withheld", "params": {"native_query": "FROM x"}})])
    lead = run_lead(tmp_path, [_query(), _query(), _query(), denied, _text(SUMMARY)],
                    verbs=_withheld_verb(rec))
    assert lead.model.calls == 5
    assert split(lead.out)[1] == SUMMARY
    denials = read_jsonl_rows(RunPaths(lead.run_dir).policy_denials)
    assert [(d["system"], d["verb"]) for d in denials] == [("elastic", "withheld")]
    assert len(lead.rows) == 3, "a denied call wrote an evidence row"
    assert [c.verb for c in rec.calls] == ["query", "query"]
    answer = tool_returns(lead.model.last_inbound)[-1]
    assert str(answer.content) != QUERY_NOT_RUN, "the denial was answered as a closed door"


# =========================================================================================
# The store — the stopped lead's session records its summary round like any other.
# =========================================================================================


def test_the_stopped_leads_session_is_recorded_like_a_finished_ones(tmp_path):
    """One run, one recorder, one ceiling: the session holds one request and one response
    per round, plus the summary turn's own request — the closing tool result is IN that
    request, recorded under the lead's own session — and ends on that request, the trailing
    parity every finished gather session has (there is no gather-side run-end flush)."""
    base = runs_base(tmp_path / "db")
    store = session_store.open_store(case_id="case-987", runs_base=base)
    session_id = store.new_session(agent_id=f"gather:{LEAD}")
    caps = driver._gather_extra_capabilities(store, session_id, f"gather:{LEAD}", request_limit=6)

    lead = run_lead(tmp_path, [_query(), _query(), _query(), _text(SUMMARY)],
                    extra=caps, session_id=session_id)
    assert split(lead.out)[1] == SUMMARY

    kinds = [k for (k,) in sql(store, """
        SELECT m.kind FROM message m JOIN session s ON s.session_id = m.session_id
        WHERE s.agent_id = ? ORDER BY m.id
    """, (f"gather:{LEAD}",))]
    assert kinds == ["request", "response"] * 3 + ["request"], kinds
    last_payload = sql(store, """
        SELECT p.payload FROM message m
        JOIN session s ON s.session_id = m.session_id
        JOIN message_payload p ON p.message_id = m.id
        WHERE s.agent_id = ? ORDER BY m.id DESC LIMIT 1
    """, (f"gather:{LEAD}",))[0][0]
    assert QUERY_DOOR_CLOSED in str(last_payload), \
        "the summary turn's request — the one carrying the closing answer — was not recorded"


def test_the_marked_final_request_is_recorded_as_it_was_sent(tmp_path):
    """The ceiling's sentence is added to the request BEFORE the recorder commits it — the
    ceiling hook sits ahead of every extra capability on a gather agent — so the session
    holds the request the model actually read, sentence included, and not a shorter one."""
    base = runs_base(tmp_path / "db")
    store = session_store.open_store(case_id="case-987c", runs_base=base)
    session_id = store.new_session(agent_id=f"gather:{LEAD}")
    caps = driver._gather_extra_capabilities(store, session_id, f"gather:{LEAD}", request_limit=3)

    lead = run_lead(tmp_path, [_query(0), _query(1), _text(SUMMARY)], ceiling=3,
                    extra=caps, session_id=session_id)
    assert split(lead.out)[1] == SUMMARY
    kinds = [k for (k,) in sql(store, """
        SELECT m.kind FROM message m JOIN session s ON s.session_id = m.session_id
        WHERE s.agent_id = ? ORDER BY m.id
    """, (f"gather:{LEAD}",))]
    assert kinds == ["request", "response"] * 2 + ["request"], kinds
    last_payload = sql(store, """
        SELECT p.payload FROM message m
        JOIN session s ON s.session_id = m.session_id
        JOIN message_payload p ON p.message_id = m.id
        WHERE s.agent_id = ? ORDER BY m.id DESC LIMIT 1
    """, (f"gather:{LEAD}",))[0][0]
    assert FINAL_REQUEST in str(last_payload), \
        "the final request was committed without the sentence the model was sent"


# =========================================================================================
# G19 — the gather model never sees main's idiom; main always does.
# =========================================================================================


@pytest.mark.parametrize("scenario", ["dead-end", "ceiling", "spent", "stray", "both"])
def test_the_gather_model_never_sees_mains_idiom_but_main_always_does(tmp_path, scenario):
    script, ceiling = {
        "dead-end": ([_query(), _query(), _query(), _text(SUMMARY)], 6),
        "ceiling": ([_query(0), _query(1), _text(SUMMARY)], 3),
        "spent": ([_query(0), _query(1), _query(2)], 3),
        "stray": ([_query(0), _query(1),
                   ModelResponse(parts=[TextPart(content=SUMMARY), _query(2).parts[0]])], 3),
        "both": ([_query(), _query(), _query(), _query(7), _query(8)], 5),
    }[scenario]
    lead = run_lead(tmp_path, script, ceiling=ceiling)
    everything_gather_saw = "\n".join(flat(m) for m in lead.model.inbound)
    assert INCOMPLETE_IDIOM not in everything_gather_saw
    assert "Treat this lead" not in everything_gather_saw
    assert INCOMPLETE_IDIOM in lead.out
    assert HEADER_DEAD_END.split("{")[0] in lead.out or \
        HEADER_REQUEST_LIMIT.split("{")[0] in lead.out
