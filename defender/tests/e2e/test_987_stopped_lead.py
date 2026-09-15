"""#987 — a STOPPED lead writes its own summary, through the REAL gather agent.

THE DEFECT. When the harness stopped a gather lead — a guard's dead end, or the request ceiling
— it did so by raising out of the run, authored a stand-in notice, and main never saw the
answers the sub-agent had already retrieved: they lived in the gather run's own context, which
unwound with the run. Main may not read `gather_raw/` (policy, not accident) and the queries
table carries digests, not answers, so a lead that answered six queries and then repeated one
read to main as empty.

THE CHANGE. The lead is not cut. The query tool CLOSES THE LEAD'S DOOR (`QueryDoor`, on the
deps) and says so in the tool result itself — the guard's own reason, or "this was the last
query round the budget allows" — followed by the instruction to write the summary now. The
model's next turn is that summary, the run ends the way a finished lead's does, and
`_run_gather` reads the door afterwards to stamp the terminator and put the arm's notice
ABOVE the summary. Nothing is replayed, no second run is made, the tools stay on the wire for
every request, and the ceiling is one number enforced in one place.

The model that queries AGAIN after being told to stop forfeits the one grace turn: the run
ends on the stored stop and main receives the notice with a fixed no-summary sentence.

WHAT LIVES HERE. Everything that needs the real graph: the failed tool result the guard
produces (from the execute hook AND the validate hook), the sibling of a tripping call, the
last query round's suffix, the forfeited grace turn on both stops, the roster on the summary
turn, the session store's rows, and the sweep for main's idiom over everything the gather model
was ever shown. `tests/test_987_query_door.py` holds what is decidable without a model.

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
)
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

# `driver` FIRST: entering the `tools_gather` <-> `tools` cycle at `tools_gather` raises on a
# partially initialized module.
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.hooks import budget_enforcer  # noqa: E402
from defender.runtime import driver, observe, session_store, tools_gather  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.query_tool import (  # noqa: E402
    BUDGET_SPENT,
    QUERY_DOOR_CLOSED,
    SIBLING_NOT_RUN,
)
from defender.runtime.tools_gather import (  # noqa: E402
    NO_SUMMARY_FORFEITED,
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
        self.inbound: list[list] = []

    def __call__(self, messages, info) -> ModelResponse:
        self.rosters.append(sorted(t.name for t in info.function_tools))
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
    extra=(), session_id: str | None = None, stamps: list | None = None,
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
            verbs=elastic_ok(rec), extra_capabilities=extra, session_id=session_id,
        )

    try:
        with override_allow_model_requests(False):
            out = asyncio.run(tools_gather._run_gather(
                deps, factory, ceiling,
                GatherRequest(LEAD, "elastic", "measure this lead",
                              ("which hosts dev.dana reached",)),
                GATHER_DEF.verb_grant,
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
    request, the summary turn included; what stops the model querying is the tool's answer,
    not its absence."""
    lead = run_lead(tmp_path, [_query(), _query(), _query(), _text(SUMMARY)])
    assert lead.model.rosters == [GATHER_ROSTER] * 4


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
        assert sibling_answer == SIBLING_NOT_RUN
        assert not any("i:99" in str(c) for c in lead.rec.calls), \
            "a call answered 'not executed' reached the backend"


# =========================================================================================
# The ceiling — the last query round is announced, the final request is the summary.
# =========================================================================================


def test_the_last_query_round_is_announced_and_the_final_request_is_the_summary(tmp_path):
    """Ceiling 3. Two distinct queries, then the summary. The SECOND round is the last the
    ceiling allows a result for: its return carries the query's result AND the budget
    sentence, so the model's third (final) request is the summary. Main receives the
    request-limit notice — naming the lead's OWN ceiling, not the framework's — with the
    summary under it. #808 d21/F6: three requests, no more, and the ceiling was never
    lowered to buy the turn."""
    stamps: list = []
    lead = run_lead(tmp_path, [_query(0), _query(1), _text(SUMMARY)], ceiling=3, stamps=stamps)

    assert lead.model.calls == 3
    header, body = split(lead.out)
    assert header == HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=3)
    assert body == SUMMARY
    assert [r["exit_code"] for r in lead.rows] == [0, 0], "the second query did not run"
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_REQUEST_LIMIT)]

    returns = tool_returns(lead.model.last_inbound)
    assert not failed(returns[-1]), "the last permitted query's result was reported as a failure"
    assert str(returns[-1].content).startswith("exit=0"), "the result itself was withheld"
    assert str(returns[-1].content).endswith(BUDGET_SPENT)
    earlier = tool_returns(lead.model.inbound[1])
    assert BUDGET_SPENT not in str(earlier[-1].content), "the budget sentence came a round early"
    assert INCOMPLETE_IDIOM not in flat(lead.model.last_inbound)


def _unknown_verb() -> ModelResponse:
    """A `query` call the GRANT CHECK turns back (no such verb) — a rejection raised from the
    execute hook, where the schema-refused call's is raised from the validate hook."""
    return ModelResponse(parts=[ToolCallPart(
        tool_name="query", args={"system": "elastic", "verb": "no-such-verb", "params": {}})])


@pytest.mark.parametrize(("placement", "rejected"), [
    ("validate", _bad_args()), ("execute", _unknown_verb()),
])
def test_a_rejection_on_the_last_query_round_closes_the_door_instead_of_asking_for_a_retry(
        tmp_path, placement, rejected):
    """Ceiling 3; the second round's call is REJECTED. A correction has no round left to be
    applied in, so at either placement the rejection goes out as a failed result that ends
    on the budget sentence — not as a retry prompt, whose "try again" would contradict it —
    and the third request is the summary, under the request-limit notice."""
    lead = run_lead(tmp_path, [_query(0), rejected, _text(SUMMARY)], ceiling=3)
    assert lead.model.calls == 3
    header, body = split(lead.out)
    assert header == HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=3)
    assert body == SUMMARY
    last = lead.model.last_inbound
    assert retry_prompts(last) == [], f"the {placement} rejection went out as a retry"
    closing = tool_returns(last)[-1]
    assert failed(closing)
    assert str(closing.content).endswith(BUDGET_SPENT)
    assert len(lead.rec.calls) == 1, "the rejected call reached the backend"


def test_a_lead_that_finishes_inside_its_ceiling_is_not_relabelled(tmp_path):
    """The positive control. Ceiling 6, one query, then the summary: no notice, no header,
    no idiom, no stamp — the text main receives is the lead's own, alone, and the gather model
    was never told to stop."""
    stamps: list = []
    lead = run_lead(tmp_path, [_query(0), _text(SUMMARY)], ceiling=6, stamps=stamps)
    assert lead.model.calls == 2
    assert stamps == []
    from defender.tests.test_987_query_door import frame_body
    assert frame_body(lead.out) == SUMMARY
    assert INCOMPLETE_IDIOM not in lead.out
    assert BUDGET_SPENT not in flat(lead.model.last_inbound)
    assert QUERY_DOOR_CLOSED not in flat(lead.model.last_inbound)


# =========================================================================================
# The forfeited grace turn — a model that queries after being told to stop gets no summary.
# =========================================================================================


def test_querying_again_after_a_dead_end_forfeits_the_summary(tmp_path):
    """Three repeats trip the guard; the fourth turn is ANOTHER query. That query is never
    executed (no row, no backend call) and the run ends on the stored dead end: main receives
    the notice and the fixed no-summary sentence, never a fifth turn's text."""
    stamps: list = []
    lead = run_lead(tmp_path, [_query(), _query(), _query(), _query(7), _text("too late")],
                    stamps=stamps)
    assert lead.model.calls == 4, "the model was given a second grace turn"
    header, body = split(lead.out)
    assert "repeats the one already issued at seq 0" in header
    assert body == NO_SUMMARY_FORFEITED
    assert "too late" not in lead.out
    assert len(lead.rows) == 3, "the forfeiting query wrote a row"
    assert not any("i:7" in str(c) for c in lead.rec.calls), "the forfeiting query ran"
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]


def test_querying_on_the_reserved_request_forfeits_the_summary(tmp_path):
    """Ceiling 3, three queries. The second round carried the budget sentence; the third
    request is a query anyway. It is answered "closed" without executing, the framework
    refuses a fourth request, and main receives the request-limit notice with the no-summary
    sentence. Three requests: the ceiling holds."""
    stamps: list = []
    lead = run_lead(tmp_path, [_query(0), _query(1), _query(2), _text("too late")],
                    ceiling=3, stamps=stamps)
    assert lead.model.calls == 3
    header, body = split(lead.out)
    assert header == HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=3)
    assert body == NO_SUMMARY_FORFEITED
    assert [r["exit_code"] for r in lead.rows] == [0, 0], "the third query ran"
    assert len(lead.rec.calls) == 2
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_REQUEST_LIMIT)]


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


# =========================================================================================
# G19 — the gather model never sees main's idiom; main always does.
# =========================================================================================


@pytest.mark.parametrize("scenario", ["dead-end", "ceiling", "forfeited"])
def test_the_gather_model_never_sees_mains_idiom_but_main_always_does(tmp_path, scenario):
    script, ceiling = {
        "dead-end": ([_query(), _query(), _query(), _text(SUMMARY)], 6),
        "ceiling": ([_query(0), _query(1), _text(SUMMARY)], 3),
        "forfeited": ([_query(), _query(), _query(), _query(7)], 6),
    }[scenario]
    lead = run_lead(tmp_path, script, ceiling=ceiling)
    everything_gather_saw = "\n".join(flat(m) for m in lead.model.inbound)
    assert INCOMPLETE_IDIOM not in everything_gather_saw
    assert "Treat this lead" not in everything_gather_saw
    assert INCOMPLETE_IDIOM in lead.out
    assert HEADER_DEAD_END.split("{")[0] in lead.out or \
        HEADER_REQUEST_LIMIT.split("{")[0] in lead.out
