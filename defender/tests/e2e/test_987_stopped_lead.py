"""#987 — a STOPPED lead writes its own summary, through the REAL gather agent."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

from dataclasses import replace as _with_live_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _live_run_1165

import asyncio
from dataclasses import replace
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
from defender.investigation.driver import MAIN_DEF  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender._io import read_jsonl_rows  # noqa: E402
from defender.records import RunPaths  # noqa: E402
from defender.investigation import driver, observe, tools_gather  # noqa: E402
from defender.records import session_store  # noqa: E402
from defender.investigation.agent_definition import bind  # noqa: E402
from defender.providers import BuiltModel  # noqa: E402
from defender.investigation.query_tool import (  # noqa: E402
    QUERY_DOOR_CLOSED,
    QUERY_NOT_RUN,
)
from defender.systems.verb_grant import VerbGrant  # noqa: E402
from defender.systems.verbs import VerbContext  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import PAYLOAD  # noqa: E402
from defender.tests.e2e.test_repeat_breaker_807 import GrantScopedVerbs  # noqa: E402
from defender.investigation.request_ceiling import FINAL_REQUEST  # noqa: E402
from defender.investigation.tools_gather import (  # noqa: E402
    NO_SUMMARY_FAILED,
    GatherRequest,
)
from defender.tests.support.storage._session_store_705 import runs_base, sql  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    VerbRecorder,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import elastic_ok  # noqa: E402
from defender.tests.integrations.test_987_query_door import (  # noqa: E402
    HEADER_DEAD_END,
    HEADER_REQUEST_LIMIT,
    INCOMPLETE_IDIOM,
    frame_body,
    split,
)
from defender.records import SessionPaths  # noqa: E402

pytestmark = pytest.mark.e2e

LEAD = "l-001"

PARAMS = {"native_query": "FROM logs | WHERE user.name == \"dev.dana\""}

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
    `FunctionModel`; the tools, capabilities, instructions and retry policy are the shipped"""
    run_dir = materialize(root, GOLDEN_AB3)
    from defender.investigation.run_state import RunState

    # #1106: a run hands MAIN's deps its tenant's record, which every lead inherits.
    deps = replace(_with_live_run_1165(bind(MAIN_DEF, run_dir, defender_dir=DEFENDER), run=_live_run_1165(run_dir)),
                   tenant=T1106.fixture_run_tenant(),
                   run_state=RunState(run_dir, run_dir.name))
    rec = VerbRecorder()
    model = GatherModel(responses)
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")

    def factory(agent_id: str, system: str, request_limit: int):
        return driver.build_gather_agent(
            DEFENDER, logger, agent_id,
            make_model=lambda name, effort: BuiltModel(FunctionModel(model), None),
            verbs=verbs if verbs is not None else elastic_ok(rec),
            extra_capabilities=extra, session_id=session_id,
            verb_grant=T1106.fixture_grants().gather,
        )

    try:
        with override_allow_model_requests(False):
            out = asyncio.run(tools_gather._run_gather(
                deps, factory, ceiling,
                GatherRequest(LEAD, "elastic", "measure this lead",
                              ("which hosts dev.dana reached",)),
                T1106.fixture_grants().gather,
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


def test_the_tripping_call_is_answered_with_the_guards_reason_and_the_summary_follows(tmp_path):
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


def test_a_schema_refused_repeat_is_answered_from_the_validate_hook(tmp_path):
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


def test_a_sibling_of_the_tripping_call_is_never_told_it_was_a_repeat(tmp_path):
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


def test_the_final_request_is_marked_and_is_the_summary(tmp_path):
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


def test_the_final_request_withholds_the_tools_and_no_other_request_does(tmp_path):
    lead = run_lead(tmp_path, [_query(0), _query(1), _text(SUMMARY)], ceiling=3)
    assert lead.model.rosters == [GATHER_ROSTER] * 3
    assert lead.model.tool_choices == [None, None, "none"]


def test_a_summary_written_beside_a_stray_query_on_the_final_request_is_kept(tmp_path):
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
    stamps: list = []
    lead = run_lead(tmp_path, [_query(0), _text(SUMMARY)], ceiling=6, stamps=stamps)
    assert lead.model.calls == 2
    assert stamps == []
    assert frame_body(lead.out) == SUMMARY
    assert INCOMPLETE_IDIOM not in lead.out
    assert all(marked(m) == [] for m in lead.model.inbound)
    assert QUERY_DOOR_CLOSED not in flat(lead.model.last_inbound)


def test_querying_again_after_a_dead_end_is_refused_and_the_summary_still_arrives(tmp_path):
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


def test_a_model_that_never_stops_querying_after_a_dead_end_is_bounded_by_the_ceiling(tmp_path):
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


def test_the_stopped_leads_session_is_recorded_like_a_finished_ones(tmp_path):
    base = runs_base(tmp_path / "db")
    store = session_store.open_store(case_id="case-987", sessions=SessionPaths(fixture_runs_base(base)))
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
