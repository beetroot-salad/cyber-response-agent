"""#987 — the SALVAGE TURN, through the REAL gather agent.

THE CODE DOES NOT EXIST YET. RED by construction, like its sibling.

`tests/test_987_salvage_seam.py` holds everything decidable with a fake gather agent — the
ceiling arithmetic, the arm census, the header bytes, the terminator. THIS module holds
everything that is not, and it holds it because a mocked agent would certify exactly the
mechanism the design leans on:

  - **The tool-less turn (O3/M4).** `Agent.override(toolsets=[], tools=[], native_tools=[])`
    is documented for the toolsets an agent was BUILT with and silent about the ones a
    capability contributes. The design records that as unpinned (c15), so the pin is a run
    through the production factory — `driver.build_gather_agent`, the real `GATHER_DEF`, the
    real `QueryCapture` — reading the roster off `AgentInfo`, which is the tool definitions as
    THE MODEL is offered them. A registry entry or an `agent._function_toolset` peek would both
    pass while the wire carried something else.
  - **Closing the dangling call (M3).** pydantic-ai refuses a new user prompt over a history
    that ends on unanswered tool calls ("Cannot provide a new user prompt when the message
    history contains unprocessed tool calls" — c2, executed). So the summary turn producing
    text at all is the proof that the harness answered every dangling call first. Stubbing the
    agent would make that proof vacuous.
  - **A failed summary turn (O4).** The gather build sets output retries to 0 (`_build.py:158`,
    c10), so a response with no actionable part fails the turn for real, through the real
    graph, as `UnexpectedModelBehavior`. `raise Exception("boom")` from a stub would pass
    against an implementation that only handles the exception it was handed.
  - **A hallucinated tool call (c11).** Under `request_limit=1` a tool call on the tool-less
    turn becomes a retry round and the next request trips the limit: no tool executes, no
    queries-table row is written, one request is spent. That is three facts about pydantic-ai's
    graph, and none of them survives being mocked.

Two layers, both real:

  1. `_run_gather` over an agent built by the PRODUCTION factory at a ceiling this file
     chooses. Everything from the dispatch down is production code — the query tool, the repeat
     guard, the capture capability, the two tables, the recorder — and the ceiling is small
     enough to drive the request-limit arm in three turns instead of forty.
  2. The whole loop through `_replay_harness.drive`, for the obligations that are about MAIN:
     what main receives, what main may not read, and what the session store records.

No `monkeypatch.setattr`: the model enters through `make_model`, the verb registry through
`verbs=`, the store through `store_factory=`/`extra_capabilities`, and the agent through
`gather_factory` — every one a seam the entry point already declares.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

# `driver` FIRST — see the note in `tests/test_987_salvage_seam.py`: entering the
# `tools_gather` <-> `tools` cycle at `tools_gather` raises on a partially initialized module.
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.hooks import budget_enforcer  # noqa: E402
from defender.runtime import driver, observe, permission, session_store, tools_gather  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.tools_gather import GatherRequest  # noqa: E402
from defender.tests._session_store_705 import runs_base, sql, store_factory  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import elastic_ok  # noqa: E402

# THE SURFACE UNDER TEST — none of it exists on this base (RED by construction).
from defender.runtime.tools_gather import (  # noqa: E402
    SALVAGE_CLOSED_SENTENCE,
    SALVAGE_PROMPT,
    SALVAGE_REQUEST_LIMIT,
)
from defender.scripts.gather_tools import record_query as rq  # noqa: E402
from defender.tests.test_987_salvage_seam import (  # noqa: E402
    HEADER_DEAD_END,
    HEADER_RETRY_EXHAUSTED,
    HEADER_STORE,
    INCOMPLETE_IDIOM,
    split,
    frame_body,
)

pytestmark = pytest.mark.e2e

LEAD = "l-001"

#: The roster the production gather factory really contributes, as the model is offered it.
#: Restated rather than derived: O3's whole content is that the summary turn's roster is
#: DIFFERENT from this one, and deriving both from the same call would make the difference
#: unobservable. If a tool is added to `GATHER_DEF` this constant is the one place to say so.
GATHER_ROSTER = ["bash", "list_verbs", "query", "read_file", "template_search"]

PARAMS = {"native_query": "FROM logs | WHERE user.name == \"dev.dana\""}


def _query(i: int | None = None) -> ModelResponse:
    """One `query` call. `i` makes it DISTINCT (the repeat guard trips on the third identical
    request, which is a different arm); omit it to repeat."""
    params = dict(PARAMS) if i is None else {"native_query": f"{PARAMS['native_query']} AND i:{i}"}
    return ModelResponse(parts=[ToolCallPart(
        tool_name="query", args={"system": "elastic", "verb": "query", "params": params})])


def _text(body: str) -> ModelResponse:
    return ModelResponse(parts=[TextPart(content=body)])


def _empty() -> ModelResponse:
    """A response with no actionable part. Gather's output retries are 0 (c10), so the real
    graph turns this into `UnexpectedModelBehavior` on the FIRST occurrence — a real fault
    through the real primitive, and the design's own named way for a summary turn to fail."""
    return ModelResponse(parts=[])


class GatherModel:
    """The gather side of a `FunctionModel`, replaying explicit responses.

    It records, per call, the roster the model was offered (function, output AND provider-native
    channels) and the message list it was handed. `info.function_tools` is the definitions as
    the model sees them, which is the only honest address for O3.
    """

    __name__ = "GatherModel"

    def __init__(self, responses: list[ModelResponse]):
        self._responses = responses
        self.calls = 0
        self.rosters: list[list[str]] = []
        self.native: list[list[str]] = []
        self.output_tools: list[list[str]] = []
        self.inbound: list[list] = []

    def __call__(self, messages, info) -> ModelResponse:
        self.rosters.append(sorted(t.name for t in info.function_tools))
        self.output_tools.append(sorted(t.name for t in info.output_tools))
        self.native.append(sorted(
            getattr(t, "name", str(t))
            for t in (info.model_request_parameters.native_tools or [])))
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
    """One dispatch driven at the seam: the run dir, the model, the verb recorder."""

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
    what: tuple[str, ...] = ("which hosts dev.dana reached",),
) -> _Lead:
    """Drive the REAL `_run_gather` over an agent the PRODUCTION factory built.

    The only thing this replaces is the provider: `build_gather_agent`'s own `make_model` seam
    hands back a `FunctionModel`. The tools, the capabilities, the instructions, the retry
    policy and the `override` semantics are all the shipped ones, which is what makes the
    roster read below a pin on production rather than on a fixture.
    """
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
                GatherRequest(LEAD, "elastic", "measure this lead", what),
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


def prompts(messages: list) -> list[str]:
    return [p.content for m in messages if isinstance(m, ModelRequest)
            for p in m.parts if isinstance(p, UserPromptPart) and isinstance(p.content, str)]


def flat(messages: list) -> str:
    out: list[str] = []
    for m in messages:
        for p in getattr(m, "parts", []):
            c = getattr(p, "content", None)
            if c is not None:
                out.append(c if isinstance(c, str) else str(c))
    return "\n".join(out)


class BrokenAppendStore:
    """A REAL store handle whose `append` refuses the Nth write.

    It wraps the real object and delegates everything else — the shape #826's
    `_UnstampableStore` already uses at this seam. It raises a real production exception class
    rather than inventing one, and it classifies nothing: whether a refused round ends the lead
    or the run is the contract under test.
    """

    def __init__(self, real, *, at: int):
        self._real = real
        self._at = at
        self.n = 0

    def append(self, *a, **kw):
        self.n += 1
        if self.n == self._at:
            raise session_store.StoreAppendError("the store cannot take this round")
        return self._real.append(*a, **kw)

    def __getattr__(self, name):
        return getattr(self._real, name)


class RefusesTheSalvageRound:
    """A REAL store handle that refuses exactly the SALVAGE round's own write.

    Keyed on the message's SHAPE rather than on a write count: the salvage round's request is
    the one `ModelRequest` carrying a tool return AND a user prompt in one message (M3's
    closing request, which pydantic-ai fuses), and no round of an ordinary lead has that shape.
    A counted fault would silently stop selecting the round it names the day the recorder
    commits one more or one fewer message per round.
    """

    def __init__(self, real):
        self._real = real
        self.refused = 0

    def append(self, session_id, messages, **kw):
        for m in messages:
            parts = list(getattr(m, "parts", []))
            if (any(isinstance(p, UserPromptPart) for p in parts)
                    and any(isinstance(p, ToolReturnPart) for p in parts)):
                self.refused += 1
                raise session_store.StoreAppendError("the store cannot take this round")
        return self._real.append(session_id, messages, **kw)

    def __getattr__(self, name):
        return getattr(self._real, name)


def store_arm(tmp_path: Path, wrap):
    """`(store, session_id, capabilities)` for a lead whose recorder writes to a real store.

    `wrap` builds the fault-injecting wrapper around the real handle. The recorder is wired
    through `driver._gather_extra_capabilities`, the production assembly `_build_gather` uses,
    so the history processor under the fault is the shipped one.
    """
    base = runs_base(tmp_path / "db")
    store = wrap(session_store.open_store(case_id="case-987", runs_base=base))
    session_id = store.new_session(agent_id=f"gather:{LEAD}")
    caps = driver._gather_extra_capabilities(
        store, session_id, f"gather:{LEAD}", request_limit=5)
    return store, session_id, caps


# =========================================================================================
# O3 — after the cut, the gather model can issue no query on this lead.
# =========================================================================================


def test_the_summary_turn_is_offered_no_tool_through_the_real_gather_factory(tmp_path):
    """O3, M4 — the pin the design asks for by name.

    `override(toolsets=[], tools=[], native_tools=[])` is documented for the toolsets an agent
    was built with; whether it reaches a toolset a CAPABILITY contributes is undocumented
    (c15, unprobed), and gather's factory attaches `QueryCapture` — the wrapper `query` lives
    behind — as a capability. So this is driven through `driver.build_gather_agent` with the
    real `GATHER_DEF`, and read off `AgentInfo`: the tool definitions as the MODEL is offered
    them, on EVERY call, not just the first.

    All three channels are read, because withholding two of them is the failure that looks like
    success: a provider-native tool left advertised is a query the model can still issue.

    Two positive controls on the same scenario, so the empty roster cannot be an artefact of
    the harness: the query rounds BEFORE the cut are offered the whole production roster, and a
    lead that is not cut at all keeps it on its last round too."""
    cut = run_lead(tmp_path / "cut", [_query(), _query(), _query(), _text("two logins.")])

    assert cut.model.calls == 4, \
        f"the salvage turn never happened — {cut.model.calls} model calls, not 4"
    assert cut.model.rosters[:3] == [GATHER_ROSTER] * 3, (
        "the control is broken: the query rounds were not offered the production roster, so an "
        f"empty roster on the last round proves nothing: {cut.model.rosters!r}"
    )
    assert cut.model.rosters[-1] == [], (
        "the summary turn was offered function tools — the gather model can still issue a "
        f"query after the cut: {cut.model.rosters[-1]!r}"
    )
    assert cut.model.native[-1] == [], \
        f"the summary turn was offered provider-native tools: {cut.model.native[-1]!r}"
    assert cut.model.output_tools[-1] == [], \
        f"the summary turn was offered an output tool: {cut.model.output_tools[-1]!r}"

    clean = run_lead(tmp_path / "clean", [_query(), _text("two logins.")])
    assert clean.model.rosters[-1] == GATHER_ROSTER, (
        "a lead that was NOT cut lost its query tool on its last round — the override leaked "
        "out of the salvage path onto every lead"
    )


def test_a_hallucinated_query_on_the_summary_turn_executes_nothing_and_writes_no_row(tmp_path):
    """O3's second clause and c11 — "or a queries-table row for the lead is written after the
    terminator".

    Withholding the tool is not by itself the guarantee: a model that has spent the last three
    turns calling `query` may well emit a fourth call whatever it is offered. What makes the
    door shut is the ceiling — the summary turn runs under `request_limit=1`, so a hallucinated
    call becomes a retry round the model never gets to answer. Driven for real: the model DOES
    emit the call, and the assertions are on what the backend and the table saw.

    The lead then degrades exactly as O4 says, because the run ended on the usage limit rather
    than on text — which is the honest outcome, not a second failure."""
    before = run_lead(tmp_path / "ctl", [_query(), _query(), _query(), _text("summary")])
    lead = run_lead(tmp_path / "hall", [_query(), _query(), _query(), _query()])

    assert lead.model.calls == 4, (
        f"{lead.model.calls} model calls — the hallucinated call bought the model another turn, "
        "which is one more request than the lead's ceiling reserves"
    )
    assert len(lead.rec.calls) == 2, (
        "a verb ran after the terminator — the summary turn executed the tool it hallucinated: "
        f"{lead.rec.verbs!r}"
    )
    assert [r["seq"] for r in lead.rows] == [r["seq"] for r in before.rows], (
        "the queries table gained a row after the cut; the summary turn is supposed to be "
        f"unable to write one: {lead.rows!r}"
    )
    assert len(lead.rows) == 3, "the control scenario stopped writing the lead's own three rows"

    header, tail = split(lead.out)
    assert header.startswith(f"gather for {LEAD} hit a dead end:")
    assert "A summary turn was attempted and failed (UsageLimitExceeded)" in tail, (
        "a summary turn that spent its one request on a tool call was reported as if it had "
        f"written a summary: {tail!r}"
    )


# =========================================================================================
# O1 / M3 — the history handed to the summary turn, and the answers that survive it.
# =========================================================================================


def test_the_dangling_tripping_call_is_answered_in_gathers_own_vocabulary(tmp_path):
    """M3, O1, O7 — the closing tool return.

    On the dead-end arm the captured history ends on a `ModelResponse` carrying the tripping
    `ToolCallPart`, unanswered: the guard raised instead of returning a result. pydantic-ai
    refuses a new user prompt over such a history outright (c2, executed: "Cannot provide a new
    user prompt when the message history contains unprocessed tool calls"), so THE SUMMARY TURN
    HAPPENING AT ALL is the proof that the harness answered the dangling call first. That is
    why this test drives the real graph rather than asserting on a constructed list.

    What the answer SAYS is the second half, and it is gather's own vocabulary throughout: the
    dead end's `reason`, plus the fixed `SALVAGE_CLOSED_SENTENCE`. Never main's idiom — G19 is
    the one #807 decision this change does not revise, and the closing tool return is the new
    surface that could break it."""
    lead = run_lead(tmp_path, [_query(), _query(), _query(), _text("two logins for dev.dana.")])

    assert lead.model.calls == 4, "the summary turn did not run, so nothing below is observed"
    salvage = lead.model.last_inbound
    closing = tool_returns(salvage)
    assert closing, (
        "the summary turn ran over a history with no tool return at all — either the dangling "
        "call was dropped rather than answered, or the tripping call was never in the history"
    )
    answer = str(closing[-1].content)
    assert closing[-1].tool_name == "query", \
        f"the closing return answers a tool the lead never called: {closing[-1].tool_name!r}"
    assert "repeats the one already issued at seq 0" in answer, (
        "the dangling call was answered with something other than the dead end's own reason — "
        f"the model is told it was stopped but not why: {answer!r}"
    )
    assert SALVAGE_CLOSED_SENTENCE in answer, \
        f"the closing return does not tell gather the query door is shut: {answer!r}"
    assert INCOMPLETE_IDIOM not in answer, \
        "main's disposition vocabulary was handed to the gather model in the closing return"

    assert len(prompts(salvage)) >= 2, (
        "the summary turn carries only the lead's original dispatch prompt — nothing told the "
        f"model to write the summary now: {prompts(salvage)!r}"
    )
    assert INCOMPLETE_IDIOM not in flat(salvage), \
        "main's idiom reached the gather model somewhere in the replayed history"
    assert frame_body(lead.out).endswith("two logins for dev.dana."), \
        "the summary the model wrote from its own answers did not reach main"


def test_every_dangling_sibling_call_is_answered_not_just_the_first(tmp_path):
    """M3's plural, and the shape that actually occurs: `gather_dispatch` drives `query_tool`
    CONCURRENTLY, so a turn issuing two identical siblings past the threshold leaves TWO
    unanswered `ToolCallPart`s in one `ModelResponse`.

    c2 does not say "the last tool call"; it says unprocessed tool calls, plural. An
    implementation that answers only the part it took the exception from leaves the other
    dangling and the summary turn cannot run at all — so this is driven through the real
    concurrency rather than asserted on a hand-built list, and the pass condition is again that
    the turn produced text."""
    two_at_once = ModelResponse(parts=[
        ToolCallPart(tool_name="query",
                     args={"system": "elastic", "verb": "query", "params": dict(PARAMS)}),
        ToolCallPart(tool_name="query",
                     args={"system": "elastic", "verb": "query", "params": dict(PARAMS)}),
    ])
    lead = run_lead(tmp_path, [_query(), _query(), two_at_once, _text("what I had: two logins.")])

    assert lead.model.calls == 4, (
        "the summary turn never ran — the likeliest cause is a second dangling sibling the "
        "closing request left unanswered, which pydantic-ai refuses a prompt over"
    )
    salvage = lead.model.last_inbound
    last_response = next(m for m in reversed(salvage) if isinstance(m, ModelResponse))
    dangling = [p for p in last_response.parts if isinstance(p, ToolCallPart)]
    assert len(dangling) == 2, \
        f"the scenario did not produce two concurrent calls: {dangling!r}"
    answered = {p.tool_call_id for p in tool_returns(salvage)}
    assert {p.tool_call_id for p in dangling} <= answered, (
        "a dangling sibling call was left unanswered; the summary turn is only reachable "
        "because every one of them was closed"
    )
    assert frame_body(lead.out).endswith("what I had: two logins.")


def test_a_lead_cut_before_its_first_response_still_gets_its_summary_turn(tmp_path):
    """M6's shape clause (the design's finding 14): the captured list can be a SINGLE
    `ModelRequest`.

    The store arm can fire on the very first recorder run, before the model has ever answered —
    there is no `ModelResponse` to inspect and no tool call to close. An implementation that
    reads `captured[-1].parts` for tool calls without checking the message TYPE, or that
    indexes `captured[-2]`, breaks here and nowhere else.

    The design says the summary turn runs on every degrading arm regardless of what the lead
    executed, including nothing: "a model refused six times may still say usefully what it
    could not ask". So the pass condition is a real summary, not a graceful failure."""
    _store, session_id, caps = store_arm(
        tmp_path, lambda real: BrokenAppendStore(real, at=1))
    lead = run_lead(tmp_path / "run", [_text("I was stopped before I could ask anything.")],
                    extra=caps, session_id=session_id)

    assert lead.model.calls == 1, (
        f"{lead.model.calls} model calls — the query phase was supposed to be cut before its "
        "first request, leaving the summary turn as the only one"
    )
    header, summary = split(lead.out)
    assert header == HEADER_STORE.format(lead=LEAD, detail="the store cannot take this round")
    assert summary == "I was stopped before I could ask anything."


# =========================================================================================
# O1 / O5 — every degrading arm, at a real ceiling, through the real graph.
# =========================================================================================


def test_the_request_limit_arm_summarizes_inside_the_ceiling_it_was_given(tmp_path):
    """O1 + O5 + M2, driven where they meet: the arm that cannot be salvaged by re-running
    anything, because the lead is out of requests.

    The whole of M2 exists for this arm. The query phase is capped at `ceiling - 1`, the cut
    happens one round earlier than it used to, and the reserved request buys the summary. So
    the model call count equals the ceiling EXACTLY — not one more, which is what a naive
    "just run one more turn" would spend, and not one less.

    Two ceilings, because a single one cannot tell `ceiling - 1` from a hardcoded number."""
    for ceiling in (3, 5):
        lead = run_lead(tmp_path / f"c{ceiling}",
                        [_query(i) for i in range(10)][:ceiling - 1] + [_text("partial: 2 hosts.")],
                        ceiling=ceiling)
        assert lead.model.calls == ceiling, (
            f"a lead ceilinged at {ceiling} made {lead.model.calls} model requests — #808 "
            "d21/F6's number is what stays fixed while its composition changes"
        )
        assert len(lead.rec.calls) == ceiling - 1, (
            f"{len(lead.rec.calls)} backend calls at ceiling {ceiling} — the query phase did "
            "not give up its round to the summary turn"
        )
        header, summary = split(lead.out)
        assert header.startswith(f"gather for {LEAD} hit its request limit ("), \
            f"the request-limit arm did not fire at all: {header!r}"
        assert header.endswith(
            f"before finishing; any queries it ran are in the queries table. {INCOMPLETE_IDIOM}")
        assert summary == "partial: 2 hosts."


def test_the_retry_exhausted_arm_summarizes_over_the_history_it_had(tmp_path):
    """O1 on the arm #826 named as the SECOND silent terminator. `UnexpectedModelBehavior` is
    what the framework raises once a response carries nothing actionable and the output retry
    budget — 0, for gather (c10) — is gone. The lead's earlier answers are still in the
    captured history, and they are what the summary turn writes from.

    Driven with a real empty response rather than a raised stub: this is the same primitive the
    failed-summary-turn test below turns on, and pinning it here means the two cannot disagree
    about what "a response the graph refuses" is."""
    lead = run_lead(tmp_path, [_query(1), _query(2), _empty(),
                               _text("2 hosts before I lost the thread.")])

    assert lead.model.calls == 4
    header, summary = split(lead.out)
    assert header == HEADER_RETRY_EXHAUSTED.format(
        lead=LEAD, detail="Exceeded maximum output retries (0)")
    assert summary == "2 hosts before I lost the thread."
    assert len(lead.rec.calls) == 2, "the two answers the summary is written from never happened"


def test_the_store_arm_summarizes_from_the_history_the_store_could_not_record(tmp_path):
    """O1 on the fourth arm, and the one where the distinction matters most.

    The gather recorder is OBSERVATIONAL: `_make_gather_recorder` returns the live list
    unchanged, so gather never sends a store-sourced history and a recording failure cannot put
    an unrecorded list on the wire. The consequence is that a lead cut by the store still has
    every answer it retrieved sitting in its own context — the answers were never the store's
    to lose — and throwing them away was pure loss.

    The lead answered one query before the store refused; that answer is what the summary is
    written from."""
    _store, session_id, caps = store_arm(
        tmp_path, lambda real: BrokenAppendStore(real, at=2))
    lead = run_lead(tmp_path / "run", [_query(1), _text("one host: db-1.")],
                    extra=caps, session_id=session_id)

    assert lead.model.calls == 2, f"{lead.model.calls} model calls, not one query and one summary"
    assert len(lead.rec.calls) == 1, "the lead retrieved nothing, so O1's premise is absent"
    header, summary = split(lead.out)
    assert header == HEADER_STORE.format(lead=LEAD, detail="the store cannot take this round")
    assert summary == "one host: db-1."


def test_the_dead_end_arm_hands_main_what_the_lead_actually_retrieved(tmp_path):
    """O1 on the reporter's own arm, stated as the defect it closes: a lead that answered two
    queries and then hit the repeat guard used to reach main as the notice alone, and main
    wrote "No container infrastructure context retrieved" — accurately, from its seat, because
    none of the answers had reached it.

    The summary the model writes from those answers is now the body under the notice. The
    assertion is on a fact that exists ONLY in the query payloads, so it cannot have come from
    the header, the queries table or the lead's own goal."""
    lead = run_lead(tmp_path, [_query(), _query(), _query(),
                               _text("dev.dana authenticated twice; no container workload seen.")])

    # The reason and the escape are SPENT from their shipped producers rather than
    # re-spelled: a copy here would keep this arm green against a wording that had moved, and
    # neither string is #987's to change. What #987 owns is the frame around them, and that is
    # `HEADER_DEAD_END` — transcribed, because it is the thing under test.
    header, summary = split(lead.out)
    assert header == HEADER_DEAD_END.format(
        lead=LEAD,
        reason=rq.dead_end_reason("elastic", "query", rq.RepeatTrip(0, rq.REPEAT_THRESHOLD), 2),
        escape=rq.REPEAT_ESCAPE,
    ), f"the dead-end header is no longer today's notice, to the byte: {header!r}"
    assert summary == "dev.dana authenticated twice; no container workload seen."
    assert lead.persisted == lead.out, \
        "the persisted account and the string main received are not the same object"


# =========================================================================================
# O4 — a failed summary turn never worsens the run.
# =========================================================================================


def test_a_summary_turn_the_graph_refuses_degrades_to_the_failure_sentence(tmp_path):
    """O4 through the real fault the design names: gather's build sets output retries to 0
    (`_build.py:158`, c10), so a summary response the graph finds non-actionable fails the turn
    on its first occurrence, as `UnexpectedModelBehavior`, inside the real graph.

    Three things must survive it: nothing escapes `_run_gather` (an exception here unwinds
    through MAIN's own tool call, mid-lead — the run-ending shape #878 catalogued), main is
    TOLD rather than handed the bare notice, and the file is still written. The third is why
    the file is read back and compared: `_persist_gather_summary` runs after the composition,
    and a `return` taken inside the failure branch skips it silently.

    The lead's queries are asserted to have happened, so this is a lead with real answers that
    could not be summarized — not a vacuous one."""
    lead = run_lead(tmp_path, [_query(), _query(), _query(), _empty()])

    assert lead.model.calls == 4, "the summary turn never ran, so there was nothing to fail"
    assert len(lead.rec.calls) == 2, "the lead retrieved nothing, so O1's premise is absent"
    header, tail = split(lead.out)
    assert header.startswith(f"gather for {LEAD} hit a dead end:"), \
        "the failed summary turn displaced the ORIGINAL cut's notice"
    assert tail == ("A summary turn was attempted and failed (UnexpectedModelBehavior); "
                    "no summary is available."), \
        f"a failed summary turn did not say so in main's context: {tail!r}"
    assert lead.persisted == lead.out, \
        "a lead whose summary turn failed left no persisted account of the lead at all"


def test_a_store_that_refuses_the_salvage_round_loses_the_summary_but_not_the_run(tmp_path):
    """O4's second real fault, and the one this design makes newly reachable: the summary turn's
    OWN history recorder writes through the same store every other round does. A store that
    refuses that write raises `StoreError` out of the salvage run — a second cut, inside the
    handler for the first.

    Driven on the DEAD-END arm, so the original cut and the salvage failure are different
    causes and the terminator has something to get wrong. Two implementations fail here and
    both look reasonable: re-raising the second `StoreError` (a lead-level fault ends the run),
    and re-classifying the terminator to `store` (every reader comparing leads is told the
    repeat guard never fired)."""
    store, session_id, caps = store_arm(tmp_path, RefusesTheSalvageRound)
    stamps: list[tuple[str, str]] = []
    lead = run_lead(tmp_path / "run",
                    [_query(), _query(), _query(), _text("two logins for dev.dana.")],
                    extra=caps, session_id=session_id, stamps=stamps)

    assert store.refused >= 1, (
        "the store never saw the salvage round's own fused request, so no fault was injected "
        "and this test asserts nothing"
    )
    header, tail = split(lead.out)
    assert header.startswith(f"gather for {LEAD} hit a dead end:"), \
        "the salvage turn's own failure displaced the ORIGINAL cut's notice"
    assert "A summary turn was attempted and failed (" in tail, \
        f"a summary turn that could not be recorded was reported as a summary: {tail!r}"
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)], (
        "the terminator names the summary turn's own fate rather than the cut that caused it"
    )
    assert lead.persisted == lead.out


# =========================================================================================
# The whole loop — what MAIN receives, what MAIN may not read, what the store records.
# =========================================================================================


class Rosters(ReplayFn):
    """`ReplayFn` plus the per-call tool roster and the per-call inbound history.

    The harness's own `ToolRoster` captures the FIRST call's roster, which is the one call this
    suite does not care about: the salvage turn is the last. Subclassed here rather than
    widened there because the two answer different questions and #807's suite reads the first.

    A turn whose text is `_EMPTY_MARK` is replayed as a response with NO parts — the real
    non-actionable response of c10, expressed inside the harness's own `Turn` vocabulary so a
    scenario stays a few lines of `Turn(...)`.
    """

    __name__ = "Rosters"

    _EMPTY_MARK = "__no_actionable_part__"

    def __init__(self, turns: list[Turn]):
        super().__init__(turns)
        self.rosters: list[list[str]] = []
        self.inbound: list[list] = []

    def __call__(self, messages, info) -> ModelResponse:
        self.rosters.append(sorted(t.name for t in info.function_tools))
        self.inbound.append(list(messages))
        response = super().__call__(messages, info)
        if any(getattr(p, "content", None) == self._EMPTY_MARK for p in response.parts):
            return ModelResponse(parts=[])
        return response


#: The scripted turn that becomes a response the graph refuses (c10).
EMPTY_TURN = Turn(text=Rosters._EMPTY_MARK)


def _dispatch(lead: str = LEAD) -> tuple[str, dict]:
    return ("gather", {
        "lead_id": lead, "system": "elastic", "goal": "measure this lead",
        "what_to_summarize": ["auth events"],
    })


def _q(params: dict) -> Turn:
    return Turn(tool_calls=[("query", {"system": "elastic", "verb": "query", "params": params})])


def _drive(root: Path, gather_turns: list[Turn], *, run_id: str, stores: list | None = None,
           tmp_path: Path | None = None):
    """The whole loop: MAIN dispatches one lead, the nested gather agent replays `gather_turns`.
    Everything between the two fakes is production code."""
    run_dir = materialize(root, GOLDEN_AB3)
    rec = VerbRecorder()
    main = ReplayFn([Turn(tool_calls=[_dispatch()]), Turn(text="Investigation complete.")])
    gather = Rosters(gather_turns)
    seams: dict = {}
    if stores is not None:
        seams["store_factory"] = store_factory(tmp_path, sink=stores)
    drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=elastic_ok(rec), **seams)
    return run_dir, main, gather, rec


#: A gather script that trips the repeat guard on its third call and then summarizes.
_TRIP_AND_SUMMARIZE = [
    _q(dict(PARAMS)), _q(dict(PARAMS)), _q(dict(PARAMS)),
    Turn(text="dev.dana logged in from 10.0.0.9 twice; no container workload was reachable."),
]


def test_main_receives_the_answers_it_may_not_read_anywhere_else(tmp_path):
    """O1 + O2 + O6, end to end, against the policy that makes the summary the ONLY channel.

    P1 of the grounding, re-asserted here as the control rather than cited: main's read grant
    admits `gather_summaries/` and the queries table and DENIES `gather_raw/` by name. So a
    fact that exists only in a query payload reaches main through the summary or not at all —
    which is what makes "the answers reached main" a claim about this change rather than about
    the filesystem.

    The vocabulary clause rides here too: the text opens with the per-arm notice and carries
    the idiom, so #807's G19 screen and #826's `truncated_by` readers still fire, and the
    return is ONE `untrusted` frame around the whole of it."""
    run_dir, main, gather, _rec = _drive(tmp_path, _TRIP_AND_SUMMARIZE, run_id="d987-main")

    summary = (run_dir / "gather_summaries" / f"{LEAD}.md").read_text(encoding="utf-8")
    assert summary in main.seen[-1], \
        "the persisted account and the string main received are not the same object"
    header, body = split(summary)
    assert header.startswith(f"gather for {LEAD} hit a dead end:")
    assert INCOMPLETE_IDIOM in header, "main lost the word it screens cut-short leads on"
    assert body == "dev.dana logged in from 10.0.0.9 twice; no container workload was reachable."
    assert "10.0.0.9" in main.seen[-1], (
        "the lead's own retrieved detail did not reach main — this is the defect: the answers "
        "existed and died with the sub-agent's context"
    )

    deps = bind(MAIN_DEF, run_dir, defender_dir=DEFENDER)
    raw = permission.decide_read(
        RunPaths(run_dir).gather_raw / LEAD / "0.json",
        run_dir=run_dir, defender_dir=DEFENDER, policy=deps.policy)
    assert not raw.allow, (
        "main may read gather_raw/ after all — then the summary was never the only channel and "
        "the assertion above is not about this change"
    )
    allowed = permission.decide_read(
        run_dir / "gather_summaries" / f"{LEAD}.md",
        run_dir=run_dir, defender_dir=DEFENDER, policy=deps.policy)
    assert allowed.allow, "the control is broken: main cannot read the summary either"


def test_the_gather_model_never_sees_mains_idiom_but_main_always_does(tmp_path):
    """O7, end to end, with both controls on one scenario.

    #807 G19 is pinned by `test_tripping_call_carries_no_repeat_note`'s
    `INCOMPLETE_IDIOM not in seen`, and that assertion was true partly because the gather model
    was never asked anything after the cut. It is asked now — over its whole history, plus a
    closing tool return, plus a prompt — so the same words have three new ways to reach it and
    the pin is re-driven against every message it saw, not just the last.

    The positive control is the other direction on the same run: the idiom DOES reach main. A
    "not in" over a phrase the codebase had quietly reworded would otherwise pass everywhere."""
    _run_dir, main, gather, _rec = _drive(tmp_path, _TRIP_AND_SUMMARIZE, run_id="d987-idiom")

    assert gather.calls == 4, "the salvage turn did not run, so O7's new surfaces are untested"
    for i, seen in enumerate(gather.seen):
        assert INCOMPLETE_IDIOM not in seen, \
            f"main's disposition vocabulary reached the gather model on call {i + 1}"
        assert "Treat this lead as incomplete" not in seen
    assert flat(gather.inbound[-1]), "the salvage turn was handed an empty history"
    assert INCOMPLETE_IDIOM in main.seen[-1], (
        "the control is vacuous: main never saw the idiom either, so the negatives above are "
        "about a phrase nothing emits"
    )


def test_the_summary_round_is_recorded_once_under_the_leads_own_session(tmp_path):
    """O5's bookkeeping half, on a real store.

    Three things, and each has its own way of going wrong: the summary request must be
    RECORDED (a run over a replayed history that the recorder skips leaves main's account
    unbacked by any session row), recorded ONCE (the salvage run is handed the whole history
    again, so a recorder that ingested from zero would re-commit every round the lead already
    wrote — c5), and recorded under the SAME `agent_id` (a second session would make the lead
    look like two dispatches to every reader joining `session` rows, and `claim_lead` refuses
    a second dispatch of one lead id).

    The terminator is asserted beside it because the stamp and the rows are written on opposite
    sides of the salvage turn, and a test that pins only one of them passes either way."""
    stores: list = []
    _run_dir, _main, gather, _rec = _drive(
        tmp_path / "run", _TRIP_AND_SUMMARIZE, run_id="d987-store",
        stores=stores, tmp_path=tmp_path)
    store = stores[-1]

    assert gather.calls == 4
    sessions = dict(sql(store, "SELECT agent_id, truncated_by FROM session"))
    assert sessions[f"gather:{LEAD}"] == session_store.TRUNCATED_BY_DEAD_END, \
        "the lead's session names the summary turn's fate, or none at all"
    assert [a for a in sorted(sessions) if LEAD in a] == [f"gather:{LEAD}"], (
        f"the summary turn opened a session of its own for this lead: {sorted(sessions)!r}"
    )

    kinds = [k for (k,) in sql(store, """
        SELECT m.kind FROM message m JOIN session s ON s.session_id = m.session_id
        WHERE s.agent_id = ? ORDER BY m.rowid
    """, (f"gather:{LEAD}",))]
    assert kinds == ["request", "response"] * 3 + ["request"], (
        "the lead's session does not hold exactly its three query rounds plus one summary "
        f"request: {kinds}. Three rounds ran, so three request/response pairs are stored (the "
        "tripping response is committed by the salvage run's own ingest); the summary request "
        "is the one row after them, and its response is not flushed — the same parity a CLEAN "
        "lead's session ends on. A longer list is the replayed history being re-committed."
    )


def test_a_failed_summary_turn_leaves_the_run_running_and_the_lead_reported(tmp_path):
    """O4 end to end, which is the clause the seam cannot reach: "the run continues".

    `_run_gather` is called from inside MAIN's own tool execution, so an exception out of the
    salvage path does not merely lose a summary — it unwinds MAIN's turn and ends the
    investigation with no disposition. Driven with the same real non-actionable response, and
    asserted on MAIN getting its next turn and on the run reaching its own end."""
    turns = [_q(dict(PARAMS)), _q(dict(PARAMS)), _q(dict(PARAMS)), EMPTY_TURN]
    run_dir, main, gather, _rec = _drive(tmp_path, turns, run_id="d987-fail")

    assert gather.calls == 4
    assert main.calls == 2, \
        "main never took its turn after the failed summary — the run unwound mid-lead"
    summary = (run_dir / "gather_summaries" / f"{LEAD}.md").read_text(encoding="utf-8")
    header, tail = split(summary)
    assert header.startswith(f"gather for {LEAD} hit a dead end:")
    assert tail == ("A summary turn was attempted and failed (UnexpectedModelBehavior); "
                    "no summary is available.")
    assert summary in main.seen[-1]


def test_the_salvage_request_limit_is_the_one_reserved_request(tmp_path):
    """The constant, bound to the arithmetic it serves rather than left free: the design
    reserves exactly one request, and every ceiling assertion in these two modules is
    `(request_limit - 1) + SALVAGE_REQUEST_LIMIT == request_limit`. A constant of 2 would make
    `test_the_request_limit_arm_summarizes_inside_the_ceiling_it_was_given` fail, which is the
    point — this is the address where the number is stated once."""
    assert SALVAGE_REQUEST_LIMIT == 1
    for text in (SALVAGE_PROMPT, SALVAGE_CLOSED_SENTENCE):
        assert isinstance(text, str)
        assert text.strip(), "a salvage constant is bound to nothing"
    assert re.search(r"\bno further quer", SALVAGE_CLOSED_SENTENCE, re.I), (
        "the closing tool return does not tell gather the query door is shut — it is the only "
        "thing the model is told about why its call came back without an answer"
    )
