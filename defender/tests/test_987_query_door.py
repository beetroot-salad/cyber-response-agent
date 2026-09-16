"""#987 — the STOPPED lead, at `_run_gather`'s own seam and at the stop record's.

THE DEFECT. A gather lead the harness stopped — a guard's dead end, or its request ceiling —
was cut by an exception, and main received a stand-in notice in place of everything the lead
had retrieved (see `tests/e2e/test_987_stopped_lead.py` for the whole story).

THE CHANGE. The stop is a TOOL RESULT, not an exception, and it is WRITTEN DOWN where it
happens. A guard's stop closes the lead's query door and is told to the model in the tool's
own answer; the ceiling is a ROUND, and `RequestCeiling` tells the model on the last request
itself, withholds the tools on it, and marks the ceiling on the same record; the model's next
turn is the summary; `_run_gather` composes main's message from that record and the run's own
outcome, and never infers a stop from a request count. This module drives `_run_gather` with
FAKE gather agents through the `gather_factory` seam the entry point already declares — the
notice bytes, the terminator, the composition, the arm census — and the record's and the
ceiling hooks' own semantics with no agent at all. Everything that needs the REAL query tool
and the real graph is next door.

No `monkeypatch.setattr`: every fake enters through `gather_factory`.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded  # noqa: E402
from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)

# `driver` FIRST: entering the `tools_gather` <-> `tools` cycle at `tools_gather` raises on a
# partially initialized module.
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.hooks.budget_enforcer import BudgetKill  # noqa: E402
from defender.runtime import (  # noqa: E402
    circuit_breaker,
    query_tool,
    request_ceiling,
    session_store,
    tools_gather,
)
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.request_ceiling import FINAL_REQUEST, RequestCeiling  # noqa: E402
from defender.runtime.tools import DeadEnd, LeadStop  # noqa: E402
from defender.runtime.tools_gather import (  # noqa: E402
    NO_SUMMARY_FAILED,
    GatherRequest,
)
from defender.tests.e2e._replay_harness import DEFENDER, GOLDEN_AB3, materialize  # noqa: E402

LEAD = "l-001"

#: The tail sentence #807's G19/C5 pinned as MAIN's own vocabulary — the one sentence gather
#: must never be shown, and the one main must always be.
INCOMPLETE_IDIOM = "Treat this lead as incomplete and reason from what was captured."

# ---------------------------------------------------------------------------------------
# THE FOUR NOTICES, AS LITERALS THIS FILE OWNS. Re-deriving them from the implementation
# would make every header assertion a tautology. The dead-end and the two fault notices are
# the arms' text at the base commit; the request-limit one names the lead's OWN ceiling where
# it used to quote the framework's exception (which names `request_limit - 1`'s composition,
# not the ceiling), and says the lead was TOLD TO STOP rather than that it stopped "before
# finishing" — a lead that wrote its summary on the marked request finished.
# ---------------------------------------------------------------------------------------
HEADER_REQUEST_LIMIT = (
    "gather for {lead} reached its request limit ({limit} requests) and was told to stop; "
    "any queries it ran are in the queries table. " + INCOMPLETE_IDIOM
)
HEADER_DEAD_END = (
    "gather for {lead} hit a dead end: {reason} {escape} " + INCOMPLETE_IDIOM
)
HEADER_RETRY_EXHAUSTED = (
    "gather for {lead} ended abnormally ({detail}); any queries it ran are in "
    "the queries table. " + INCOMPLETE_IDIOM
)
HEADER_STORE = (
    "gather for {lead} could not be recorded ({detail}); any queries it ran are "
    "in the queries table. " + INCOMPLETE_IDIOM
)

DEAD_END = DeadEnd(reason="the request (elastic query) repeats seq 0.", escape="Move on.")

_FRAME = re.compile(r"\A<run-([0-9a-f]+)-untrusted>\n(?P<body>.*)\n</run-\1-untrusted>\Z",
                    re.DOTALL)


def frame_body(returned: str) -> str:
    """The body inside the ONE `untrusted` frame `_run_gather` returns — a header emitted
    outside the frame, or a summary given a frame of its own, fails here."""
    m = _FRAME.match(returned)
    assert m, f"the return is not one whole `untrusted` frame: {returned!r}"
    body = m.group("body")
    assert "-untrusted>" not in body, \
        "the header and the summary came back in two frames — main's parser sees two documents"
    return body


def split(returned: str) -> tuple[str, str]:
    """`(header, summary)`: the arm's notice, a blank line, the lead's own text."""
    body = frame_body(returned)
    head, sep, tail = body.partition("\n\n")
    assert sep, f"the return carries no header/summary split at all: {body!r}"
    return head, tail


class Agent:
    """A gather agent that records its one `.run`, does `to_stop` to the deps' stop record
    (the query tool's or the ceiling hook's part, played here), and either returns a result
    carrying `output` and NOTHING ELSE — the shape `tests/test_wrap_fresh_875.py`'s doubles
    have always returned, so a `_run_gather` that reads anything but `.output` off the result
    fails here first — or raises `exc`."""

    def __init__(self, output: str = "measured: two logins from dev.dana.",
                 *, exc: BaseException | None = None, to_stop=None):
        self._output, self._exc, self._to_stop = output, exc, to_stop
        self.runs: list[dict] = []
        self.deps: list = []

    async def run(self, prompt=None, **kwargs):
        self.runs.append({"prompt": prompt, **kwargs})
        self.deps.append(kwargs["deps"])
        if self._to_stop is not None:
            self._to_stop(kwargs["deps"].stop)
        if self._exc is not None:
            raise self._exc
        return SimpleNamespace(output=self._output)


def dispatch(root: Path, agent, *, ceiling: int = 40, stamps: list | None = None,
             handed: list | None = None) -> str:
    run_dir = materialize(root, GOLDEN_AB3)
    deps = bind(MAIN_DEF, run_dir, defender_dir=DEFENDER)

    def factory(agent_id: str, system: str, request_limit: int):
        if handed is not None:
            handed.append(request_limit)
        return agent

    return asyncio.run(tools_gather._run_gather(
        deps, factory, ceiling, GatherRequest(LEAD, "elastic", "measure this lead", ("auth",)),
        GATHER_DEF.verb_grant,
        (lambda agent_id, reason: stamps.append((agent_id, reason))) if stamps is not None
        else None,
        catalog=None,
    ))


def dead_end(stop: LeadStop) -> None:
    stop.close_door(DEAD_END)


def ceiling(stop: LeadStop) -> None:
    stop.mark_ceiling(8)


def both(stop: LeadStop) -> None:
    dead_end(stop)
    ceiling(stop)


# ----------------------------------------------------------------------------------------
# The stop record itself.
# ----------------------------------------------------------------------------------------


def test_the_door_closes_once_on_a_dead_end_and_the_ceiling_marks_once():
    """Two siblings tripping in one round keep the FIRST's reason: the notice main reads names
    the request that actually stopped the lead. The ceiling is a separate arm of the same
    record — the door (the query tool's question) is closed by a dead end alone."""
    stop = LeadStop()
    assert (stop.dead_end, stop.ceiling, stop.door_closed) == (None, None, False)
    stop.close_door(DEAD_END)
    assert (stop.dead_end, stop.ceiling, stop.door_closed) == (DEAD_END, None, True)
    stop.close_door(DeadEnd(reason="later", escape="x"))
    assert stop.dead_end == DEAD_END, "a later close overwrote the first"

    marked = LeadStop()
    marked.mark_ceiling(8)
    assert (marked.dead_end, marked.ceiling, marked.door_closed) == (None, 8, False), \
        "the ceiling closed the query door — the door is the guard's"
    marked.mark_ceiling(40)
    assert marked.ceiling == 8


def test_the_dead_end_is_held_as_strings_not_as_the_exception():
    """`DeadEnd` is frozen and carries the two strings main is shown; the `GatherDeadEnd`
    that carried them — with its traceback pinning the tripping call's frames — is not what
    the record keeps for the rest of the run."""
    with pytest.raises(AttributeError):
        DEAD_END.reason = "changed"  # type: ignore[misc]
    assert not hasattr(DEAD_END, "__traceback__")


def test_a_bound_gather_deps_carries_no_stop_record(tmp_path):
    """Outside a dispatch nobody would read a record, so there is none: a guard's dead end on
    such deps unwinds as the exception it always was. `_run_gather` is the one place that
    makes one. The ceiling is not a deps field at all — it is the run's `UsageLimits`."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    deps = bind(GATHER_DEF, run_dir, defender_dir=DEFENDER)
    assert deps.stop is None
    assert not hasattr(deps, "request_limit")


# ----------------------------------------------------------------------------------------
# The ceiling hooks — one number, read off the run context, one predicate for both.
# ----------------------------------------------------------------------------------------


def _ctx(requests: int, request_limit: int | None = 8, stop: LeadStop | None = None,
         ) -> SimpleNamespace:
    return SimpleNamespace(
        usage=SimpleNamespace(requests=requests),
        usage_limits=SimpleNamespace(request_limit=request_limit) if request_limit is not None
        else None,
        deps=SimpleNamespace(stop=stop),
    )


def _request_context(settings: dict | None = None) -> SimpleNamespace:
    req = ModelRequest(parts=[
        ToolReturnPart(tool_name="query", content="exit=0", tool_call_id="c1")])
    return SimpleNamespace(messages=[req], model_settings=settings)


def _marked(requests: int, request_limit: int | None = 8) -> SimpleNamespace:
    """The request context after the hook saw it at `requests`."""
    rc = _request_context()
    asyncio.run(RequestCeiling().before_model_request(_ctx(requests, request_limit), rc))
    return rc


def test_the_final_request_alone_is_marked_and_after_the_rounds_tool_results():
    """`requests` reads N-1 while request N is prepared, so the request prepared at
    `ceiling - 1` is the last the ceiling allows. One sentence, as a USER part, after the
    round's tool returns — the order the framework itself canonicalizes a request to — and
    nothing on any other request."""
    assert [len(_marked(n).messages[-1].parts) for n in (5, 6, 7, 8)] == [1, 1, 2, 1]
    parts = _marked(7).messages[-1].parts
    assert isinstance(parts[0], ToolReturnPart)
    assert isinstance(parts[1], UserPromptPart)
    assert parts[1].content == FINAL_REQUEST
    assert len(_marked(0, request_limit=1).messages[-1].parts) == 2, \
        "a ceiling of one marks the very first request"
    assert len(_marked(7, request_limit=None).messages[-1].parts) == 1, \
        "a run with no ceiling was marked"


def test_the_final_request_goes_out_with_tools_defined_but_none_callable():
    """The tools stay on the wire (a history with tool blocks must define tools) and the
    request says no tool may be chosen: `tool_choice: none`, merged over whatever settings
    the request already carried, and on no other request."""
    rc = _marked(7)
    assert rc.model_settings == {"tool_choice": "none"}
    rc = _request_context({"temperature": 0.0})
    asyncio.run(RequestCeiling().before_model_request(_ctx(7), rc))
    assert rc.model_settings == {"temperature": 0.0, "tool_choice": "none"}
    assert _marked(6).model_settings is None, "an earlier request had its tools withheld"


def test_marking_the_final_request_records_the_ceiling_on_the_stop():
    """The stop is WRITTEN where it happens: the hook that told the model marks the record
    with the run's own ceiling — the number off `ctx.usage_limits`, not a deps copy — and a
    context with no record (an agent bound outside a dispatch) is still marked, just not
    recorded."""
    stop = LeadStop()
    asyncio.run(RequestCeiling().before_model_request(_ctx(6, stop=stop), _request_context()))
    assert stop.ceiling is None, "a request before the final one was recorded as the ceiling"
    asyncio.run(RequestCeiling().before_model_request(_ctx(7, stop=stop), _request_context()))
    assert stop.ceiling == 8
    rc = _marked(7)
    assert len(rc.messages[-1].parts) == 2


def test_the_hook_leaves_a_history_that_does_not_end_on_a_request_to_the_framework():
    """The framework raises its own `UserError` for a processed history that does not end on
    a `ModelRequest`; the hook does not pre-empt it by appending a user part to a response
    (which also has `.parts`), under `-O` or otherwise."""
    resp = ModelResponse(parts=[TextPart(content="x")])
    rc = SimpleNamespace(messages=[resp], model_settings=None)
    asyncio.run(RequestCeiling().before_model_request(_ctx(7), rc))
    assert rc.messages[-1].parts == [TextPart(content="x")]


def _after(requests: int, response: ModelResponse, request_limit: int | None = 8) -> ModelResponse:
    return asyncio.run(RequestCeiling().after_model_request(
        _ctx(requests, request_limit), request_context=_request_context(), response=response,
    ))


def test_tool_calls_on_the_final_response_are_dropped_and_the_text_kept():
    """`requests` reads N once request N's response is in hand, so the final response is
    seen at `ceiling`. On it every function tool call is dropped — a provider that ignored
    `tool_choice` — and the text and thinking the model wrote stay, in order, with the
    response's own metadata; a response with no calls comes back untouched, the same
    object."""
    call = ToolCallPart(tool_name="query", args={"system": "elastic"}, tool_call_id="c9")
    both = ModelResponse(parts=[ThinkingPart(content="hm"), TextPart(content="SUMMARY"), call],
                         model_name="m")
    out = _after(8, both)
    assert out.parts == [ThinkingPart(content="hm"), TextPart(content="SUMMARY")]
    assert out.model_name == "m"
    only_calls = ModelResponse(parts=[call])
    assert _after(8, only_calls).parts == [], "a calls-only final response kept its calls"
    text = ModelResponse(parts=[TextPart(content="SUMMARY")])
    assert _after(8, text) is text


def test_responses_before_the_final_one_and_on_an_unbounded_run_keep_their_calls():
    """The response to the second-to-last request — the one whose calls are the last to RUN
    — keeps them: the count reads `ceiling - 1` there, which is the number the marker sees
    while preparing the final request, and the two hooks must not read one count as one
    request."""
    call = ToolCallPart(tool_name="query", args={}, tool_call_id="c9")
    resp = ModelResponse(parts=[TextPart(content="x"), call])
    assert _after(7, resp) is resp, "the last permitted round's tool calls were dropped"
    assert _after(8, resp, request_limit=None) is resp, "a run with no ceiling lost its calls"


def test_the_request_count_and_the_ceiling_read_off_a_bare_context():
    assert request_ceiling.requests_so_far(SimpleNamespace()) == 0
    assert request_ceiling.requests_so_far(SimpleNamespace(usage=None)) == 0
    assert request_ceiling.requests_so_far(SimpleNamespace(usage=SimpleNamespace(requests=3))) == 3
    assert request_ceiling.request_limit(SimpleNamespace()) is None
    assert request_ceiling.request_limit(_ctx(0, request_limit=None)) is None
    assert request_ceiling.request_limit(_ctx(0, request_limit=8)) == 8
    bare = SimpleNamespace(deps=SimpleNamespace())
    assert not request_ceiling.is_final_request(bare, answered=False)
    assert not request_ceiling.is_final_request(bare, answered=True)
    assert request_ceiling.is_final_request(_ctx(7), answered=False)
    assert request_ceiling.is_final_request(_ctx(8), answered=True)
    assert not request_ceiling.is_final_request(_ctx(8), answered=False)
    assert not request_ceiling.is_final_request(_ctx(7), answered=True)


# ----------------------------------------------------------------------------------------
# `_run_gather` — one run, one ceiling, and the record read afterwards.
# ----------------------------------------------------------------------------------------


def test_the_factory_and_the_usage_limit_are_handed_one_number(tmp_path):
    """#880 F-19 and #808 d21/F6 in one assertion: the recorder the factory builds and the
    `UsageLimits` the run enforces (which is what the ceiling hooks read) are the SAME
    ceiling — not the ceiling and a derived neighbour. Driven at two ceilings so a constant
    cannot pass. The deps carry a fresh, open stop record: `_run_gather` is where they are
    made — and no ceiling of their own."""
    for i, ceiling_ in enumerate((40, 8)):
        handed: list[int] = []
        agent = Agent()
        dispatch(tmp_path / f"c{i}", agent, ceiling=ceiling_, handed=handed)
        assert len(agent.runs) == 1, "a lead makes ONE run"
        assert handed == [ceiling_]
        assert agent.runs[0]["usage_limits"].request_limit == ceiling_
        assert agent.deps[0].stop == LeadStop()


def test_a_lead_that_finished_is_untouched(tmp_path):
    stamps: list = []
    out = dispatch(tmp_path, Agent("measured: two logins."), ceiling=8, stamps=stamps)
    assert frame_body(out) == "measured: two logins."
    assert stamps == []
    assert INCOMPLETE_IDIOM not in out


def test_a_dead_end_on_the_record_puts_the_dead_end_notice_above_the_summary(tmp_path):
    stamps: list = []
    out = dispatch(tmp_path, Agent("what I had.", to_stop=dead_end), stamps=stamps)
    header, body = split(out)
    assert header == HEADER_DEAD_END.format(lead=LEAD, reason=DEAD_END.reason,
                                            escape=DEAD_END.escape)
    assert body == "what I had."
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]


def test_a_ceiling_on_the_record_puts_the_request_limit_notice_above_the_summary(tmp_path):
    """The run ended cleanly and the record says the ceiling hook marked it: the notice names
    the ceiling the HOOK wrote (the run's), not the dispatch argument — here they agree, and
    the count off the result is never consulted (the result has none)."""
    stamps: list = []
    out = dispatch(tmp_path, Agent("what I had.", to_stop=ceiling), ceiling=8, stamps=stamps)
    header, body = split(out)
    assert header == HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=8)
    assert "request_limit of" not in header, \
        "the notice quotes the framework's exception text rather than the lead's ceiling"
    assert "before finishing" not in header, "a lead that wrote its summary did finish"
    assert body == "what I had."
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_REQUEST_LIMIT)]


def test_a_dead_end_outranks_the_ceiling_when_the_lead_met_both(tmp_path):
    stamps: list = []
    out = dispatch(tmp_path, Agent("s.", to_stop=both), ceiling=8, stamps=stamps)
    assert split(out)[0].startswith(f"gather for {LEAD} hit a dead end: ")
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]


def test_a_fault_after_the_ceiling_was_marked_shows_main_the_ceiling(tmp_path):
    """The model wrote no text on its marked, tool-less final request: whichever way the
    framework then ends the run — no output retries left, or one more request the ceiling
    refuses — the record says the ceiling was marked, and main reads the ceiling notice over
    the fixed no-summary sentence, with the ceiling's stamp: that session was cut off by its
    request limit, not by a retry count."""
    for i, exc in enumerate((
        UnexpectedModelBehavior("Exceeded maximum output retries (0)"),
        UsageLimitExceeded("The next request would exceed the request_limit of 8"),
    )):
        stamps: list = []
        out = dispatch(tmp_path / str(i), Agent(exc=exc, to_stop=ceiling), ceiling=8,
                       stamps=stamps)
        assert split(out) == (HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=8), NO_SUMMARY_FAILED)
        assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_REQUEST_LIMIT)]


@pytest.mark.parametrize("arm", ["retry-exhausted", "store", "request-limit"])
def test_a_fault_on_an_unstopped_lead_carries_its_notice_and_the_failed_sentence(tmp_path, arm):
    """The FAULT arms, on a lead the harness never stopped: their own notice as the header,
    the same two-paragraph shape as every other cut lead, so main reads one format. The
    request-limit exception with NO ceiling on the record is a fake's shape (nothing marked
    the request), and it still names the dispatch's ceiling."""
    exc, header, terminator = {
        "retry-exhausted": (
            UnexpectedModelBehavior("Exceeded maximum output retries (0)"),
            HEADER_RETRY_EXHAUSTED.format(
                lead=LEAD, detail=str(UnexpectedModelBehavior("Exceeded maximum output retries (0)"))),
            session_store.TRUNCATED_BY_RETRY_EXHAUSTED,
        ),
        "store": (
            session_store.StoreError("the store cannot take this round"),
            HEADER_STORE.format(lead=LEAD, detail="the store cannot take this round"),
            session_store.TRUNCATED_BY_STORE,
        ),
        "request-limit": (
            UsageLimitExceeded("limit"),
            HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=40),
            session_store.TRUNCATED_BY_REQUEST_LIMIT,
        ),
    }[arm]
    stamps: list = []
    out = dispatch(tmp_path, Agent(exc=exc), stamps=stamps)
    assert split(out) == (header, NO_SUMMARY_FAILED)
    assert stamps == [(f"gather:{LEAD}", terminator)]


@pytest.mark.parametrize("exc", [
    UnexpectedModelBehavior("Exceeded maximum output retries (0)"),
    session_store.StoreError("disk full"),
    UsageLimitExceeded("limit"),
], ids=["retry-exhausted", "store", "request-limit"])
def test_a_fault_after_a_dead_end_still_shows_main_the_dead_end(tmp_path, exc):
    """A guard stopped the lead, and the model then FAILED to summarize (an empty response,
    a store that refused the summary round, no text on the final request). Main is shown the
    stop — the guard's reason is what it reasons from — with the no-summary sentence under
    it, and the session is stamped with the dead end that stopped it. Before this, the fault
    arms never looked at the record, and the dead end vanished from both."""
    stamps: list = []
    out = dispatch(tmp_path, Agent(exc=exc, to_stop=both), ceiling=8, stamps=stamps)
    header, got_body = split(out)
    assert header == HEADER_DEAD_END.format(lead=LEAD, reason=DEAD_END.reason,
                                            escape=DEAD_END.escape)
    assert got_body == NO_SUMMARY_FAILED
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]


@pytest.mark.parametrize("arm", ["budget", "aborted"])
def test_the_two_run_level_arms_still_pass_through(tmp_path, arm):
    exc, terminator = {
        "budget": (BudgetKill("tail exhausted"), session_store.TRUNCATED_BY_BUDGET),
        "aborted": (circuit_breaker.RunAborted(5, ["elastic"]), session_store.TRUNCATED_BY_ABORTED),
    }[arm]
    stamps: list = []
    with pytest.raises(type(exc)):
        dispatch(tmp_path, Agent(exc=exc, to_stop=dead_end), stamps=stamps)
    assert stamps == [(f"gather:{LEAD}", terminator)], \
        "a run-level end was stamped with the lead's stop instead of what ended the run"


# ----------------------------------------------------------------------------------------
# Vocabulary — what the gather model is told never carries main's idiom.
# ----------------------------------------------------------------------------------------


def test_no_closing_sentence_carries_mains_idiom_and_every_notice_does():
    for module, name in (
        (request_ceiling, "WRITE_SUMMARY_NOW"), (request_ceiling, "FINAL_REQUEST"),
        (query_tool, "QUERY_DOOR_CLOSED"), (query_tool, "QUERY_NOT_RUN"),
    ):
        text = getattr(module, name)
        assert "Treat this lead" not in text, name
        assert "summary" in text, f"{name} does not ask for the summary"
    assert not hasattr(request_ceiling, "TOOL_NOT_RUN_BUDGET_SPENT"), \
        "a 'budget spent' tool result exists — on the final request no tool call happens"
    assert "{" not in tools_gather.NO_SUMMARY_FAILED, \
        "the no-summary sentence has a hole — the only text to fill it is not the host's"
    assert tools_gather.INCOMPLETE_IDIOM == INCOMPLETE_IDIOM
    assert tools_gather._dead_end_notice(LEAD, DEAD_END).endswith(INCOMPLETE_IDIOM)
    assert tools_gather._request_limit_notice(LEAD, 8).endswith(INCOMPLETE_IDIOM)
