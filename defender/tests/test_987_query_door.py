"""#987 — the STOPPED lead, at `_run_gather`'s own seam and at the door's.

THE DEFECT. A gather lead the harness stopped — a guard's dead end, or its request ceiling —
was cut by an exception, and main received a stand-in notice in place of everything the lead
had retrieved (see `tests/e2e/test_987_stopped_lead.py` for the whole story).

THE CHANGE. The stop is a TOOL RESULT, not an exception. A guard's stop closes the lead's
`QueryDoor` and is told to the model in the tool's own answer; the ceiling is a ROUND, and
`RequestCeiling` tells the model on the last request itself; the model's next turn is the
summary; `_run_gather` reads the door and the run's request count afterwards and puts the
notice above it. This module drives `_run_gather` with FAKE gather agents through the
`gather_factory` seam the entry point already declares — the notice bytes, the terminator,
the composition, the arm census, the ceiling handed down — and the door's and the ceiling
hook's own semantics with no agent at all. Everything that needs the REAL query tool and the
real graph is next door.

No `monkeypatch.setattr`: every fake enters through `gather_factory`.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ToolFailed, UnexpectedModelBehavior, UsageLimitExceeded  # noqa: E402
from pydantic_ai.messages import ModelRequest, ToolReturnPart, UserPromptPart  # noqa: E402

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
from defender.runtime.tools import QueryDoor  # noqa: E402
from defender.runtime.tools_gather import (  # noqa: E402
    NO_SUMMARY_FAILED,
    NO_SUMMARY_SPENT,
    GatherRequest,
)
from defender.scripts.gather_tools.record_query import GatherDeadEnd  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER, GOLDEN_AB3, materialize  # noqa: E402

LEAD = "l-001"

#: The tail sentence #807's G19/C5 pinned as MAIN's own vocabulary — the one sentence gather
#: must never be shown, and the one main must always be.
INCOMPLETE_IDIOM = "Treat this lead as incomplete and reason from what was captured."

# ---------------------------------------------------------------------------------------
# THE FOUR NOTICES, AS LITERALS THIS FILE OWNS. Re-deriving them from the implementation
# would make every header assertion a tautology. Three are the arms' text at the base commit;
# the request-limit one names the lead's OWN ceiling where it used to quote the framework's
# exception (which names `request_limit - 1`'s composition, not the ceiling — a reader
# reconciling the notice against #808's 40/8 read a contradiction).
# ---------------------------------------------------------------------------------------
HEADER_REQUEST_LIMIT = (
    "gather for {lead} hit its request limit ({limit} requests) before finishing; "
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

DEAD_END = GatherDeadEnd(reason="the request (elastic query) repeats seq 0.", escape="Move on.")

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
    """A gather agent that records its one `.run`, does `to_door` to the deps' door (the
    query tool's part, played here), and either returns `output` with a usage that counts
    `requests`, or raises `exc`."""

    def __init__(self, output: str = "measured: two logins from dev.dana.",
                 *, exc: BaseException | None = None, to_door=None, requests: int = 2):
        self._output, self._exc, self._to_door = output, exc, to_door
        self._requests = requests
        self.runs: list[dict] = []
        self.deps: list = []

    async def run(self, prompt=None, **kwargs):
        self.runs.append({"prompt": prompt, **kwargs})
        self.deps.append(kwargs["deps"])
        if self._to_door is not None:
            self._to_door(kwargs["deps"].door)
        if self._exc is not None:
            raise self._exc

        class _Result:
            output = self._output
            usage = SimpleNamespace(requests=self._requests)

        return _Result()


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


# ----------------------------------------------------------------------------------------
# The door itself.
# ----------------------------------------------------------------------------------------


def test_the_door_closes_once_on_a_dead_end_and_holds_nothing_else():
    """Two siblings tripping in one round keep the FIRST's reason: the notice main reads names
    the request that actually stopped the lead. The door knows nothing of the ceiling."""
    door = QueryDoor()
    assert not door.closed
    door.close(DEAD_END)
    assert door.closed
    assert door.dead_end is DEAD_END
    door.close(GatherDeadEnd(reason="later", escape="x"))
    assert door.dead_end is DEAD_END, "a later close overwrote the first"
    assert not hasattr(door, "request_limit"), \
        "the ceiling is a fact about the round (`RequestCeiling`), not a door state"


def test_a_bound_gather_deps_carries_no_door_and_no_ceiling(tmp_path):
    """Outside a dispatch nobody would read a door, so there is none: a guard's dead end on
    such deps unwinds as the exception it always was, and the ceiling hook has nothing to
    mark. `_run_gather` is the one place that makes both."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    deps = bind(GATHER_DEF, run_dir, defender_dir=DEFENDER)
    assert deps.door is None
    assert deps.request_limit is None


# ----------------------------------------------------------------------------------------
# The ceiling hook — one number, read at the round.
# ----------------------------------------------------------------------------------------


def _ctx(requests: int, request_limit: int | None = 8) -> SimpleNamespace:
    return SimpleNamespace(
        usage=SimpleNamespace(requests=requests),
        deps=SimpleNamespace(request_limit=request_limit),
    )


def _marked(requests: int, request_limit: int | None = 8) -> list:
    """The parts of a one-tool-return request after the hook saw it at `requests`."""
    req = ModelRequest(parts=[
        ToolReturnPart(tool_name="query", content="exit=0", tool_call_id="c1")])
    rc = SimpleNamespace(messages=[req])
    asyncio.run(RequestCeiling().before_model_request(_ctx(requests, request_limit), rc))
    return rc.messages[-1].parts


def test_the_final_request_alone_is_marked_and_after_the_rounds_tool_results():
    """`requests` reads N-1 while request N is prepared, so the request prepared at
    `ceiling - 1` is the last the ceiling allows. One sentence, as a USER part, after the
    round's tool returns — the order the framework itself canonicalizes a request to — and
    nothing on any other request."""
    assert [len(_marked(n)) for n in (5, 6, 7, 8)] == [1, 1, 2, 1]
    parts = _marked(7)
    assert isinstance(parts[0], ToolReturnPart)
    assert isinstance(parts[1], UserPromptPart)
    assert parts[1].content == FINAL_REQUEST
    assert len(_marked(0, request_limit=1)) == 2, "a ceiling of one marks the very first request"
    assert len(_marked(7, request_limit=None)) == 1, "deps with no ceiling were marked"


def test_a_tool_call_on_the_final_request_is_refused_and_earlier_ones_run():
    """Round N's tool calls run with `requests == N`; on round `ceiling` their results would
    go into a request the framework refuses, so nothing runs — whatever the tool."""
    ran: list = []

    async def handler(args):
        ran.append(args)
        return "ok"

    hook = RequestCeiling()
    for n in (1, 7):
        assert asyncio.run(hook.wrap_tool_execute(
            _ctx(n), call=SimpleNamespace(tool_name="bash"), args={"n": n}, handler=handler,
        )) == "ok"
    with pytest.raises(ToolFailed) as ei:
        asyncio.run(hook.wrap_tool_execute(
            _ctx(8), call=SimpleNamespace(tool_name="query"), args={"n": 8}, handler=handler,
        ))
    assert request_ceiling.TOOL_NOT_RUN_BUDGET_SPENT in str(ei.value)
    assert [a["n"] for a in ran] == [1, 7]
    assert asyncio.run(hook.wrap_tool_execute(
        _ctx(8, request_limit=None), call=SimpleNamespace(tool_name="query"), args={"n": 9},
        handler=handler,
    )) == "ok", "deps with no ceiling were refused"


def test_the_request_count_reads_zero_for_a_context_with_no_usage():
    assert request_ceiling.requests_so_far(SimpleNamespace()) == 0
    assert request_ceiling.requests_so_far(SimpleNamespace(usage=None)) == 0
    assert request_ceiling.requests_so_far(SimpleNamespace(usage=SimpleNamespace(requests=3))) == 3


# ----------------------------------------------------------------------------------------
# `_run_gather` — one run, one ceiling, and the door read afterwards.
# ----------------------------------------------------------------------------------------


def test_the_factory_the_deps_and_the_usage_limit_are_handed_one_number(tmp_path):
    """#880 F-19 and #808 d21/F6 in one assertion: the recorder the factory builds, the
    ceiling hook reading the deps, and the `UsageLimits` the run enforces are the SAME
    ceiling — not the ceiling and a derived neighbour. Driven at two ceilings so a constant
    cannot pass. The deps carry a fresh, open door: `_run_gather` is where doors are made."""
    for i, ceiling in enumerate((40, 8)):
        handed: list[int] = []
        agent = Agent()
        dispatch(tmp_path / f"c{i}", agent, ceiling=ceiling, handed=handed)
        assert len(agent.runs) == 1, "a lead makes ONE run"
        assert handed == [ceiling]
        assert agent.runs[0]["usage_limits"].request_limit == ceiling
        assert agent.deps[0].request_limit == ceiling
        assert isinstance(agent.deps[0].door, QueryDoor)
        assert not agent.deps[0].door.closed


def test_a_lead_that_finished_is_untouched(tmp_path):
    stamps: list = []
    out = dispatch(tmp_path, Agent("measured: two logins.", requests=2), ceiling=8, stamps=stamps)
    assert frame_body(out) == "measured: two logins."
    assert stamps == []
    assert INCOMPLETE_IDIOM not in out


def test_a_door_closed_on_a_dead_end_puts_the_dead_end_notice_above_the_summary(tmp_path):
    stamps: list = []
    agent = Agent("what I had.", to_door=lambda d: d.close(DEAD_END))
    out = dispatch(tmp_path, agent, stamps=stamps)
    header, body = split(out)
    assert header == HEADER_DEAD_END.format(lead=LEAD, reason=DEAD_END.reason,
                                            escape=DEAD_END.escape)
    assert body == "what I had."
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]


def test_a_summary_written_on_the_final_request_gets_the_request_limit_notice_above_it(tmp_path):
    """The run ended cleanly and its request count IS the ceiling: the text came from the
    request `RequestCeiling` marked. Nothing on the door; the count alone says so."""
    stamps: list = []
    out = dispatch(tmp_path, Agent("what I had.", requests=8), ceiling=8, stamps=stamps)
    header, body = split(out)
    assert header == HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=8)
    assert "request_limit of" not in header, \
        "the notice quotes the framework's exception text rather than the lead's ceiling"
    assert body == "what I had."
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_REQUEST_LIMIT)]


def test_a_dead_end_outranks_the_ceiling_when_the_lead_met_both(tmp_path):
    stamps: list = []
    out = dispatch(tmp_path, Agent("s.", to_door=lambda d: d.close(DEAD_END), requests=8),
                   ceiling=8, stamps=stamps)
    assert split(out)[0].startswith(f"gather for {LEAD} hit a dead end: ")
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]


@pytest.mark.parametrize("door_state", ["open", "dead-end"])
def test_the_request_limit_exception_is_a_final_request_spent_on_tool_calls(tmp_path, door_state):
    """The framework's exception reaches `_run_gather` only when the model answered its
    marked final request with tool calls (refused, not run) and the request after it was
    refused. Notice — the dead end's if a guard had closed the door, else the ceiling's — a
    blank line, the fixed no-summary sentence. No dead-end ARM exists: on deps with a door a
    guard's stop never leaves the tool."""
    to_door, header, terminator = {
        "open": (None, HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=8),
                 session_store.TRUNCATED_BY_REQUEST_LIMIT),
        "dead-end": (lambda d: d.close(DEAD_END),
                     HEADER_DEAD_END.format(lead=LEAD, reason=DEAD_END.reason,
                                            escape=DEAD_END.escape),
                     session_store.TRUNCATED_BY_DEAD_END),
    }[door_state]
    stamps: list = []
    exc = UsageLimitExceeded("The next request would exceed the request_limit of 8")
    out = dispatch(tmp_path, Agent(exc=exc, to_door=to_door), ceiling=8, stamps=stamps)
    assert split(out) == (header, NO_SUMMARY_SPENT)
    assert stamps == [(f"gather:{LEAD}", terminator)]


@pytest.mark.parametrize("arm", ["retry-exhausted", "store"])
def test_a_fault_arm_carries_its_notice_and_the_failed_sentence(tmp_path, arm):
    """The two FAULT arms are untouched in what they say about the fault; they carry the
    same two-paragraph shape as every other cut lead, so main reads one format."""
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
    }[arm]
    stamps: list = []
    out = dispatch(tmp_path, Agent(exc=exc), stamps=stamps)
    assert split(out) == (header, NO_SUMMARY_FAILED)
    assert stamps == [(f"gather:{LEAD}", terminator)]


@pytest.mark.parametrize("arm", ["budget", "aborted"])
def test_the_two_run_level_arms_still_pass_through(tmp_path, arm):
    exc, terminator = {
        "budget": (BudgetKill("tail exhausted"), session_store.TRUNCATED_BY_BUDGET),
        "aborted": (circuit_breaker.RunAborted(5, ["elastic"]), session_store.TRUNCATED_BY_ABORTED),
    }[arm]
    stamps: list = []
    with pytest.raises(type(exc)):
        dispatch(tmp_path, Agent(exc=exc), stamps=stamps)
    assert stamps == [(f"gather:{LEAD}", terminator)]


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
    assert "Treat this lead" not in request_ceiling.TOOL_NOT_RUN_BUDGET_SPENT
    for name in ("NO_SUMMARY_SPENT", "NO_SUMMARY_FAILED"):
        text = getattr(tools_gather, name)
        assert "{" not in text, f"{name} has a hole — the only text to fill it is not the host's"
    assert tools_gather.INCOMPLETE_IDIOM == INCOMPLETE_IDIOM
    assert tools_gather._dead_end_notice(LEAD, DEAD_END).endswith(INCOMPLETE_IDIOM)
    assert tools_gather._request_limit_notice(LEAD, 8).endswith(INCOMPLETE_IDIOM)
