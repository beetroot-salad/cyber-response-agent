"""#987 — the STOPPED lead, at `_run_gather`'s own seam and at the door's.

THE DEFECT. A gather lead the harness stopped — a guard's dead end, or its request ceiling —
was cut by an exception, and main received a stand-in notice in place of everything the lead
had retrieved (see `tests/e2e/test_987_stopped_lead.py` for the whole story).

THE CHANGE. The stop is a TOOL RESULT, not an exception. The query tool closes the lead's
`QueryDoor` and tells the model so in the tool's own answer; the model's next turn is the
summary; `_run_gather` reads the door after the run and puts the arm's notice above it. This
module drives `_run_gather` with FAKE gather agents through the `gather_factory` seam the
entry point already declares — the notice bytes, the terminator, the composition, the arm
census, the ceiling handed down — and the door's own semantics with no agent at all.
Everything that needs the REAL query tool and the real graph is next door.

No `monkeypatch.setattr`: every fake enters through `gather_factory`.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded  # noqa: E402

# `driver` FIRST: entering the `tools_gather` <-> `tools` cycle at `tools_gather` raises on a
# partially initialized module.
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.hooks.budget_enforcer import BudgetKill  # noqa: E402
from defender.runtime import circuit_breaker, query_tool, session_store, tools_gather  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.tools import QueryDoor  # noqa: E402
from defender.runtime.tools_gather import (  # noqa: E402
    NO_SUMMARY_FAILED,
    NO_SUMMARY_FORFEITED,
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
    """A gather agent that records its one `.run`, and either returns `output` after doing
    `to_door` to the deps' door (the query tool's part, played here), or raises `exc`."""

    def __init__(self, output: str = "measured: two logins from dev.dana.",
                 *, exc: BaseException | None = None, to_door=None):
        self._output, self._exc, self._to_door = output, exc, to_door
        self.runs: list[dict] = []
        self.doors: list[QueryDoor] = []

    async def run(self, prompt=None, **kwargs):
        self.runs.append({"prompt": prompt, **kwargs})
        self.doors.append(kwargs["deps"].door)
        if self._exc is not None:
            raise self._exc
        if self._to_door is not None:
            self._to_door(kwargs["deps"].door)

        class _Result:
            output = self._output

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


def test_the_door_closes_once_and_a_dead_end_outranks_a_ceiling_close_in_the_same_round():
    door = QueryDoor(8)
    assert not door.closed
    door.close(at=7)
    assert door.closed
    assert (door.closed_at, door.dead_end) == (7, None)
    door.close(at=7, dead_end=DEAD_END)
    assert door.dead_end is DEAD_END, \
        "a sibling's dead end in the closing round did not outrank the ceiling's 'spent'"
    other = GatherDeadEnd(reason="later", escape="x")
    door.close(at=8, dead_end=other)
    assert (door.dead_end, door.closed_at) == (DEAD_END, 7), "a later close overwrote the first"

    first = QueryDoor(8)
    first.close(at=3, dead_end=DEAD_END)
    first.close(at=3)
    assert first.dead_end is DEAD_END, "a ceiling close erased a dead end"


def test_the_last_query_round_is_one_below_the_ceiling_and_a_door_without_one_never_closes():
    """`requests` is the count DURING a round's tool calls; the round that sees `ceiling - 1`
    is the last whose results the model can be shown before its final request."""
    door = QueryDoor(8)
    assert [door.is_last_query_round(n) for n in (6, 7, 8)] == [False, True, True]
    assert not QueryDoor().is_last_query_round(10 ** 6)
    assert not QueryDoor(None).closed


def test_a_bound_gather_deps_carries_an_open_door_with_no_ceiling(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    deps = bind(GATHER_DEF, run_dir, defender_dir=DEFENDER)
    assert isinstance(deps.door, QueryDoor)
    assert not deps.door.closed
    assert deps.door.request_limit is None


# ----------------------------------------------------------------------------------------
# `_run_gather` — one run, one ceiling, and the door read afterwards.
# ----------------------------------------------------------------------------------------


def test_the_factory_the_door_and_the_usage_limit_are_handed_one_number(tmp_path):
    """#880 F-19 and #808 d21/F6 in one assertion: the recorder the factory builds, the door
    the query tool reads, and the `UsageLimits` the run enforces are the SAME ceiling — not
    the ceiling and a derived neighbour. Driven at two ceilings so a constant cannot pass."""
    for i, ceiling in enumerate((40, 8)):
        handed: list[int] = []
        agent = Agent()
        dispatch(tmp_path / f"c{i}", agent, ceiling=ceiling, handed=handed)
        assert len(agent.runs) == 1, "a lead makes ONE run"
        assert handed == [ceiling]
        assert agent.runs[0]["usage_limits"].request_limit == ceiling
        assert agent.doors[0].request_limit == ceiling


def test_a_lead_that_finished_is_untouched(tmp_path):
    stamps: list = []
    out = dispatch(tmp_path, Agent("measured: two logins."), stamps=stamps)
    assert frame_body(out) == "measured: two logins."
    assert stamps == []
    assert INCOMPLETE_IDIOM not in out


def test_a_door_closed_on_a_dead_end_puts_the_dead_end_notice_above_the_summary(tmp_path):
    stamps: list = []
    agent = Agent("what I had.", to_door=lambda d: d.close(at=3, dead_end=DEAD_END))
    out = dispatch(tmp_path, agent, stamps=stamps)
    header, body = split(out)
    assert header == HEADER_DEAD_END.format(lead=LEAD, reason=DEAD_END.reason,
                                            escape=DEAD_END.escape)
    assert body == "what I had."
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]


def test_a_door_closed_on_the_ceiling_puts_the_request_limit_notice_above_the_summary(tmp_path):
    stamps: list = []
    agent = Agent("what I had.", to_door=lambda d: d.close(at=7))
    out = dispatch(tmp_path, agent, ceiling=8, stamps=stamps)
    header, body = split(out)
    assert header == HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=8)
    assert "request_limit of" not in header, \
        "the notice quotes the framework's exception text rather than the lead's ceiling"
    assert body == "what I had."
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_REQUEST_LIMIT)]


def test_a_dead_end_outranks_the_ceiling_when_both_closed_the_door(tmp_path):
    def both(d: QueryDoor) -> None:
        d.close(at=7)
        d.close(at=7, dead_end=DEAD_END)

    stamps: list = []
    out = dispatch(tmp_path, Agent("s.", to_door=both), ceiling=8, stamps=stamps)
    assert split(out)[0].startswith(f"gather for {LEAD} hit a dead end: ")
    assert stamps == [(f"gather:{LEAD}", session_store.TRUNCATED_BY_DEAD_END)]


@pytest.mark.parametrize("arm", ["request-limit", "dead-end"])
def test_a_stop_that_reaches_the_frame_as_an_exception_is_a_forfeited_grace_turn(tmp_path, arm):
    """The two STOP exceptions reach `_run_gather` only when the model queried again after
    being told to stop (the query tool re-raises a stored dead end; the framework refuses the
    request after a closed-door round). Notice, blank line, the fixed no-summary sentence."""
    exc, header, terminator = {
        "request-limit": (
            UsageLimitExceeded("The next request would exceed the request_limit of 8"),
            HEADER_REQUEST_LIMIT.format(lead=LEAD, limit=8),
            session_store.TRUNCATED_BY_REQUEST_LIMIT,
        ),
        "dead-end": (
            DEAD_END,
            HEADER_DEAD_END.format(lead=LEAD, reason=DEAD_END.reason, escape=DEAD_END.escape),
            session_store.TRUNCATED_BY_DEAD_END,
        ),
    }[arm]
    stamps: list = []
    out = dispatch(tmp_path, Agent(exc=exc), ceiling=8, stamps=stamps)
    assert split(out) == (header, NO_SUMMARY_FORFEITED)
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
    for name in ("WRITE_SUMMARY_NOW", "QUERY_DOOR_CLOSED", "BUDGET_SPENT", "SIBLING_NOT_RUN"):
        text = getattr(query_tool, name)
        assert "Treat this lead" not in text, name
        assert "summary" in text, f"{name} does not ask for the summary"
    for name in ("NO_SUMMARY_FORFEITED", "NO_SUMMARY_FAILED"):
        text = getattr(tools_gather, name)
        assert "{" not in text, f"{name} has a hole — the only text to fill it is not the host's"
    assert tools_gather.INCOMPLETE_IDIOM == INCOMPLETE_IDIOM
    assert tools_gather._dead_end_notice(LEAD, DEAD_END).endswith(INCOMPLETE_IDIOM)
    assert tools_gather._request_limit_notice(LEAD, 8).endswith(INCOMPLETE_IDIOM)
