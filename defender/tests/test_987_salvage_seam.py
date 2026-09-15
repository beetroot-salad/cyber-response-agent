"""#987 — the SALVAGE TURN, at `_run_gather`'s own seam.

THE CODE DOES NOT EXIST YET. This module is RED by construction: the import block below names
the surface the implementation must build (`SALVAGE_PROMPT`, `SALVAGE_REQUEST_LIMIT`,
`SALVAGE_CLOSED_SENTENCE`, `SALVAGE_FAILED_SENTENCE`), and that is the point.

THE DEFECT. When one of `_run_gather`'s four DEGRADING arms fires — `UsageLimitExceeded`,
`GatherDeadEnd`, `UnexpectedModelBehavior`, `session_store.StoreError` — the harness authored a
stand-in notice and main never saw the answers the sub-agent had already retrieved, because
they lived in the gather run's own context, which unwound with the run. Main may not read
`gather_raw/` (policy, not accident), and the queries table carries digests, not answers, so a
lead that answered six queries and then died read to main as empty.

THE CHANGE. After any of those four cuts the SAME gather agent gets one more turn, TOOL-LESS,
over its own captured history, to write the summary. Today's notice becomes a HEADER on top of
it, so main still tells a cut-short lead from a finished one in the vocabulary it already
handles. The ceiling is not raised: the query phase now runs under `request_limit - 1` and the
summary turn spends the reserved request.

WHAT LIVES HERE AND WHAT LIVES NEXT DOOR. This module drives `_run_gather` with FAKE gather
agents through the `gather_factory` seam the entry point already declares — the arithmetic, the
arm census, the header bytes, the terminator, and the constants' own vocabulary, none of which
need a model. Everything that needs the REAL agent — the tool-less turn through the real
factory, the closing of dangling tool calls, the failed summary turn, the hallucinated tool
call — is in `tests/e2e/test_987_salvage_turn.py`, driven through real pydantic-ai machinery,
because those are exactly the claims a mocked agent would certify without testing.

Two committed decisions are revised here, named so they are not revised silently:
  - #807 F-C ("gather is never asked again") — gather is never asked to QUERY again; it is
    asked once, tool-less, to SUMMARIZE. G19 (the gather model never sees main's idiom) stands
    and is pinned harder than before, because there is now a prompt that could have leaked it.
  - #808 d21/F6 ("a lead makes at most `request_limit` model requests") — the NUMBER stands;
    its composition changes to `request_limit - 1` query rounds plus the one summary turn.

No `monkeypatch.setattr`: every fake enters through `gather_factory`, the parameter
`_run_gather` already takes.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded  # noqa: E402

# `driver` FIRST, and deliberately: `runtime.tools_gather` imports `runtime.tools`, which
# re-imports `GatherRequest` back out of it, so entering the cycle at `tools_gather` itself
# raises `ImportError` on a partially initialized module. Every sibling suite enters through
# `driver` for the same reason.
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.hooks.budget_enforcer import BudgetKill  # noqa: E402
from defender.runtime import circuit_breaker, session_store, tools_gather  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.tools_gather import GatherRequest  # noqa: E402
from defender.scripts.gather_tools.record_query import GatherDeadEnd  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER, GOLDEN_AB3, materialize  # noqa: E402

# THE SURFACE UNDER TEST — none of it exists on this base (RED by construction).
from defender.runtime.tools_gather import (  # noqa: E402
    SALVAGE_CLOSED_SENTENCE,
    SALVAGE_FAILED_SENTENCE,
    SALVAGE_PROMPT,
    SALVAGE_REQUEST_LIMIT,
)

LEAD = "l-001"

#: The tail sentence #807's G19/C5 pinned as MAIN's own vocabulary — the one word gather must
#: never be shown, and the one word main must always be.
INCOMPLETE_IDIOM = "Treat this lead as incomplete and reason from what was captured."

# ---------------------------------------------------------------------------------------
# TODAY'S FOUR NOTICES, RESTATED AS TEMPLATES.
#
# O6 is "byte-identical to what the four arms carry today", so the comparison has to be
# against literals this file OWNS. Re-deriving them from the implementation under test would
# make every header assertion below a tautology: the header would be whatever shipped.
# Transcribed from `runtime/tools_gather.py`'s four `except` arms at the base commit.
# ---------------------------------------------------------------------------------------
HEADER_REQUEST_LIMIT = (
    "gather for {lead} hit its request limit ({detail}) before finishing; "
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

#: `(exception, header template, expected terminator)` — the four DEGRADING arms, the whole
#: census. `_run_gather`'s docstring calls its branch count "the terminator census"; this is
#: the half of it that degrades into a summary rather than ending the run.
DEGRADING_ARMS = {
    "request-limit": (
        UsageLimitExceeded("the limit"),
        HEADER_REQUEST_LIMIT,
        session_store.TRUNCATED_BY_REQUEST_LIMIT,
    ),
    "dead-end": (
        GatherDeadEnd(reason="the request (elastic query) repeats seq 0.", escape="Move on."),
        HEADER_DEAD_END,
        session_store.TRUNCATED_BY_DEAD_END,
    ),
    "retry-exhausted": (
        UnexpectedModelBehavior("Exceeded maximum output retries (0)"),
        HEADER_RETRY_EXHAUSTED,
        session_store.TRUNCATED_BY_RETRY_EXHAUSTED,
    ),
    "store": (
        session_store.StoreError("the store cannot take this round"),
        HEADER_STORE,
        session_store.TRUNCATED_BY_STORE,
    ),
}


def header_for(arm: str, lead: str = LEAD) -> str:
    """Today's notice for `arm`, filled the way the shipped `except` block fills it.

    The interpolated slot is `str(e)` — the exception's own rendering, not the string it was
    constructed with. `UsageLimitExceeded` appends its "Consider raising the limit…" advice to
    whatever it was given, and a template filled with the constructor argument would quietly
    stop describing what main receives.
    """
    exc, template, _terminator = DEGRADING_ARMS[arm]
    if isinstance(exc, GatherDeadEnd):
        return template.format(lead=lead, reason=exc.reason, escape=exc.escape)
    return template.format(lead=lead, detail=str(exc))


#: The two arms that END THE RUN. They re-raise today and must keep re-raising: a summary turn
#: on either would convert a kill into a measurement string and hide it from
#: `run_investigation`'s own catch.
RUN_LEVEL_ARMS = {
    "budget": (BudgetKill("tail exhausted"), session_store.TRUNCATED_BY_BUDGET),
    "aborted": (circuit_breaker.RunAborted(5, ["elastic"]), session_store.TRUNCATED_BY_ABORTED),
}

_FRAME = re.compile(r"\A<run-([0-9a-f]+)-untrusted>\n(?P<body>.*)\n</run-\1-untrusted>\Z",
                    re.DOTALL)


def frame_body(returned: str) -> str:
    """The body inside the ONE `untrusted` frame `_run_gather` returns.

    Asserting through this rather than on the raw string is what makes O6's "the whole return
    still goes through the existing wrap" load-bearing: a header emitted outside the frame, or
    a model-authored summary given a frame of its own, fails here rather than passing a
    substring check.
    """
    m = _FRAME.match(returned)
    assert m, f"the return is not one whole `untrusted` frame: {returned!r}"
    body = m.group("body")
    assert "-untrusted>" not in body, \
        "the header and the summary came back in two frames — main's parser sees two documents"
    return body


def split(returned: str) -> tuple[str, str]:
    """`(header, summary)` — M5's composition: today's notice, a blank line, the summary."""
    body = frame_body(returned)
    head, sep, tail = body.partition("\n\n")
    assert sep, f"the return carries no header/summary split at all: {body!r}"
    return head, tail


class RecordingAgent:
    """A gather agent that records every `.run` and every `.override`, and raises `exc` out of
    the FIRST run.

    It is a fault injector and an observation channel, nothing else: it classifies no
    exception, composes no string and decides no policy. `summary` is what the salvage turn
    "writes"; `None` makes the salvage turn itself fail, which is how this file reaches M6
    without a model (the REAL failure modes — a non-text response, a hallucinated tool call —
    are driven for real next door).
    """

    def __init__(self, exc: BaseException, *, summary: str | None = "measured two logins."):
        self._exc = exc
        self._summary = summary
        self.runs: list[dict] = []
        self.overrides: list[dict] = []

    def override(self, **kwargs):
        self.overrides.append(kwargs)

        class _Ctx:
            def __enter__(self):
                return None

            def __exit__(self, *a):
                return False

        return _Ctx()

    async def run(self, prompt=None, **kwargs):
        self.runs.append({"prompt": prompt, **kwargs})
        if len(self.runs) == 1:
            raise self._exc
        if self._summary is None:
            raise UnexpectedModelBehavior("Exceeded maximum output retries (0)")

        class _Result:
            output = self._summary

        return _Result()


class CleanAgent:
    """The complementary condition for every negative below: a lead that finished."""

    def __init__(self, output: str = "measured: two logins from dev.dana."):
        self._output = output
        self.runs: list[dict] = []
        self.overrides: list[dict] = []

    def override(self, **kwargs):  # pragma: no cover — reaching it IS the failure
        raise AssertionError("a lead that finished was given a tool-less summary turn")

    async def run(self, prompt=None, **kwargs):
        self.runs.append({"prompt": prompt, **kwargs})

        class _Result:
            output = self._output

        return _Result()


def _deps(root: Path):
    run_dir = materialize(root, GOLDEN_AB3)
    return run_dir, bind(MAIN_DEF, run_dir, defender_dir=DEFENDER)


def dispatch(root: Path, agent, *, ceiling: int = 40, lead: str = LEAD,
             what: tuple[str, ...] = ("auth events",), stamps: list | None = None,
             handed: list | None = None) -> tuple[Path, str]:
    """Drive the REAL `_run_gather` over `agent`, handed in through the factory seam."""
    run_dir, deps = _deps(root)

    def factory(agent_id: str, system: str, request_limit: int):
        if handed is not None:
            handed.append(request_limit)
        return agent

    out = asyncio.run(tools_gather._run_gather(
        deps, factory, ceiling, GatherRequest(lead, "elastic", "measure this lead", what),
        GATHER_DEF.verb_grant,
        (lambda agent_id, reason: stamps.append((agent_id, reason))) if stamps is not None
        else None,
        catalog=None,
    ))
    return run_dir, out


def _limit_of(run_kwargs: dict) -> int | None:
    limits = run_kwargs.get("usage_limits")
    return getattr(limits, "request_limit", None) if limits is not None else None


# ----------------------------------------------------------------------------------------
# O5 / M2 — the ceiling split. #808 d21/F6's number stands; its composition changes.
# ----------------------------------------------------------------------------------------


def test_the_query_phase_ceiling_is_one_below_the_leads_own_and_the_salvage_turn_spends_it(
        tmp_path):
    """O5, M2 — `_run_gather` hands `request_limit - 1` to BOTH the factory and the query
    run's `UsageLimits`, and reserves exactly one request for the summary turn.

    BOTH, and by construction rather than by two literals agreeing: the factory builds this
    lead's history recorder, whose withholding mirror compares the request count against a
    ceiling, and `_build.py`'s own contract (#880 F-19, `test_the_gather_factory_is_handed_the
    _ceiling_this_dispatch_will_enforce`) is that the two are one number. A change that lowered
    only the `UsageLimits` would leave the recorder committing a round that is never sent.

    Driven at TWO ceilings so a factory or a `UsageLimits` reading a constant — 39, or
    `GATHER_REQUEST_LIMIT - 1` — cannot pass both. The lead's own ceiling is asserted as the
    SUM, which is the property #808's number actually names: `(request_limit - 1) +
    SALVAGE_REQUEST_LIMIT == request_limit`, so the total a cut-short lead can spend is
    unchanged."""
    assert SALVAGE_REQUEST_LIMIT == 1, \
        "the reserved request is not one — the ceiling arithmetic below has no fixed point"

    for i, ceiling in enumerate((40, 8)):
        handed: list[int] = []
        agent = RecordingAgent(UsageLimitExceeded("the limit"))
        dispatch(tmp_path / f"c{i}", agent, ceiling=ceiling, handed=handed)

        assert handed == [ceiling - 1], (
            f"the factory was handed {handed} for a lead ceilinged at {ceiling} — its recorder "
            f"will withhold the doomed round against a number this dispatch does not enforce"
        )
        assert len(agent.runs) == 2, \
            f"a cut-short lead made {len(agent.runs)} runs, not a query phase plus one summary"
        assert _limit_of(agent.runs[0]) == ceiling - 1, (
            f"the query phase ran under {_limit_of(agent.runs[0])}, not {ceiling - 1} — the "
            "reserved request is taken out of nothing, so the lead can exceed its ceiling"
        )
        assert _limit_of(agent.runs[1]) == SALVAGE_REQUEST_LIMIT
        assert handed[0] == _limit_of(agent.runs[0]), (
            "the recorder's ceiling and the enforced ceiling are different numbers — #880 "
            "F-19's shape, reintroduced by the split"
        )
        assert _limit_of(agent.runs[0]) + SALVAGE_REQUEST_LIMIT == ceiling, (
            "a cut-short lead's query rounds plus its summary turn exceed the ceiling #808 "
            "d21/F6 pinned — the number was supposed to hold while its composition changed"
        )


def test_a_lead_that_finished_takes_no_summary_turn_and_its_text_is_untouched(tmp_path):
    """The positive control every negative in this file pairs with, and O2's other half: a
    CLEAN lead is not relabelled. It makes exactly one model run, is offered no tool-less turn
    at all (`CleanAgent.override` raises if one is attempted), carries no header, and does not
    carry main's incomplete idiom — otherwise "main can tell a cut-short lead from a finished
    one" is discharged by a vocabulary both of them speak.

    Its ceiling is one lower too (M2, "clean end: unchanged except the ceiling is one lower"),
    which is the cost the design records rather than hides."""
    agent = CleanAgent()
    run_dir, out = dispatch(tmp_path, agent, ceiling=40)

    assert len(agent.runs) == 1, "a lead that finished was asked to summarize itself again"
    assert _limit_of(agent.runs[0]) == 39
    body = frame_body(out)
    assert body == "measured: two logins from dev.dana.", \
        f"a clean lead's own text was rewritten by the salvage path: {body!r}"
    assert INCOMPLETE_IDIOM not in body, "a lead that finished reads to main as cut short"
    for phrase in ("gather for ", "hit its request limit", "hit a dead end",
                   "ended abnormally", "could not be recorded", "A summary turn was attempted"):
        assert phrase not in body, f"a clean lead was given a cut-short header: {phrase!r}"
    assert (run_dir / "gather_summaries" / f"{LEAD}.md").read_text(encoding="utf-8") == out


# ----------------------------------------------------------------------------------------
# O1 / O2 / O6 — one summary turn per degrading arm, under today's notice.
# ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("arm", sorted(DEGRADING_ARMS))
def test_every_degrading_arm_takes_one_tool_less_summary_turn_over_its_own_history(
        tmp_path, arm):
    """O1, O3, M3, M4 — the mechanism is UNIFORM across the four arms, and every one of them
    is a lead whose answers were being thrown away. The reporter saw only the dead-end arm
    because that is the one whose sibling parity failed; the request-limit and retry-exhausted
    arms lost the same context the same way.

    Four things are asserted about the second run, at the seam where they are decidable
    without a model: it carries NO user prompt positionally (`run(None, …)`, because the
    prompt rides in the replayed history — a new prompt over a history ending on unanswered
    tool calls is refused by the library outright), it carries a `message_history`, it runs
    under `SALVAGE_REQUEST_LIMIT`, and it runs under an `override` that withholds all three
    tool channels pydantic-ai 2.19.0 offers. `native_tools` is named explicitly: withholding
    `toolsets` and `tools` while leaving a provider-native tool advertised is precisely the
    hole O3 forbids, and it is one keyword away.

    The same `deps` object goes to both runs, so the summary turn is the same agent on the
    same lead — not a second dispatch under a second `agent_id`."""
    exc, _template, _term = DEGRADING_ARMS[arm]
    agent = RecordingAgent(exc, summary="two logins from dev.dana at 00:00 and 00:05.")
    _run_dir, out = dispatch(tmp_path, agent)

    assert len(agent.runs) == 2, \
        f"the {arm} arm made {len(agent.runs)} runs — it still authors the summary itself"
    salvage = agent.runs[1]
    assert salvage["prompt"] is None, (
        "the summary turn was sent as a NEW user prompt; on a history that ends on unanswered "
        "tool calls pydantic-ai refuses that outright, so this arm cannot work in general"
    )
    assert salvage.get("message_history"), \
        "the summary turn was run over no history — there is nothing to summarize FROM"
    assert _limit_of(salvage) == SALVAGE_REQUEST_LIMIT
    assert salvage.get("deps") is agent.runs[0].get("deps"), \
        "the summary turn was given different deps — it is a second dispatch, not one lead"

    assert len(agent.overrides) == 1, \
        f"{len(agent.overrides)} overrides wrapped the summary turn; exactly one may"
    ov = agent.overrides[0]
    for channel in ("toolsets", "tools", "native_tools"):
        assert channel in ov, (
            f"the summary turn's override leaves `{channel}` alone — a tool reaching the model "
            "on this turn is O3's failure, and this is the channel it comes through"
        )
        assert list(ov[channel]) == [], f"the override put something back on `{channel}`: {ov!r}"

    assert frame_body(out).endswith("two logins from dev.dana at 00:00 and 00:05."), \
        "main did not receive the summary the gather agent wrote"


@pytest.mark.parametrize("arm", sorted(DEGRADING_ARMS))
def test_the_header_is_byte_identical_to_todays_notice_and_the_summary_sits_under_it(
        tmp_path, arm):
    """O2, O6, M5 — today's per-arm string moves from "the whole message" to "the header",
    unchanged to the byte, and the model-authored summary follows it after one blank line.

    Byte-identical is the demand and not "contains": the four notices are the vocabulary main
    already handles (`dead_end_return_contract`'s "opens with the existing idiom", #826's
    `truncated_by` readers, #807's G19 screen), and a header reworded to introduce the summary
    would re-open every one of them. So this asserts EQUALITY against a literal transcribed
    into this file, not a substring of whatever shipped.

    The security clause rides here too: the header is the HARNESS-authored half, and the
    exception's own text is all it may interpolate — `record_query.py`'s refusal-path
    invariant, which #987 revises to bind the header rather than the whole message."""
    exc, _template, _term = DEGRADING_ARMS[arm]
    header = header_for(arm)
    summary = "dev.dana logged in twice; no container context was reachable."
    agent = RecordingAgent(exc, summary=summary)
    run_dir, out = dispatch(tmp_path, agent)

    got_header, got_summary = split(out)
    assert got_header == header, (
        f"the {arm} arm's header is no longer today's notice.\n  want: {header!r}\n"
        f"  got:  {got_header!r}"
    )
    assert got_summary == summary, \
        f"the model's summary was edited on the way to main: {got_summary!r}"
    assert frame_body(out) == f"{header}\n\n{summary}", \
        "the header and the summary are not one blank line apart"
    assert INCOMPLETE_IDIOM in got_header, \
        "the idiom left the header — main loses the one word it screens cut-short leads on"
    assert (run_dir / "gather_summaries" / f"{LEAD}.md").read_text(encoding="utf-8") == out, (
        "the persisted record is not the string main received — the two are supposed to be "
        "the same object, and every downstream reader of the `.md` reads the other one"
    )


def test_the_dead_end_header_still_carries_none_of_the_models_own_params(tmp_path):
    """O6, the revised invariant, stated in both directions (`record_query.py:1124-1127`).

    "Never the model-authored `params` text on a refusal path" used to bind the whole returned
    message. It now binds the HARNESS-AUTHORED HEADER — and only that, because the summary the
    model writes after being shown its own refusal crosses through exactly the channel every
    clean lead's summary crosses, `untrusted`-wrapped, where a model could already echo its own
    arguments. The revision is explicit, so it is pinned explicitly: the header must not carry
    the fragment, and the test must be able to SEE the fragment when it is there.

    The positive control is the second half: the same fragment, put in the model's summary,
    reaches main. Without it "not in the header" passes on a run where the fragment never
    existed at all."""
    fragment = 'FROM logs | WHERE user.name == "dev.dana" | LIMIT 5000'
    reason = ("the request (elastic query) repeats the one already issued at seq 0; this lead "
              "executed 2 queries before this repeat.")
    exc = GatherDeadEnd(reason=reason, escape="Move on with what this lead captured.")
    agent = RecordingAgent(exc, summary=f"I kept re-sending `{fragment}` and got the same rows.")
    _run_dir, out = dispatch(tmp_path, agent)

    header, summary = split(out)
    assert fragment not in header, \
        "the model's own query text crossed into main's context inside the harness's header"
    assert fragment in summary, (
        "the control cannot see the fragment at all — the assertion above is vacuous. The "
        "model-authored summary is the channel that MAY carry it; only the header may not"
    )


# ----------------------------------------------------------------------------------------
# O5 — the terminator names the original cut; the run-level arms are untouched.
# ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("arm", sorted(DEGRADING_ARMS))
def test_the_terminator_stamped_is_the_original_cut_not_the_summary_turns_outcome(tmp_path, arm):
    """O5 — the stamp answers "what ended this lead", and the answer is the cut, never the
    salvage turn's own fate.

    Driven on the arm where the two genuinely differ: the summary turn here FAILS, and it fails
    with `UnexpectedModelBehavior` — the retry-exhausted arm's own exception. A `finally` that
    re-classified on the way out, or a `terminator` reassigned inside the salvage guard, would
    stamp `retry-exhausted` on a lead the repeat guard killed, and every reader joining
    `session` rows to compare leads would be reading the wrong cause.

    `truncated_by` stays a six-value closed set: nothing here adds a seventh for "summarized"."""
    exc, _template, terminator = DEGRADING_ARMS[arm]
    stamps: list[tuple[str, str]] = []
    agent = RecordingAgent(exc, summary=None)
    dispatch(tmp_path, agent, stamps=stamps)

    assert len(agent.runs) == 2, "the summary turn this test is about never ran"
    assert stamps == [(f"gather:{LEAD}", terminator)], (
        f"the {arm} arm stamped {stamps!r} — the summary turn's outcome displaced the cut's"
    )
    assert terminator in session_store.TRUNCATED_BY_VALUES


@pytest.mark.parametrize("arm", sorted(RUN_LEVEL_ARMS))
def test_the_two_run_level_arms_are_untouched_and_take_no_summary_turn(tmp_path, arm):
    """The census's other half, asserted rather than assumed. `BudgetKill` ends the RUN and
    `RunAborted` is the infra breaker's run-level abort; both must reach
    `run_investigation`'s own catch. Converting either into a header-plus-summary would hide a
    kill behind a measurement string — and on `BudgetKill` it would spend one more model
    request out of a budget that was just declared exhausted.

    They still stamp their terminator on the way past (#826 item 1), which is why they are
    driven here rather than left to the four-arm parametrization to imply."""
    exc, terminator = RUN_LEVEL_ARMS[arm]
    stamps: list[tuple[str, str]] = []
    agent = RecordingAgent(exc)

    with pytest.raises(type(exc)):
        dispatch(tmp_path, agent, stamps=stamps)

    assert len(agent.runs) == 1, f"a {arm} kill was given a summary turn before it propagated"
    assert agent.overrides == [], f"a {arm} kill reached the tool-less override"
    assert stamps == [(f"gather:{LEAD}", terminator)], \
        "a run-level kill left its gather session reading as one that finished"


# ----------------------------------------------------------------------------------------
# O4 — a failed summary turn never worsens the run.
# ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("arm", sorted(DEGRADING_ARMS))
def test_a_failed_summary_turn_degrades_to_the_header_plus_one_fixed_sentence(tmp_path, arm):
    """O4, M6 — the guard spans BOTH the history build and the tool-less run, and swallows
    everything: the lead falls back to today's notice plus one sentence naming the failure, the
    run continues, and the file is still written.

    Without the sentence this is worse than today rather than better: main would receive the
    bare notice and could not tell "nothing was salvageable" from "nobody tried", which is O1's
    stated failure condition. So the fallback is asserted as an EXACT string, with the
    exception's CLASS NAME in it — the class, not its message, because the message is model- or
    provider-authored text and the header's own security clause would then have a second,
    unguarded inlet.

    Nothing is re-raised: `BudgetKill` fires only from the tool-execute hook and `RunAborted`
    only inside the query tool, and no tool executes on a tool-less turn — so there is nothing
    left for this guard to let through. The REAL failure modes (a non-text response, a
    hallucinated tool call) are driven through the real machinery next door; what this pins is
    the shape of the fallback, once."""
    exc, _template, _term = DEGRADING_ARMS[arm]
    header = header_for(arm)
    agent = RecordingAgent(exc, summary=None)
    run_dir, out = dispatch(tmp_path, agent)

    expected = ("A summary turn was attempted and failed (UnexpectedModelBehavior); "
                "no summary is available.")
    assert frame_body(out) == f"{header}\n\n{expected}", (
        "a failed summary turn did not degrade to today's notice plus the fixed sentence:\n"
        f"  {frame_body(out)!r}"
    )
    persisted = run_dir / "gather_summaries" / f"{LEAD}.md"
    assert persisted.is_file(), \
        "a lead that reached the try left no summary file — the salvage path swallowed the record"
    assert persisted.read_text(encoding="utf-8") == out


def test_the_failure_sentence_is_a_module_constant_with_one_hole_for_the_class(tmp_path):
    """M6's data-model clause: the sentence is `SALVAGE_FAILED_SENTENCE`, a constant in
    `tools_gather`, not a literal buried in an `except` block.

    Bound as a constant because it is the one string that tells main "a summary was attempted
    and there is none", and #807's G19 screen and the judge's payload measurer are both
    downstream of it; a second spelling of it is a second vocabulary. The hole is asserted to
    be exactly one, so the class name cannot be concatenated in beside a second interpolation
    the header's security clause has not looked at."""
    from string import Formatter

    fields = [f for _, f, _, _ in Formatter().parse(SALVAGE_FAILED_SENTENCE) if f is not None]
    assert len(fields) == 1, \
        f"the failure sentence has {len(fields)} replacement fields, not one: {fields!r}"
    filled = SALVAGE_FAILED_SENTENCE.format(**{fields[0]: "UnexpectedModelBehavior"}) \
        if fields[0] else SALVAGE_FAILED_SENTENCE.format("UnexpectedModelBehavior")
    assert filled == ("A summary turn was attempted and failed (UnexpectedModelBehavior); "
                      "no summary is available.")


def test_a_gather_agent_with_no_override_seam_still_degrades_rather_than_killing_the_run(
        tmp_path):
    """O4's blunt arm, and the one that keeps this change from breaking every existing caller:
    `_run_gather`'s `gather_factory` is a documented seam a dozen tests build bare fakes
    against (`tests/e2e/test_826_gather_deferred.py`'s terminator table, this module's own
    neighbours before the change). A fake with only `.run` on it has no `.override`, so the
    salvage path raises `AttributeError` inside it.

    That must degrade, not propagate: an exception escaping `_run_gather` unwinds through
    MAIN's own tool call mid-lead, which is the run-ending shape #878 catalogued. The guard is
    `except Exception`, and this is the cheapest real fault that proves it is not
    `except (UnexpectedModelBehavior, UsageLimitExceeded)`."""
    class _BareAgent:
        def __init__(self):
            self.runs = 0

        async def run(self, *a, **kw):
            self.runs += 1
            raise GatherDeadEnd(reason="repeats seq 0.", escape="Move on.")

    agent = _BareAgent()
    run_dir, out = dispatch(tmp_path, agent)

    header, tail = split(out)
    assert header == HEADER_DEAD_END.format(lead=LEAD, reason="repeats seq 0.", escape="Move on.")
    assert "A summary turn was attempted and failed (AttributeError)" in tail, (
        "a gather agent with no override seam either killed the run or was reported as if it "
        f"had summarized: {tail!r}"
    )
    assert (run_dir / "gather_summaries" / f"{LEAD}.md").is_file()


# ----------------------------------------------------------------------------------------
# O7 — the gather model is never shown main's idiom.
# ----------------------------------------------------------------------------------------


def test_no_salvage_constant_carries_mains_incomplete_idiom(tmp_path):
    """O7 / #807 G19, at the two new strings that could leak it.

    G19 is the one #807 decision this change does NOT revise: the gather model must never be
    shown main's disposition vocabulary, because a sub-agent told "treat this lead as
    incomplete" writes its summary to that instruction rather than to what it measured. The
    salvage turn adds two strings gather DOES see — the prompt and the closing tool return —
    and both are checked here, on the constants themselves, so the pin survives a scenario that
    happens not to exercise them.

    Paired with the positive control that makes it non-vacuous: the idiom is in all four
    headers, which is the whole of what main screens on. A "not in" over a word the codebase
    had quietly dropped would otherwise pass everywhere."""
    for name, text in (("SALVAGE_PROMPT", SALVAGE_PROMPT),
                       ("SALVAGE_CLOSED_SENTENCE", SALVAGE_CLOSED_SENTENCE),
                       ("SALVAGE_FAILED_SENTENCE", SALVAGE_FAILED_SENTENCE)):
        assert text.strip(), f"{name} is bound to nothing"
        assert "Treat this lead as incomplete" not in text, \
            f"{name} shows the gather model main's own disposition vocabulary"
        assert "incomplete" not in text.lower(), (
            f"{name} teaches gather a near-miss of the idiom — #807's screen is on the word, "
            "and a summary written to it reads to main as a disposition"
        )

    for header in (HEADER_REQUEST_LIMIT, HEADER_DEAD_END, HEADER_RETRY_EXHAUSTED, HEADER_STORE):
        assert INCOMPLETE_IDIOM in header, \
            "the control is vacuous: main's own notices no longer carry the idiom either"


def test_the_summary_prompt_names_this_leads_obligations_and_closes_the_query_door(tmp_path):
    """M3's content clause, and O3's half that is decidable from text: the prompt the gather
    model is handed must address THIS lead's `what_to_summarize` — the obligations the summary
    was dispatched to establish — and must say that no further queries are possible, so the
    model spends its one turn writing rather than planning a query it cannot issue.

    `what_to_summarize` is asserted item by item against a lead carrying two of them, because
    a prompt that names only the goal, or only the first dimension, leaves the summary
    unanchored to the contract main is going to read it against.

    The prompt is asserted on the MESSAGE HISTORY the agent was actually handed, not on the
    constant: a constant that says the right thing and a run that sends a different string are
    the same green test otherwise."""
    what = ("which hosts dev.dana reached", "whether any container workload was involved")
    agent = RecordingAgent(GatherDeadEnd(reason="repeats seq 0.", escape="Move on."))
    dispatch(tmp_path, agent, what=what)

    history = agent.runs[1]["message_history"]
    sent = "\n".join(
        part.content if isinstance(getattr(part, "content", None), str) else str(
            getattr(part, "content", ""))
        for msg in history for part in getattr(msg, "parts", [])
    )
    for obligation in what:
        assert obligation in sent, \
            f"the summary turn was never told to address {obligation!r} — the lead's own contract"
    # The constant and the wire, bound together: the longest fixed run of text in
    # `SALVAGE_PROMPT` (it may be a template around `what_to_summarize`) must appear verbatim
    # in what was sent. A constant that says the right thing while the run sends a different
    # string is otherwise indistinguishable from a correct implementation.
    from string import Formatter

    literals = [lit for lit, _, _, _ in Formatter().parse(SALVAGE_PROMPT) if lit]
    anchor = max(literals, key=len) if literals else ""
    assert len(anchor) >= 20, \
        f"SALVAGE_PROMPT carries no fixed text long enough to bind the wire to: {SALVAGE_PROMPT!r}"
    assert anchor in sent, \
        "the prompt the model was handed is not the one `SALVAGE_PROMPT` declares"
    assert "no further quer" in sent.lower(), (
        "the summary turn was not told the query door is shut — the model spends its one "
        "reserved request planning a call it cannot make"
    )
    assert INCOMPLETE_IDIOM not in sent, \
        "main's idiom reached the gather model inside the summary prompt"
