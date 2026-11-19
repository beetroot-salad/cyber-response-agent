"""#1579: the stage runner's typed output (design r3 "Flow", P5, O1/O2/O4/O5). `run_stage(output=)`
asks through an output tool, validates inside the call, re-asks a refused reply with its reason
(O1), bounds the call at 1 + N requests whatever the caller's `request_limit` (P5), keeps every
request in the call's one trace (O5), never parses text (O4), and ends in `Accepted`,
`ReplyUnusable` (the model could not produce a usable reply) or `RunUnprocessable` (anything
else, a host error in the check included). Driven with `ScriptedCalls` as `make_model`."""
from __future__ import annotations

import asyncio
import itertools
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import ModelRetry  # noqa: E402
from pydantic_ai.messages import ModelResponse, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.investigation import observe  # noqa: E402
from defender.learning._pydantic_stage import run_stage  # noqa: E402
from defender.learning.branch.questioner import QuestionerDeps  # noqa: E402
from defender.learning.core.config import RunUnprocessable, StageContext, StageWiring  # noqa: E402
from defender.providers import BuiltModel  # noqa: E402
from defender.tests.support.learning.core import _typed_output1579 as TY  # noqa: E402


def _only_yes(mapping) -> None:
    word = mapping.get("word")
    if word != "yes":
        raise ModelRetry(f"word={word!r} is not 'yes'")


def _stage(tmp_path: Path, make_model, *, output="default", label: str = "q:t",
           timeout: int = 30, request_limit: int = 1):
    """`run_stage` on the questioner stage with the seams' own ctx (`request_limit=1`): the
    runner alone derives a typed call's 1 + N bound. Returns (result, trace path)."""
    prompt = tmp_path / "role.md"
    prompt.write_text("Answer.\n", encoding="utf-8")
    run_dir = tmp_path / "lrd"
    run_dir.mkdir(exist_ok=True)
    wiring = StageWiring(prompt_path=prompt, model="kimi-k3", effort="none",
                         trace_name=f"{label.replace(':', '_')}_trace.jsonl", label=label)
    extra = {} if output is None else {
        "output": TY.typed_output(_only_yes) if output == "default" else output}
    with override_allow_model_requests(False):
        out = run_stage(stage="questioner", wiring=wiring,
                        ctx=StageContext(learning_run_dir=run_dir, user="pick a word",
                                         request_limit=request_limit, wall_clock_timeout=timeout),
                        deps=QuestionerDeps(), make_model=make_model, **extra)
    return out, observe.stage_trace_path(run_dir, wiring.trace_name)


def _causes(exc: BaseException):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def test_control_a_text_stage_is_unchanged(tmp_path):
    """Base-green control: no `output=`, one text reply, one request, a str back."""
    calls = TY.ScriptedCalls(["plain text"])
    out, _ = _stage(tmp_path, calls, output=None)
    assert out == "plain text"
    assert isinstance(out, str)
    assert calls.request_counts() == [1]


def test_o1_a_refused_reply_is_re_asked_in_the_same_call_with_its_reason(tmp_path):
    calls = TY.ScriptedCalls([{"word": "no"}, {"word": "yes"}])

    out, _ = _stage(tmp_path, calls)

    assert out == ({"word": "yes"}, 2), "Accepted(the corrected mapping, 2 requests)"
    assert isinstance(out, TY.accepted())
    assert calls.request_counts() == [2], "one call with two requests, though ctx.request_limit is 1"
    assert any("word='no' is not 'yes'" in r for r in calls.reasons_sent(0)), (
        f"the model was not told why: {calls.reasons_sent(0)}")
    assert calls.offered[0][0].name == "answer", "the first request offers the output tool"


def test_o4_a_bare_yaml_text_answer_is_never_used_it_is_re_asked(tmp_path):
    """Text that would parse to a valid reply is not one: it goes back with "call the tool",
    and the tool answer is the result (the text had a different word, so a parse would show)."""
    calls = TY.ScriptedCalls(["word: wrong\n", {"word": "yes"}])

    out, _ = _stage(tmp_path, calls)

    assert out == ({"word": "yes"}, 2)
    assert calls.request_counts() == [2]
    assert any("call the tool" in r.lower() for r in calls.reasons_sent(0)), calls.reasons_sent(0)


def test_o4_a_text_answer_that_is_a_valid_reply_is_not_accepted(tmp_path):
    """The accepted-if-parsed variant: text `word: yes` would pass the check if parsed. It must
    still be re-asked; the call ends only on a tool answer."""
    calls = TY.ScriptedCalls(["word: yes\n", "word: yes\n", "word: yes\n"])

    with pytest.raises(TY.reply_unusable()):
        _stage(tmp_path, calls)
    assert calls.request_counts() == [TY.MAX_REQUESTS]


def test_o5_every_request_is_one_response_record_in_the_calls_one_trace(tmp_path):
    calls = TY.ScriptedCalls([{"word": "no"}, {"word": "no"}, {"word": "yes"}])

    out, trace = _stage(tmp_path, calls)

    assert out == ({"word": "yes"}, 3)
    assert TY.response_records(trace) == 3


def test_o5_the_failed_attempts_of_an_exhausted_call_stay_in_the_trace(tmp_path):
    calls = TY.ScriptedCalls([{"word": "a"}, {"word": "b"}, {"word": "c"}])
    with pytest.raises(TY.reply_unusable()):
        _stage(tmp_path, calls, label="q:o5x")
    trace = observe.stage_trace_path(tmp_path / "lrd", "q_o5x_trace.jsonl")
    assert TY.response_records(trace) == TY.MAX_REQUESTS


# ---------------------------------------------------------------------------------------------
# P5, the class case: every order of the five bad kinds over the whole 1 + N budget.
# ---------------------------------------------------------------------------------------------

def _bad_kinds():
    return {
        "check": None,  # a dict refused by the check; its reason is scripted per attempt
        "prose": "this is just prose, no tool call",
        "badjson": TY.BadJSON(),
        "unknown-tool": TY.UnknownTool({"word": "yes"}),
        "empty": "",
    }


_WRAP_PREFIX = "Validation feedback:\n"
_WRAP_SUFFIX = "\n\nFix the errors and try again."


def _framework_reason(tmp_path: Path, kind: str) -> str:
    """The retry text the framework sends the model for a non-check bad kind, as the harness
    observes it (what request 2 carried back after a first attempt of that kind), minus the
    framework's own wrapper lines, which the exhaustion's reason may or may not carry."""
    calls = TY.ScriptedCalls([_bad_kinds()[kind], {"word": "yes"}])
    out, _ = _stage(tmp_path, calls, label=f"q:cal-{kind}")
    assert out == ({"word": "yes"}, 2)
    (reason,) = calls.reasons_sent(0)
    return reason.removesuffix(_WRAP_SUFFIX).removeprefix(_WRAP_PREFIX)


def _ending_failures(order, raised, expected: list[str], calls: TY.ScriptedCalls, label: str) -> list[str]:
    last = expected[-1]
    out: list[str] = []
    if raised.requests != TY.MAX_REQUESTS:
        out.append(f"{order}: requests={raised.requests}")
    if last not in raised.reason or last not in str(raised) or label not in str(raised):
        out.append(f"{order}: reason {raised.reason!r} / str {str(raised)!r} lack {last!r} or the call's name")
    stale = [e for e in expected[:-1] if e != last and e in raised.reason]
    if stale:
        out.append(f"{order}: the reason carries an earlier attempt's text {stale!r}, not only the last's")
    sent = calls.reasons_sent(0)
    if len(sent) != len(expected) - 1 or any(e not in s for e, s in zip(expected, sent, strict=False)):
        out.append(f"{order}: reasons sent {sent!r}, wanted {expected[:-1]!r}")
    return out


def _order_failures(tmp_path: Path, n: int, order: tuple[str, ...], framework: dict[str, str]) -> list[str]:
    kinds = _bad_kinds()
    label = f"q:p5-{n}"
    script, expected = [], []
    for pos, kind in enumerate(order, 1):
        if kind == "check":
            script.append({"word": f"bad{pos}"})
            expected.append(f"word='bad{pos}' is not 'yes'")
        else:
            script.append(kinds[kind])
            expected.append(framework[kind])
    calls = TY.ScriptedCalls([*script, {"word": "yes"}])  # a 4th reply must never be asked for
    out: list[str] = []
    try:
        _stage(tmp_path, calls, label=label)
    except TY.reply_unusable() as raised:
        out += _ending_failures(order, raised, expected, calls, label)
    except Exception as other:  # noqa: BLE001 — any other ending is the defect under test
        out.append(f"{order}: ended {type(other).__name__}: {other}")
    else:
        out.append(f"{order}: the call was accepted")
    if calls.request_counts() != [TY.MAX_REQUESTS]:
        out.append(f"{order}: requests sent {calls.request_counts()}")
    return out


def test_p5_any_order_of_the_five_bad_kinds_ends_reply_unusable_with_the_last_reason(tmp_path):
    kinds = _bad_kinds()
    framework = {k: _framework_reason(tmp_path, k) for k in kinds if k != "check"}
    failures = [f for n, order in enumerate(itertools.product(kinds, repeat=TY.MAX_REQUESTS))
                for f in _order_failures(tmp_path, n, order, framework)]
    assert not failures, "\n".join(failures[:12]) + f"\n({len(failures)} failures)"


def test_p5_reply_unusable_is_not_a_run_unprocessable(tmp_path):
    calls = TY.ScriptedCalls([{"word": "a"}, "prose", {"word": "c"}])
    with pytest.raises(TY.reply_unusable()) as raised:
        _stage(tmp_path, calls)
    assert not isinstance(raised.value, RunUnprocessable)


def test_p5_a_host_exception_in_the_check_is_run_unprocessable_after_one_request(tmp_path):
    def broken(_mapping):
        raise TypeError("host bug")

    calls = TY.ScriptedCalls([{"word": "yes"}, {"word": "yes"}])
    with pytest.raises(RunUnprocessable) as raised:
        _stage(tmp_path, calls, output=TY.typed_output(broken))
    assert not isinstance(raised.value, TY.reply_unusable())
    assert raised.value.requests == 1
    assert calls.request_counts() == [1], "a host bug is not re-asked"


def test_p5_a_host_exception_after_a_refusal_counts_both_requests(tmp_path):
    def broken_on_second(mapping):
        if mapping["word"] == "no":
            raise ModelRetry("first refused")
        raise TypeError("host bug")

    calls = TY.ScriptedCalls([{"word": "no"}, {"word": "yes"}, {"word": "yes"}])
    with pytest.raises(RunUnprocessable) as raised:
        _stage(tmp_path, calls, output=TY.typed_output(broken_on_second))
    assert raised.value.requests == 2
    assert calls.request_counts() == [2]


def test_p5_a_transport_fault_on_request_one_is_run_unprocessable_with_the_413_on_its_chain(tmp_path):
    calls = TY.ScriptedCalls([TY.http_413()])
    with pytest.raises(RunUnprocessable) as raised:
        _stage(tmp_path, calls)
    assert not isinstance(raised.value, TY.reply_unusable())
    assert raised.value.requests == 1
    assert any(getattr(c, "status_code", None) == 413 for c in _causes(raised.value))


def test_p5_the_same_fault_on_a_re_ask_counts_two_requests(tmp_path):
    calls = TY.ScriptedCalls([{"word": "no"}, TY.http_413()])
    with pytest.raises(RunUnprocessable) as raised:
        _stage(tmp_path, calls)
    assert raised.value.requests == 2
    assert any(getattr(c, "status_code", None) == 413 for c in _causes(raised.value))


# ---------------------------------------------------------------------------------------------
# Wall clock: a typed call's bound is (1 + N) x the stage's single-request timeout.
# ---------------------------------------------------------------------------------------------

def _slow_model(per_request: float):
    """A `make_model` whose every request takes `per_request` seconds (cancellable, so a
    wall-clock bound ends it) and answers a refused reply, so the call keeps asking."""
    async def fn(_messages, info):
        await asyncio.sleep(per_request)
        return ModelResponse(parts=[ToolCallPart(tool_name=info.output_tools[0].name,
                                                 args={"word": "no"})])
    return lambda _name, _effort: BuiltModel(FunctionModel(fn), None)


def test_wall_clock_a_typed_call_may_run_past_one_timeout_up_to_three(tmp_path):
    """3 requests x 0.6 s = 1.8 s: past one 1 s timeout, inside (1 + N) x 1 s. The call must run
    to exhaustion (ReplyUnusable), not be cut off at 1 s. (`wall_clock_timeout` is whole seconds.)"""
    with pytest.raises(TY.reply_unusable()):
        _stage(tmp_path, _slow_model(0.6), timeout=1)


def test_wall_clock_control_the_typed_bound_is_finite_three_timeouts_not_more(tmp_path):
    """Positive control: 1.2 s requests (each over the 1 s timeout) get cut at 3 s, during the
    third request: RunUnprocessable (a timeout), 3 requests sent, not one (so the bound is
    beyond 1x) and not an unbounded call."""
    with pytest.raises(RunUnprocessable) as raised:
        _stage(tmp_path, _slow_model(1.2), timeout=1, label="q:slow")
    assert not isinstance(raised.value, TY.reply_unusable())
    assert raised.value.requests == TY.MAX_REQUESTS


def test_wall_clock_control_a_text_stage_keeps_the_single_request_timeout(tmp_path):
    """A text stage's 1.5 s request is cut at its 1 s timeout: the (1 + N) scaling is for typed
    calls only."""
    async def fn(_messages, _info):
        await asyncio.sleep(1.5)
        return ModelResponse(parts=[])

    with pytest.raises(RunUnprocessable):
        _stage(tmp_path, lambda _n, _e: BuiltModel(FunctionModel(fn), None), output=None,
               timeout=1, label="q:text-slow")
