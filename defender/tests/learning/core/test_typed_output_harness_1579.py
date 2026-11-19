"""#1579 harness self-test: `ScriptedCalls` drives a bare pydantic_ai agent with the design's
output union exactly as the framework answers each reply kind (R11; base-green)."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent, ModelRetry, TextOutput, ToolOutput  # noqa: E402
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded  # noqa: E402
from pydantic_ai.usage import UsageLimits  # noqa: E402

from defender.tests.support.learning.core import _typed_output1579 as TY  # noqa: E402


def _check(**args):
    if args.get("word") != "yes":
        raise ModelRetry(f"word={args.get('word')!r} is not 'yes'")
    return args


def _text(_text: str):
    raise ModelRetry("call the tool")


def _run(*replies):
    calls = TY.ScriptedCalls(list(replies))
    built = calls("scripted", None)
    agent = Agent(built.model, output_type=[ToolOutput(_check, name="answer"),
                                            TextOutput(_text)])
    out = agent.run_sync("pick", retries={"output": TY.N},
                         usage_limits=UsageLimits(request_limit=TY.MAX_REQUESTS))
    return out.output, calls


def _ended(*replies):
    calls = TY.ScriptedCalls(list(replies))
    agent = Agent(calls("scripted", None).model,
                  output_type=[ToolOutput(_check, name="answer"), TextOutput(_text)])
    with pytest.raises((UnexpectedModelBehavior, UsageLimitExceeded)) as raised:
        agent.run_sync("pick", retries={"output": TY.N},
                       usage_limits=UsageLimits(request_limit=TY.MAX_REQUESTS))
    return raised.value, calls


def test_a_dict_is_an_output_tool_call_and_its_refusal_reason_reaches_the_model():
    out, calls = _run({"word": "no"}, {"word": "yes"})
    assert out == {"word": "yes"}
    assert calls.request_counts() == [2]
    assert any("'no' is not 'yes'" in r for r in calls.reasons_sent(0))
    assert calls.offered[0][0].name == "answer"


@pytest.mark.parametrize("bad", [TY.BadJSON(), TY.UnknownTool({"word": "yes"}), "prose", ""],
                         ids=["bad-json", "unknown-tool", "prose", "empty-text"])
def test_every_scripted_bad_kind_is_refused_with_a_retry_prompt(bad):
    out, calls = _run(bad, {"word": "yes"})
    assert out == {"word": "yes"}
    assert calls.request_counts() == [2]
    assert calls.reasons_sent(0), f"{bad!r} was not sent back with a reason"


def test_the_script_ends_a_run_at_the_framework_bound():
    failure, calls = _ended({"word": "a"}, {"word": "b"}, {"word": "c"}, {"word": "yes"})
    assert calls.request_counts() == [TY.MAX_REQUESTS]
    assert "'c' is not 'yes'" in repr(failure.__cause__), "C14: the last reason is the cause"


def test_a_scripted_exception_is_raised_from_the_model():
    from pydantic_ai.exceptions import ModelHTTPError

    with pytest.raises(ModelHTTPError) as raised:
        _run(TY.http_413())
    assert raised.value.status_code == 413
