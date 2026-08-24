"""Mutation-kill regression tests for `src/seam_harness/transcripts.py`,
`adaptive.py` (transcript/wave/dossier logic), and `recursive.py` `_call`.

Each test in this file exists because a specific, realistic single-line
mutation of the target code survived the pre-existing suite
(`tests/test_transcripts.py`, `tests/test_transcripts_contract.py`, and
`tests/test_adaptive.py`). The docstring on each test names the mutant it
kills; see the mutation-testing report for the full mutant table.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.function import FunctionModel

from seam_harness.models import HarnessSpec, TaskFrame
from seam_harness.recursive import RecursiveHarness
from seam_harness.transcripts import ParticipantTranscript, TranscriptStore



async def _raising_stream_fn(messages, agent_info):
    raise RuntimeError("boom")
    yield  # pragma: no cover - makes this an async generator

def _request(*parts: Any) -> ModelRequest:
    return ModelRequest(parts=list(parts))


def _response(*parts: Any) -> ModelResponse:
    return ModelResponse(parts=list(parts))


def test_prune_stops_exactly_at_budget_not_one_step_past_it() -> None:
    """Kills the `over_budget()` mutant `>` -> `>=`.

    Builds a transcript where removing exactly one ThinkingPart lands
    `estimated_tokens()` precisely on the budget. Correct `>` semantics stop
    pruning the instant the budget is met (a second ThinkingPart in a later
    prunable message must survive untouched); the `>=` mutant keeps treating
    "exactly at budget" as still over budget and prunes one message further
    than necessary.
    """
    store = TranscriptStore()
    store.append(
        "n",
        [
            _request(UserPromptPart(content="U" * 4)),
            _response(ThinkingPart(content="T" * 40)),
            _response(ThinkingPart(content="T" * 40)),
        ],
    )
    store.append(
        "n",
        [
            _request(UserPromptPart(content="R" * 4)),
            _response(TextPart(content="S" * 4)),
        ],
    )
    transcript = store.get("n")
    assert transcript is not None
    assert transcript.estimated_tokens() == 23  # (4 + 40 + 40 + 4 + 4) // 4

    events = store.prune("n", token_budget=13, keep_recent_turns=1)

    thinking_events = [event for event in events if event.kind == "thinking"]
    assert len(thinking_events) == 1  # only the first ThinkingPart was pruned
    assert transcript.estimated_tokens() == 13  # stopped exactly at budget
    # the second prunable ThinkingPart (message index 2) must survive intact
    assert len(transcript.messages[2].parts) == 1
    assert isinstance(transcript.messages[2].parts[0], ThinkingPart)
    assert transcript.messages[2].parts[0].content == "T" * 40


def test_tool_return_stub_is_not_re_stubbed_on_a_second_prune() -> None:
    """Kills dropping the `if _is_stub(content_str): continue` guard in the
    ToolReturnPart-stubbing phase.

    Turn 0 (the transcript's first turn) is prunable but can never be
    dropped outright, so its lone non-immune ToolReturnPart survives every
    prune call as a live, stubbed part.  Turn 1 is protected and large
    enough that the transcript stays over budget forever, forcing a second
    `prune()` call to walk the same ToolReturnPart again.  Correct code
    recognizes the existing `"[pruned "` stub and leaves it alone; the
    mutant re-wraps it, producing a new event and a growing, doubly-stubbed
    string.
    """
    store = TranscriptStore()
    store.append(
        "n",
        [
            _request(
                UserPromptPart(content="U" * 100),
                ToolReturnPart(
                    tool_name="search_tool", content="R" * 100, tool_call_id="r1"
                ),
            )
        ],
    )
    store.append(
        "n",
        [
            _request(UserPromptPart(content="P" * 100)),
            _response(TextPart(content="Q" * 100)),
        ],
    )
    transcript = store.get("n")
    assert transcript is not None

    first_events = store.prune("n", token_budget=1, keep_recent_turns=1)
    assert any(event.kind == "tool_return" for event in first_events)
    stubbed_content = transcript.messages[0].parts[1].content
    assert stubbed_content.startswith("[pruned tool result: search_tool")

    second_events = store.prune("n", token_budget=1, keep_recent_turns=1)

    assert second_events == []
    assert transcript.messages[0].parts[1].content == stubbed_content


class _DummyDeps(BaseModel):
    note: str = "hello"


def test_call_failed_attempt_appends_only_the_new_messages_not_the_seeded_history(
    tmp_path,
) -> None:
    """Kills `captured[transcript_messages_before:]` -> `captured[:]` in
    `RecursiveHarness._call`.

    `capture_run_messages()` seeds its list from the incoming
    `message_history` before adding this attempt's new messages (verified
    against pydantic-ai's `UserPromptNode.run`, which does
    `messages[:] = _clean_message_history(ctx.state.message_history)`). So
    when a transcript already carries prior-turn history and the call then
    fails, slicing from `transcript_messages_before` is what keeps the
    already-seeded history from being re-appended to the transcript a
    second time. The pre-existing tests only exercise this path with an
    empty transcript, where the slice is a no-op either way.
    """
    spec = HarnessSpec(
        frame=TaskFrame(
            title="Failed-attempt slice",
            task="Exercise _call's failed-attempt transcript slicing.",
            product_intent="Confirm seeded history is not re-appended.",
        )
    )
    harness = RecursiveHarness(spec, runs_dir=tmp_path / "runs")
    agent: Agent[_DummyDeps, str] = Agent(deps_type=_DummyDeps, output_type=str)

    def raising_fn(messages: list[Any], info: Any) -> ModelResponse:
        raise RuntimeError("boom")

    transcript = ParticipantTranscript(node_id="n1")
    transcript.messages = [
        _request(UserPromptPart(content="seed prompt")),
        _response(TextPart(content="seed answer")),
    ]
    transcript.turn_offsets = [0]

    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(
            harness._call(
                agent,
                _DummyDeps(),
                role="probe_role",
                model_name=FunctionModel(raising_fn, stream_function=_raising_stream_fn),
                max_tokens=100,
                transcript=transcript,
                prompt="new attempt",
            )
        )

    # exactly one new turn was recorded (the failed attempt), and the seeded
    # history was NOT duplicated into it. (The streaming path may capture an
    # extra interrupted-response marker alongside the request, so pin the
    # absence of duplication and the new prompt's presence, not an exact
    # message count.)
    assert transcript.turn_offsets == [0, 2]
    assert len(transcript.messages) >= 3
    assert transcript.messages[0].parts[0].content == "seed prompt"
    assert transcript.messages[1].parts[0].content == "seed answer"
    new_contents = [
        str(getattr(part, "content", ""))
        for message in transcript.messages[2:]
        for part in message.parts
    ]
    assert any("new attempt" in content for content in new_contents)
    assert not any("seed prompt" in content for content in new_contents)
    assert not any("seed answer" in content for content in new_contents)
