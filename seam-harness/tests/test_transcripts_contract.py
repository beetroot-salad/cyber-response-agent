"""Contract tests for stateful participant transcripts.

This file targets promises the spec makes that the implementer's own
`tests/test_transcripts.py` does not pin down: exact pruning boundaries,
idempotency across a serialize/restore round trip, per-node isolation under
concurrency, turn-dossier scoping (recent actions, retry feedback), wave-
result truncation and push-disabled behavior, failed-attempt round-tripping,
and resume edge cases (latest-by-sequence selection, no-transcripts
checkpoints, and that a restored transcript actually feeds the next call).

Nothing here duplicates an assertion already made in test_transcripts.py.
"""

from __future__ import annotations

import asyncio
import copy
import json
from typing import Any

import pytest
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.messages import (
    ModelMessagesTypeAdapter,
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.function import FunctionModel

from seam_harness.adaptive import AdaptiveHarness, _ParticipantOutcome
from seam_harness.adaptive_models import (
    AdaptiveDeps,
    AdaptiveFinalArtifact,
    DelegateAction,
    ParticipantTurn,
)
from seam_harness.journal import RunJournal, digest
from seam_harness.models import HarnessSpec, TaskFrame
from seam_harness.orchestrator import Execution
from seam_harness.recursive import RecursiveHarness, _slug
from seam_harness.recursive_models import KnowledgeAnswer, RecursivePolicy
from seam_harness.transcripts import ParticipantTranscript, TranscriptStore, _part_chars


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------



async def _raising_stream_fn(messages, agent_info):
    raise RuntimeError("boom")
    yield  # pragma: no cover - makes this an async generator

def _big(label: str, n: int = 200) -> str:
    return f"{label}:" + ("x" * n)


def _request(*parts: Any) -> ModelRequest:
    return ModelRequest(parts=list(parts))


def _response(*parts: Any) -> ModelResponse:
    return ModelResponse(parts=list(parts))


def _seed_node(
    store: TranscriptStore,
    node_id: str,
    *,
    turns: int = 4,
    output_tool: str = "participant_turn",
    size: int = 150,
) -> None:
    """Append `turns` turns to `node_id`, each carrying one of every
    prunable/protected part kind."""
    for i in range(turns):
        request = _request(
            UserPromptPart(content=_big(f"user{i}", size))
            if i == 0
            else ToolReturnPart(
                tool_name="search_tool",
                content=_big(f"toolret{i}", size),
                tool_call_id=f"ret-{i}",
            ),
            ToolReturnPart(
                tool_name=output_tool,
                content=_big(f"ack{i}", size),
                tool_call_id=f"ack-{i}",
            ),
        )
        response = _response(
            ThinkingPart(content=_big(f"thinking{i}", size)),
            TextPart(content=_big(f"text{i}", size)),
            ToolCallPart(
                tool_name="search_tool",
                args={"q": _big(f"args{i}", size)},
                tool_call_id=f"call-{i}",
            ),
        )
        store.append(node_id, [request, response])


def _seeded_store(
    node_id: str = "n",
    turns: int = 4,
    output_tool: str = "participant_turn",
    size: int = 150,
) -> TranscriptStore:
    store = TranscriptStore()
    _seed_node(store, node_id, turns=turns, output_tool=output_tool, size=size)
    return store


def _delegate_action_dict(
    local_id: str, *, target_question_ids: list[str] | None = None
) -> dict[str, Any]:
    return {
        "kind": "delegate",
        "wave_rationale": f"Delegate a single bounded child ({local_id}).",
        "delegations": [
            {
                "local_id": local_id,
                "question": f"What supports {local_id}?",
                "rationale": "Ground the parent synthesis.",
                "acceptance_condition": "Return one bounded observation.",
                "target_question_ids": target_question_ids or ["question:root"],
                "demand_ids": [],
                "tags": [],
                "independence_account": "It is the only delegation in this wave.",
            }
        ],
    }


def _finish_own_question_dict(node_id: str) -> dict[str, Any]:
    own_question = f"question:{node_id}"
    return {
        "account": "Publish the local posterior and finish.",
        "contribution": {
            "body": f"Posterior answer for {node_id}.",
            "responds_to": [
                {
                    "question_id": own_question,
                    "effect": "resolves",
                    "scope_or_reason": "The bounded mandate is answered.",
                }
            ],
            "new_questions": [],
            "links": [],
            "seam_signal": None,
        },
        "action": {
            "kind": "finish",
            "answer_ids": ["self"],
            "rationale": "The local question is answered.",
            "unresolved_question_ids": [],
        },
    }


# ---------------------------------------------------------------------------
# Pruning boundary precision
# ---------------------------------------------------------------------------


def test_prune_boundary_protects_exactly_keep_recent_turns() -> None:
    """n_turns == keep_recent_turns + 1: exactly one (the oldest) turn is
    unprotected. This isolates the turn-count boundary itself, on both
    sides, from the multi-turn drop mechanics exercised elsewhere."""
    store = _seeded_store(turns=3, size=150)
    transcript = store.get("n")
    assert transcript is not None
    keep = 2
    n_turns = transcript.turns()
    assert n_turns == keep + 1
    protected_start = transcript.turn_offsets[n_turns - keep]
    expected_protected = copy.deepcopy(transcript.messages[protected_start:])

    events = store.prune("n", token_budget=1, keep_recent_turns=keep)

    # side 1: the protected (last `keep`) turns are byte-identical
    assert transcript.messages[transcript.turn_offsets[-keep] :] == expected_protected
    assert all(event.turn <= n_turns - keep for event in events)

    # side 2: the single unprotected turn WAS touched, but never dropped
    # outright -- it holds the transcript's first user message
    assert events
    assert all(event.kind != "dropped_turn" for event in events)
    assert {event.turn for event in events} == {n_turns - keep}
    first_message = transcript.messages[0]
    assert isinstance(first_message.parts[0], UserPromptPart)
    assert first_message.parts[0].content.startswith("user0")


def test_prune_is_a_noop_when_keep_recent_turns_covers_every_turn() -> None:
    store = _seeded_store(turns=4, size=150)
    transcript = store.get("n")
    assert transcript is not None
    snapshot = copy.deepcopy(transcript.messages)

    events_equal = store.prune("n", token_budget=1, keep_recent_turns=4)
    events_over = store.prune("n", token_budget=1, keep_recent_turns=7)

    assert events_equal == []
    assert events_over == []
    assert transcript.messages == snapshot
    assert transcript.turn_offsets == [0, 2, 4, 6]
    assert transcript.pruned_events == []


def test_prune_is_a_noop_when_the_budget_is_already_exactly_satisfied() -> None:
    store = _seeded_store(turns=4, size=150)
    transcript = store.get("n")
    assert transcript is not None
    exact_budget = transcript.estimated_tokens()
    snapshot = copy.deepcopy(transcript.messages)

    events = store.prune("n", token_budget=exact_budget, keep_recent_turns=1)

    assert events == []
    assert transcript.messages == snapshot
    assert transcript.pruned_events == []

    # one token under: now there is real work, proving the guard is `<=`
    events_over = store.prune("n", token_budget=exact_budget - 1, keep_recent_turns=1)
    assert events_over


def test_prune_when_protected_window_alone_exceeds_budget_converges_without_looping() -> (
    None
):
    """When the protected recent window alone already costs more than the
    budget, pruning cannot succeed. It must still be deterministic: touch
    whatever is prunable (the lone unprotected turn), never the protected
    turns or the first turn, converge without hanging, and stay idempotent
    on a repeat call even though the budget is never actually satisfied."""
    store = _seeded_store(turns=4, size=150)
    transcript = store.get("n")
    assert transcript is not None
    keep = 3  # protects 3 of 4 turns; only the oldest turn is prunable
    protected_start = transcript.turn_offsets[-keep]
    protected_chars = sum(
        _part_chars(part)
        for message in transcript.messages[protected_start:]
        for part in message.parts
    )
    budget = protected_chars // 4 // 2  # well under the protected window alone

    first_events = store.prune("n", token_budget=budget, keep_recent_turns=keep)

    assert first_events  # the one prunable (oldest) turn was stubbed
    assert all(event.kind != "dropped_turn" for event in first_events)
    assert transcript.turns() == 4  # the first turn is never dropped outright
    assert transcript.estimated_tokens() > budget  # documented: unsatisfiable

    tokens_before_second = transcript.estimated_tokens()
    second_events = store.prune("n", token_budget=budget, keep_recent_turns=keep)
    assert second_events == []
    assert transcript.estimated_tokens() == tokens_before_second


# ---------------------------------------------------------------------------
# Prune -> serialize -> restore -> prune again
# ---------------------------------------------------------------------------


def test_prune_serialize_restore_prune_again_is_idempotent() -> None:
    store = _seeded_store(turns=3, size=150)
    store.prune("n", token_budget=1, keep_recent_turns=1)
    transcript = store.get("n")
    assert transcript is not None
    tokens_after_first_prune = transcript.estimated_tokens()
    events_after_first_prune = list(transcript.pruned_events)
    assert events_after_first_prune  # the first prune did real work

    payload = store.serialize("n")
    json.dumps(payload)  # must be plain JSON-loadable

    restored_store = TranscriptStore()
    restored_store.restore("n", payload)
    restored_transcript = restored_store.get("n")
    assert restored_transcript is not None
    assert restored_transcript.estimated_tokens() == tokens_after_first_prune

    second_events = restored_store.prune("n", token_budget=1, keep_recent_turns=1)

    assert second_events == []  # idempotent across the round trip: no double-stubbing
    assert restored_transcript.estimated_tokens() == tokens_after_first_prune
    assert restored_transcript.messages == transcript.messages
    assert restored_transcript.pruned_events == events_after_first_prune


# ---------------------------------------------------------------------------
# Multi-node isolation
# ---------------------------------------------------------------------------


def test_append_and_prune_never_touch_a_different_node() -> None:
    store = TranscriptStore()
    _seed_node(store, "node-a", turns=4, size=150)
    _seed_node(store, "node-b", turns=4, size=150)

    node_b = store.get("node-b")
    assert node_b is not None
    snapshot_b = copy.deepcopy(node_b.messages)
    offsets_b = list(node_b.turn_offsets)

    store.append(
        "node-a",
        [_request(UserPromptPart(content="extra-a")), _response(TextPart(content="x"))],
    )
    store.prune("node-a", token_budget=1, keep_recent_turns=1)

    assert node_b.messages == snapshot_b
    assert node_b.turn_offsets == offsets_b
    assert node_b.pruned_events == []


def test_concurrent_appends_on_different_nodes_do_not_corrupt_turn_offsets() -> None:
    store = TranscriptStore()

    async def _append_many(node_id: str, count: int) -> None:
        for i in range(count):
            store.append(
                node_id,
                [
                    _request(UserPromptPart(content=f"{node_id}-req-{i}")),
                    _response(TextPart(content=f"{node_id}-resp-{i}")),
                ],
            )
            await asyncio.sleep(0)  # interleave with the other node's coroutine

    async def _run() -> None:
        await asyncio.gather(_append_many("child-a", 15), _append_many("child-b", 15))

    asyncio.run(_run())

    for node_id in ("child-a", "child-b"):
        transcript = store.get(node_id)
        assert transcript is not None
        assert transcript.turn_offsets == [i * 2 for i in range(15)]
        assert len(transcript.messages) == 30
        for message in transcript.messages:
            for part in message.parts:
                content = getattr(part, "content", "")
                assert node_id in content

    child_a = store.get("child-a")
    child_b = store.get("child-b")
    assert child_a is not None and child_b is not None
    assert child_a.messages is not child_b.messages


# ---------------------------------------------------------------------------
# Output-tool return immunity
# ---------------------------------------------------------------------------


def test_prune_never_stubs_either_output_tool_return_even_in_the_same_message() -> None:
    store = TranscriptStore()
    original_normal = _big("normal-result", 300)
    original_participant = _big("participant-ack", 300)
    original_final = _big("final-ack", 300)
    turn1_request = _request(
        UserPromptPart(content=_big("user0", 300)),
        ToolReturnPart(tool_name="search_tool", content=original_normal, tool_call_id="r1"),
        ToolReturnPart(
            tool_name="participant_turn", content=original_participant, tool_call_id="r2"
        ),
        ToolReturnPart(
            tool_name="adaptive_final_artifact", content=original_final, tool_call_id="r3"
        ),
    )
    turn1_response = _response(TextPart(content=_big("text0", 300)))
    store.append("n", [turn1_request, turn1_response])
    # a second (protected) turn, so turn 1 is prunable
    store.append(
        "n",
        [
            _request(UserPromptPart(content=_big("user1", 300))),
            _response(TextPart(content=_big("text1", 300))),
        ],
    )

    store.prune("n", token_budget=1, keep_recent_turns=1)

    transcript = store.get("n")
    assert transcript is not None
    parts_by_tool = {
        part.tool_name: part
        for message in transcript.messages
        for part in message.parts
        if isinstance(part, ToolReturnPart)
    }
    assert str(parts_by_tool["search_tool"].content).startswith("[pruned ")
    assert parts_by_tool["participant_turn"].content == original_participant
    assert parts_by_tool["adaptive_final_artifact"].content == original_final


# ---------------------------------------------------------------------------
# DEFECT: dropped_turn events mislabel the turn they removed
# ---------------------------------------------------------------------------


def test_prune_dropped_turn_events_record_distinct_correct_turn_numbers() -> None:
    store = _seeded_store(turns=5, size=150)
    transcript = store.get("n")
    assert transcript is not None

    events = store.prune("n", token_budget=1, keep_recent_turns=2)
    dropped = [event for event in events if event.kind == "dropped_turn"]

    # two whole turns (originally turn #2 and turn #3) are dropped in this
    # one prune() call; each PrunedEvent should identify which turn it
    # actually removed.
    assert len(dropped) == 2
    assert sorted(event.turn for event in dropped) == [2, 3]


# ---------------------------------------------------------------------------
# RecursiveHarness._call: failed attempt round-trips into the next attempt
# ---------------------------------------------------------------------------


class _DummyDeps(BaseModel):
    note: str = "hello"


def _minimal_spec() -> HarnessSpec:
    return HarnessSpec(
        frame=TaskFrame(
            title="Transcript contract probe",
            task="Exercise _call's transcript plumbing under failure.",
            product_intent="Confirm error round-trips and history handoff.",
        )
    )


def test_call_failed_attempt_round_trips_and_feeds_the_next_attempt(tmp_path) -> None:
    harness = RecursiveHarness(_minimal_spec(), runs_dir=tmp_path / "runs")
    agent: Agent[_DummyDeps, str] = Agent(deps_type=_DummyDeps, output_type=str)

    def raising_fn(messages: list[Any], info: Any) -> ModelResponse:
        raise RuntimeError("boom")

    transcript = ParticipantTranscript(node_id="n1")

    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(
            harness._call(
                agent,
                _DummyDeps(),
                role="probe_role",
                model_name=FunctionModel(raising_fn, stream_function=_raising_stream_fn),
                max_tokens=100,
                transcript=transcript,
                prompt="attempt one",
            )
        )

    failed_message_count = len(transcript.messages)
    assert failed_message_count >= 1

    error_files = sorted((harness.journal.root / "02-call-errors").glob("*.json"))
    assert len(error_files) == 1
    payload = json.loads(error_files[0].read_text(encoding="utf-8"))

    # the persisted messages are a genuine ModelMessage list: they round-trip
    # through the same adapter used to write them, without loss.
    round_tripped = ModelMessagesTypeAdapter.validate_python(payload["messages"])
    assert len(round_tripped) == len(payload["messages"]) == failed_message_count
    re_dumped = ModelMessagesTypeAdapter.dump_python(round_tripped, mode="json")
    assert re_dumped == payload["messages"]
    assert isinstance(round_tripped[0], ModelRequest)

    # the failed attempt's messages are real history: the NEXT call on the
    # same transcript sees their content. (pydantic-ai folds a fresh prompt
    # into a still-open, response-less request rather than always appending
    # a distinct message, so assert on content survival, not list length.)
    seen_message_batches: list[list[Any]] = []

    def recording_ok_fn(messages: list[Any], info: Any) -> ModelResponse:
        seen_message_batches.append(messages)
        return ModelResponse(parts=[TextPart(content="recovered")])

    async def recording_ok_stream_fn(messages, info):
        seen_message_batches.append(messages)
        yield "recovered"

    execution = asyncio.run(
        harness._call(
            agent,
            _DummyDeps(),
            role="probe_role",
            model_name=FunctionModel(
                recording_ok_fn, stream_function=recording_ok_stream_fn
            ),
            max_tokens=100,
            transcript=transcript,
            prompt="attempt two",
        )
    )
    assert execution.output == "recovered"
    assert len(seen_message_batches) == 1
    seen_dump = json.dumps(
        ModelMessagesTypeAdapter.dump_python(seen_message_batches[0], mode="json")
    )
    assert "attempt one" in seen_dump  # the failed attempt's own prompt
    assert "attempt two" in seen_dump  # this attempt's new prompt


# ---------------------------------------------------------------------------
# Turn dossier: recent-actions scoping and same-sequence retry feedback
# ---------------------------------------------------------------------------


class RecentActionsAndFeedbackHarness(AdaptiveHarness):
    """Scripts every participant turn directly (no model), so the real
    `_choose_turn` / `_run_participant` / `_delegate` control flow -- action
    sequencing, retry/feedback bookkeeping, and turn-dossier construction --
    runs unmodified. Root: turn 1 delegates leaf-a; turn 2's first attempt is
    a deliberately invalid contribution (forcing a rejection), its retry
    delegates leaf-b; turn 3 finishes."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.calls: list[dict[str, Any]] = []
        self._call_count_by_node: dict[str, int] = {}

    async def _bounded_call(
        self,
        agent: Agent[Any, Any],
        deps: AdaptiveDeps,
        *,
        role: str,
        model_name: str,
        max_tokens: int,
        transcript: Any = None,
        prompt: str | None = None,
    ) -> Execution[Any]:
        del agent, model_name, max_tokens, transcript
        self._call_sequence += 1
        call_id = f"scripted-{self._call_sequence:03d}-{role}"
        node_id = deps.assignment.id
        call_index = self._call_count_by_node.get(node_id, 0) + 1
        self._call_count_by_node[node_id] = call_index
        self.calls.append(
            {
                "role": role,
                "prompt": prompt,
                "deps": deps,
                "node_id": node_id,
                "call_index": call_index,
            }
        )

        output: Any
        if role == "adaptive_finalizer":
            output = AdaptiveFinalArtifact(content="final", format="text", limitations=[])
        else:
            output = self._turn_output(node_id, call_index, deps)

        await self._record_knowledge_queries(call_id, deps)
        new_messages = [
            ModelRequest(parts=[UserPromptPart(content=prompt or "full dossier")]),
            ModelResponse(parts=[TextPart(content=f"turn {call_index} for {node_id}")]),
        ]
        execution = Execution(
            output=output,
            call_id=call_id,
            role=role,
            model="scripted",
            input_sha256=deps.knowledge_summary.snapshot_sha256,
            elapsed_ms=1,
            usage={},
            new_messages=new_messages,
            prompt_sha256="scripted",
        )
        self.usage.add(role, execution)
        return execution

    def _turn_output(
        self, node_id: str, call_index: int, deps: AdaptiveDeps
    ) -> ParticipantTurn:
        if node_id != "root":
            return ParticipantTurn.model_validate(_finish_own_question_dict(node_id))

        if call_index == 1:
            return ParticipantTurn.model_validate(
                {
                    "account": "Delegate the first bounded child.",
                    "contribution": None,
                    "action": _delegate_action_dict("leaf-a"),
                }
            )
        if call_index == 2:
            other_question_id = next(
                qid for qid in deps.knowledge_board.questions_by_id if qid != "question:root"
            )
            return ParticipantTurn.model_validate(
                {
                    "account": "Deliberately misdirected contribution.",
                    "contribution": {
                        "body": "Wrong response target on purpose, to force a rejection.",
                        "responds_to": [
                            {
                                "question_id": other_question_id,
                                "effect": "advances",
                                "scope_or_reason": "Deliberately not our own mandate.",
                            }
                        ],
                        "new_questions": [],
                        "links": [],
                        "seam_signal": None,
                    },
                    "action": _delegate_action_dict("leaf-b"),
                }
            )
        if call_index == 3:
            return ParticipantTurn.model_validate(
                {
                    "account": "Retry: delegate the second bounded child.",
                    "contribution": None,
                    "action": _delegate_action_dict("leaf-b"),
                }
            )
        if call_index == 4:
            return ParticipantTurn.model_validate(_finish_own_question_dict("root"))
        raise AssertionError(f"unexpected root call_index {call_index}")  # pragma: no cover


def test_third_turn_recent_actions_and_retry_feedback(tmp_path) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(
            title="Recent actions and retry feedback",
            task="Combine two sequentially delegated leaves into a root synthesis.",
            product_intent="Exercise turn-scoped recent actions and same-sequence retries.",
        )
    )
    harness = RecentActionsAndFeedbackHarness(
        spec,
        runs_dir=tmp_path / "runs",
        policy=RecursivePolicy(max_depth=2, max_nodes=5, max_concurrency=2),
    )

    asyncio.run(harness.run())

    root_calls = [call for call in harness.calls if call["node_id"] == "root"]
    assert len(root_calls) == 4
    _turn1, rejected_attempt, retry_attempt, third_turn = root_calls

    # -- participant_feedback from a rejected attempt appears in the SAME
    #    sequence's retry prompt, not before it --------------------------
    assert rejected_attempt["prompt"] is not None
    assert "must respond to its own mandate" not in rejected_attempt["prompt"]
    assert retry_attempt["prompt"] is not None
    assert "must respond to its own mandate" in retry_attempt["prompt"]
    assert any(
        "must respond to its own mandate" in message
        for message in retry_attempt["deps"].participant_feedback
    )
    rejection_files = sorted(
        (harness.journal.root / "11-participant-rejections").glob(f"{_slug('root')}-*")
    )
    assert rejection_files

    # -- recent_actions on the third turn are scoped to actions recorded
    #    since the SECOND turn, not a global tail: turn 1's own delegate
    #    action and leaf-a's finish (both from before turn 2) must be
    #    absent, while leaf-b's finish (posted during turn 2) is present --
    leaf_a_action = next(a for a in harness._actions if a.actor_id.endswith("-leaf-a"))
    leaf_b_action = next(a for a in harness._actions if a.actor_id.endswith("-leaf-b"))
    root_turn1_action = next(
        a for a in harness._actions if a.actor_id == "root" and a.sequence == 1
    )
    third_turn_action_ids = {entry.action_id for entry in third_turn["deps"].recent_actions}
    assert third_turn_action_ids == {leaf_b_action.action_id}
    assert leaf_a_action.action_id not in third_turn_action_ids
    assert root_turn1_action.action_id not in third_turn_action_ids

    # -- stable fields stay off the prompt string on every later turn, but
    #    remain reachable on deps -----------------------------------------
    for call in (rejected_attempt, retry_attempt, third_turn):
        assert spec.frame.task not in call["prompt"]
        assert spec.frame.product_intent not in call["prompt"]
        assert call["deps"].task == spec.frame.task
        assert call["deps"].product_intent == spec.frame.product_intent

    assert harness.journal.verify() == []


# ---------------------------------------------------------------------------
# Wave results: truncation boundary, push-disabled, terminal statuses
# ---------------------------------------------------------------------------


def test_truncate_wave_body_exact_boundary_and_one_char_over(tmp_path) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(
            title="Truncate boundary", task="Task.", product_intent="Intent."
        )
    )
    harness = AdaptiveHarness(
        spec, runs_dir=tmp_path / "runs", policy=RecursivePolicy(max_source_chunk_chars=500)
    )
    limit = 500 * 4

    exact = "y" * limit
    assert harness._truncate_wave_body(exact, "answer:x") == exact

    over = "y" * (limit + 1)
    result = harness._truncate_wave_body(over, "answer:x")
    assert result.startswith("y" * limit)
    assert result != over
    suffix = "… [truncated; retrieve answer:x for the full body]"
    assert result.endswith(suffix)
    assert len(result) == limit + len(suffix)


class PushDisabledHarness(AdaptiveHarness):
    """Root delegates once, then tries (and is rejected for) citing the
    child's answer without retrieving it -- exercising push_wave_results=False."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.calls: list[dict[str, Any]] = []
        self._call_count_by_node: dict[str, int] = {}

    async def _bounded_call(
        self,
        agent: Agent[Any, Any],
        deps: AdaptiveDeps,
        *,
        role: str,
        model_name: str,
        max_tokens: int,
        transcript: Any = None,
        prompt: str | None = None,
    ) -> Execution[Any]:
        del agent, model_name, max_tokens, transcript
        self._call_sequence += 1
        call_id = f"scripted-{self._call_sequence:03d}-{role}"
        node_id = deps.assignment.id
        call_index = self._call_count_by_node.get(node_id, 0) + 1
        self._call_count_by_node[node_id] = call_index
        self.calls.append({"role": role, "deps": deps, "node_id": node_id, "call_index": call_index})

        output: Any
        if role == "adaptive_finalizer":
            output = AdaptiveFinalArtifact(content="final", format="text", limitations=[])
        elif node_id != "root":
            output = ParticipantTurn.model_validate(_finish_own_question_dict(node_id))
        elif call_index == 1:
            output = ParticipantTurn.model_validate(
                {
                    "account": "Delegate the only child.",
                    "contribution": None,
                    "action": _delegate_action_dict("leaf"),
                }
            )
        elif call_index == 2:
            target = next(iter(deps.knowledge_board.answers_by_id))
            output = ParticipantTurn.model_validate(
                {
                    "account": "Cite the child's answer without retrieving it.",
                    "contribution": {
                        "body": "Synthesis that leans on an answer never queried.",
                        "responds_to": [
                            {
                                "question_id": "question:root",
                                "effect": "resolves",
                                "scope_or_reason": "Root mandate answered.",
                            }
                        ],
                        "new_questions": [],
                        "links": [
                            {
                                "target_id": target,
                                "relation": "derived_from",
                                "rationale": "Directly reused, never retrieved.",
                            }
                        ],
                        "seam_signal": None,
                    },
                    "action": {
                        "kind": "finish",
                        "answer_ids": ["self"],
                        "rationale": "Done.",
                        "unresolved_question_ids": [],
                    },
                }
            )
        else:
            output = ParticipantTurn.model_validate(_finish_own_question_dict("root"))

        await self._record_knowledge_queries(call_id, deps)
        new_messages = [
            ModelRequest(parts=[UserPromptPart(content="dossier")]),
            ModelResponse(parts=[TextPart(content=f"turn {call_index} for {node_id}")]),
        ]
        execution = Execution(
            output=output,
            call_id=call_id,
            role=role,
            model="scripted",
            input_sha256=deps.knowledge_summary.snapshot_sha256,
            elapsed_ms=1,
            usage={},
            new_messages=new_messages,
            prompt_sha256="scripted",
        )
        self.usage.add(role, execution)
        return execution


def test_push_wave_results_false_empties_wave_results_and_rejects_an_unretrieved_link(
    tmp_path,
) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(title="Push disabled", task="Task.", product_intent="Intent.")
    )
    harness = PushDisabledHarness(
        spec,
        runs_dir=tmp_path / "runs",
        policy=RecursivePolicy(
            max_depth=2, max_nodes=5, max_concurrency=2, push_wave_results=False
        ),
    )

    asyncio.run(harness.run())

    root_calls = [call for call in harness.calls if call["node_id"] == "root"]
    second_turn_deps = root_calls[1]["deps"]
    assert second_turn_deps.wave_results == []
    assert second_turn_deps.pushed_entry_ids == []

    rejection_files = list((harness.journal.root / "11-participant-rejections").glob("root-*"))
    assert rejection_files
    rejection = json.loads(rejection_files[0].read_text(encoding="utf-8"))
    assert "unread answer" in rejection["error"]

    root_post = next(post for post in harness._posts_by_id.values() if post.node_id == "root")
    assert root_post.pushed_entry_ids == []
    leaf_answer_id = next(
        answer_id
        for answer_id, answer in harness._knowledge_answers.items()
        if answer.node_id != "root"
    )
    assert leaf_answer_id not in root_post.read_entry_ids

    assert harness.journal.verify() == []


class ChildOutcomeHarness(AdaptiveHarness):
    """Bypasses `_run_participant` entirely for each synthetic child, so
    `_delegate`'s own WaveResult construction (the code under test) runs for
    real against every terminal child outcome."""

    async def _run_participant(  # type: ignore[override]
        self, node: Any, *, target_question_ids: Any, initial_board: Any = None
    ) -> _ParticipantOutcome:
        del target_question_ids, initial_board
        if node.id.endswith("-boom"):
            raise RuntimeError("simulated operational failure")
        if node.id.endswith("-silent"):
            return _ParticipantOutcome(selected_answer_ids=[], call_ids=[])

        answer_data = {
            "id": f"answer:{node.id}:turn:001",
            "node_id": node.id,
            "packet_id": None,
            "post_id": None,
            "body": "Real committed answer body, never fabricated by the caller.",
            "summary": "Real committed answer body, never fabricated by the caller.",
            "claim_ids": [],
            "sufficiency": None,
            "tags": [],
            "unresolved": [],
        }
        answer = KnowledgeAnswer(**answer_data, content_sha256=digest(answer_data))
        await self._register_answer(answer)
        async with self._state_lock:
            self._latest_answer_by_node[node.id] = answer.id
        return _ParticipantOutcome(selected_answer_ids=[answer.id], call_ids=["scripted-answered"])


def test_delegate_wave_results_status_for_failed_and_no_answer_children_have_no_fabricated_body(
    tmp_path,
) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(title="Wave status", task="Task.", product_intent="Intent.")
    )
    policy = RecursivePolicy(max_depth=2, max_nodes=5, max_concurrency=3)
    harness = ChildOutcomeHarness(spec, runs_dir=tmp_path / "runs", policy=policy)

    async def _run() -> tuple[Any, Any, Any, Any]:
        await harness._initialize_run()
        parent = harness._root_node()
        action = DelegateAction.model_validate(
            {
                "kind": "delegate",
                "wave_rationale": "Exercise every terminal wave status in one wave.",
                "delegations": [
                    {
                        "local_id": local_id,
                        "question": f"Question for {local_id}",
                        "rationale": "Rationale.",
                        "acceptance_condition": "Acceptance.",
                        "target_question_ids": ["question:root"],
                        "demand_ids": [],
                        "tags": [],
                        "independence_account": "Independent of its siblings.",
                    }
                    for local_id in ("answered", "boom", "silent")
                ],
            }
        )
        return await harness._delegate(parent, 1, action)

    _work_ids, _call_ids, _question_ids, wave_results = asyncio.run(_run())

    by_status = {result.node_id.rsplit("-", 1)[-1]: result for result in wave_results}

    assert by_status["answered"].status == "answered"
    assert by_status["answered"].answer_id is not None
    assert by_status["answered"].body == (
        "Real committed answer body, never fabricated by the caller."
    )

    assert by_status["boom"].status == "failed"
    assert by_status["boom"].answer_id is None
    assert "RuntimeError" in by_status["boom"].body
    assert "simulated operational failure" in by_status["boom"].body

    assert by_status["silent"].status == "no_answer"
    assert by_status["silent"].answer_id is None
    assert "committed answer" in by_status["silent"].body.lower()
    assert "Real committed" not in by_status["silent"].body


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------


def _transcript_payload(
    node_id: str, sequence: int, marker: str, *, turns: int
) -> dict[str, Any]:
    messages: list[Any] = []
    offsets: list[int] = []
    for i in range(turns):
        offsets.append(len(messages))
        messages.append(_request(UserPromptPart(content=f"{marker}-turn{i}")))
        messages.append(_response(TextPart(content=f"{marker}-answer{i}")))
    return {
        "node_id": node_id,
        "sequence": sequence,
        "message_count": len(messages),
        "estimated_tokens": 1,
        "turn_offsets": offsets,
        "pruned_events": [],
        "messages": ModelMessagesTypeAdapter.dump_python(messages, mode="json"),
    }


def test_resume_restores_latest_transcript_per_node_by_sequence_not_write_order(
    tmp_path,
) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(title="Resume latest", task="Task.", product_intent="Intent.")
    )
    policy = RecursivePolicy()

    source_journal = RunJournal.create(tmp_path / "manual-source", "manual-source")
    source_journal.write_record("00-input", "adaptive-run", {"spec": spec, "policy": policy})

    # Write root's HIGH-sequence record FIRST, then a LOWER one, so a
    # "last event written wins" bug (rather than "highest sequence wins")
    # would pick the wrong one.
    source_journal.write_record(
        "13-transcripts", "root-turn-005", _transcript_payload("root", 5, "high", turns=3)
    )
    source_journal.write_record(
        "13-transcripts", "root-turn-001", _transcript_payload("root", 1, "low", turns=1)
    )
    source_journal.write_record(
        "13-transcripts", "leaf-turn-002", _transcript_payload("leaf-x", 2, "leaf", turns=1)
    )

    target = AdaptiveHarness(spec, runs_dir=tmp_path / "target-runs", policy=policy)
    asyncio.run(target._restore_checkpoint(source_journal.root))

    restored_root = target.transcripts.get("root")
    assert restored_root is not None
    assert restored_root.turns() == 3
    assert restored_root.messages[0].parts[0].content == "high-turn0"

    restored_leaf = target.transcripts.get("leaf-x")
    assert restored_leaf is not None
    assert restored_leaf.turns() == 1

    marker_path = target.journal.root / "13-transcripts" / "restored-root.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker["restored_from_sequence"] == 5
    assert target.journal.verify() == []


def test_resume_with_no_transcript_records_restores_none_and_does_not_error(tmp_path) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(title="Resume empty", task="Task.", product_intent="Intent.")
    )
    policy = RecursivePolicy()
    source_journal = RunJournal.create(tmp_path / "manual-source-empty", "manual-source-empty")
    source_journal.write_record("00-input", "adaptive-run", {"spec": spec, "policy": policy})

    target = AdaptiveHarness(spec, runs_dir=tmp_path / "target-runs", policy=policy)
    asyncio.run(target._restore_checkpoint(source_journal.root))  # must not raise

    assert target.transcripts.get("root") is None
    assert not (target.journal.root / "13-transcripts").exists()
    assert target.journal.verify() == []


class CapturingTurnHarness(AdaptiveHarness):
    """Records the transcript object handed to `_bounded_call` at call time,
    proving `_choose_turn` really uses whatever `TranscriptStore.restore`
    installed on the node's next turn."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.seen_transcript_snapshots: list[list[Any]] = []

    async def _bounded_call(
        self,
        agent: Agent[Any, Any],
        deps: AdaptiveDeps,
        *,
        role: str,
        model_name: str,
        max_tokens: int,
        transcript: Any = None,
        prompt: str | None = None,
    ) -> Execution[Any]:
        del agent, model_name, max_tokens, prompt
        assert transcript is not None
        self.seen_transcript_snapshots.append(copy.deepcopy(transcript.messages))
        self._call_sequence += 1
        call_id = f"scripted-{self._call_sequence:03d}-{role}"
        output = ParticipantTurn.model_validate(_finish_own_question_dict("root"))
        await self._record_knowledge_queries(call_id, deps)
        execution = Execution(
            output=output,
            call_id=call_id,
            role=role,
            model="scripted",
            input_sha256=deps.knowledge_summary.snapshot_sha256,
            elapsed_ms=1,
            usage={},
            new_messages=[
                ModelRequest(parts=[UserPromptPart(content="new turn")]),
                ModelResponse(parts=[TextPart(content="answer")]),
            ],
            prompt_sha256="scripted",
        )
        self.usage.add(role, execution)
        return execution


def test_restored_transcript_feeds_message_history_on_next_turn(tmp_path) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(
            title="Resume feeds history", task="Task.", product_intent="Intent."
        )
    )
    harness = CapturingTurnHarness(
        spec, runs_dir=tmp_path / "runs", policy=RecursivePolicy(max_depth=1, max_nodes=2)
    )

    async def _run() -> None:
        await harness._initialize_run()
        harness.transcripts.restore(
            "root",
            {
                "node_id": "root",
                "turn_offsets": [0],
                "pruned_events": [],
                "messages": ModelMessagesTypeAdapter.dump_python(
                    [
                        _request(UserPromptPart(content="RESTORED-MARKER-CONTENT")),
                        _response(TextPart(content="prior answer")),
                    ],
                    mode="json",
                ),
            },
        )
        board = harness._knowledge_snapshot()
        root = harness._root_node()
        await harness._choose_turn(
            root, ["question:root"], 1, board, has_descendants=False
        )

    asyncio.run(_run())

    assert harness.seen_transcript_snapshots
    first_call_messages = harness.seen_transcript_snapshots[0]
    assert any(
        getattr(part, "content", None) == "RESTORED-MARKER-CONTENT"
        for message in first_call_messages
        for part in message.parts
    )
    assert harness.journal.verify() == []


# ---------------------------------------------------------------------------
# Journal: pruning fires in a scripted run, journal still verifies
# ---------------------------------------------------------------------------


class LargeContentThreeTurnHarness(AdaptiveHarness):
    """Root delegates twice then finishes, same shape as
    RecentActionsAndFeedbackHarness but with large per-turn content and no
    forced rejection, so a tiny transcript_token_budget forces real pruning."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._call_count_by_node: dict[str, int] = {}

    async def _bounded_call(
        self,
        agent: Agent[Any, Any],
        deps: AdaptiveDeps,
        *,
        role: str,
        model_name: str,
        max_tokens: int,
        transcript: Any = None,
        prompt: str | None = None,
    ) -> Execution[Any]:
        del agent, model_name, max_tokens
        self._call_sequence += 1
        call_id = f"scripted-{self._call_sequence:03d}-{role}"
        node_id = deps.assignment.id
        call_index = self._call_count_by_node.get(node_id, 0) + 1
        self._call_count_by_node[node_id] = call_index

        output: Any
        if role == "adaptive_finalizer":
            output = AdaptiveFinalArtifact(content="final", format="text", limitations=[])
        elif node_id != "root":
            output = ParticipantTurn.model_validate(_finish_own_question_dict(node_id))
        elif call_index == 1:
            output = ParticipantTurn.model_validate(
                {"account": "Delegate.", "contribution": None, "action": _delegate_action_dict("leaf-a")}
            )
        elif call_index == 2:
            output = ParticipantTurn.model_validate(
                {
                    "account": "Delegate again.",
                    "contribution": None,
                    "action": _delegate_action_dict("leaf-b"),
                }
            )
        else:
            output = ParticipantTurn.model_validate(_finish_own_question_dict("root"))

        await self._record_knowledge_queries(call_id, deps)
        new_messages = [
            ModelRequest(parts=[UserPromptPart(content=prompt or "full dossier")]),
            ModelResponse(parts=[TextPart(content="X" * 60_000)]),
        ]
        execution = Execution(
            output=output,
            call_id=call_id,
            role=role,
            model="scripted",
            input_sha256=deps.knowledge_summary.snapshot_sha256,
            elapsed_ms=1,
            usage={},
            new_messages=new_messages,
            prompt_sha256="scripted",
        )
        self.usage.add(role, execution)
        return execution


def test_scripted_run_with_a_tiny_budget_prunes_and_the_journal_still_verifies(
    tmp_path,
) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(
            title="Pruning fires",
            task="Combine two delegated leaves under a tiny transcript budget.",
            product_intent="Force real pruning during a scripted run.",
        )
    )
    harness = LargeContentThreeTurnHarness(
        spec,
        runs_dir=tmp_path / "runs",
        policy=RecursivePolicy(
            max_depth=2,
            max_nodes=5,
            max_concurrency=2,
            transcript_token_budget=20_000,
            transcript_keep_recent_turns=1,
        ),
    )

    asyncio.run(harness.run())

    assert harness.journal.verify() == []

    root_transcript = harness.transcripts.get("root")
    assert root_transcript is not None
    assert root_transcript.pruned_events  # pruning genuinely fired

    transcript_files = sorted((harness.journal.root / "13-transcripts").glob("root-turn-*.json"))
    assert len(transcript_files) >= 3  # one record per attempt across 3 turns

    assert any(
        json.loads(path.read_text(encoding="utf-8"))["pruned_events"]
        for path in transcript_files
    )
