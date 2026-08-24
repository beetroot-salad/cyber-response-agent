from __future__ import annotations

import asyncio
import copy
import json
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError
from pydantic_ai import Agent
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.function import FunctionModel

from seam_harness.adaptive import AdaptiveHarness
from seam_harness.adaptive_models import AdaptiveDeps, AdaptiveFinalArtifact, ParticipantTurn
from seam_harness.cli import _parser
from seam_harness.models import Demand, HarnessSpec, TaskFrame
from seam_harness.orchestrator import Execution
from seam_harness.recursive import RecursiveHarness
from seam_harness.recursive_cli import _policy
from seam_harness.recursive_models import KnowledgeRelation, RecursivePolicy
from seam_harness.transcripts import (
    ParticipantTranscript,
    TranscriptStore,
    _part_chars,
)


# ---------------------------------------------------------------------------
# Fixtures shared by the store-level tests
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


def _seeded_store(
    node_id: str = "n",
    turns: int = 4,
    output_tool: str = "participant_turn",
    size: int = 200,
) -> TranscriptStore:
    """A transcript whose every turn carries one of each prunable/protected part."""
    store = TranscriptStore()
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
    return store


# ---------------------------------------------------------------------------
# ParticipantTranscript / TranscriptStore
# ---------------------------------------------------------------------------


def test_append_records_turn_offsets() -> None:
    store = TranscriptStore()
    store.append(
        "n1",
        [_request(UserPromptPart(content="a")), _response(TextPart(content="b"))],
    )
    store.append("n1", [_request(UserPromptPart(content="c"))])
    transcript = store.get("n1")
    assert transcript is not None
    assert transcript.turn_offsets == [0, 2]
    assert transcript.turns() == 2
    assert len(transcript.messages) == 3

    # appending an empty batch is a no-op, not a new (empty) turn
    store.append("n1", [])
    assert transcript.turn_offsets == [0, 2]

    # a brand new node is created on first append
    assert store.get("missing") is None
    created = store.get_or_create("missing")
    assert created.turns() == 0


def test_estimated_tokens_counts_args_and_content() -> None:
    transcript = ParticipantTranscript(node_id="n")
    transcript.messages = [
        _request(UserPromptPart(content="12345678")),
        _response(
            TextPart(content="1234567890"),
            ToolCallPart(
                tool_name="search", args={"query": "abcde"}, tool_call_id="tc1"
            ),
        ),
    ]
    expected_chars = (
        len("12345678") + len("1234567890") + len(str({"query": "abcde"}))
    )
    assert transcript.estimated_tokens() == expected_chars // 4


def test_prune_never_touches_the_recent_window() -> None:
    store = _seeded_store(turns=4, size=150)
    transcript = store.get("n")
    assert transcript is not None
    protected_start = transcript.turn_offsets[-2]
    expected_recent = copy.deepcopy(transcript.messages[protected_start:])

    store.prune("n", token_budget=1, keep_recent_turns=2)

    # earlier turns may have been dropped entirely, shifting later turns down;
    # relocate the protected window by its (recomputed) offset, not a stale index.
    new_protected_start = transcript.turn_offsets[-2]
    assert transcript.messages[new_protected_start:] == expected_recent


def test_prune_never_touches_tool_call_parts_or_output_tool_returns() -> None:
    store = _seeded_store(turns=4, size=150, output_tool="participant_turn")
    transcript = store.get("n")
    assert transcript is not None

    store.prune("n", token_budget=1, keep_recent_turns=1)

    for message in transcript.messages:
        for part in message.parts:
            if isinstance(part, ToolCallPart):
                assert not str(part.args).startswith("[pruned")
            if isinstance(part, ToolReturnPart) and part.tool_name == "participant_turn":
                assert not str(part.content).startswith("[pruned")


def test_prune_stubs_are_idempotent() -> None:
    store = _seeded_store(turns=3, size=150)
    transcript = store.get("n")
    assert transcript is not None

    store.prune("n", token_budget=1, keep_recent_turns=1)
    snapshot = copy.deepcopy(transcript.messages)
    turn_offsets_snapshot = list(transcript.turn_offsets)

    second_events = store.prune("n", token_budget=1, keep_recent_turns=1)

    assert second_events == []
    assert transcript.messages == snapshot
    assert transcript.turn_offsets == turn_offsets_snapshot


def test_prune_converges_under_budget() -> None:
    store = _seeded_store(turns=6, size=100)
    transcript = store.get("n")
    assert transcript is not None

    # The floor a budget-1 prune could ever reach: the always-protected first
    # turn's unshrinkable parts (everything but thinking/text, which prune can
    # zero out) plus the fully-protected recent window.
    protected_start = transcript.turn_offsets[-1]
    recent_chars = sum(
        _part_chars(part)
        for message in transcript.messages[protected_start:]
        for part in message.parts
    )
    first_turn_messages = transcript.messages[
        transcript.turn_offsets[0] : transcript.turn_offsets[1]
    ]
    floor_chars = recent_chars + sum(
        _part_chars(part)
        for message in first_turn_messages
        for part in message.parts
        if not isinstance(part, (ThinkingPart, TextPart))
    )
    budget = floor_chars // 4 + 20

    store.prune("n", token_budget=budget, keep_recent_turns=1)

    assert transcript.estimated_tokens() <= budget


def test_dropped_turn_never_removes_the_first_user_message() -> None:
    store = _seeded_store(turns=4, size=150)
    transcript = store.get("n")
    assert transcript is not None

    events = store.prune("n", token_budget=1, keep_recent_turns=1)

    first_message = transcript.messages[0]
    assert isinstance(first_message.parts[0], UserPromptPart)
    assert first_message.parts[0].content.startswith("user0")

    dropped = [event for event in events if event.kind == "dropped_turn"]
    assert dropped
    assert all(event.turn != 1 for event in dropped)


def test_prune_events_are_recorded_on_the_transcript() -> None:
    store = _seeded_store(turns=3, size=150)
    transcript = store.get("n")
    assert transcript is not None

    # A budget just below the raw total triggers only the cheapest edits
    # (thinking removal), never a stub or a drop.
    budget = transcript.estimated_tokens() - 1
    events = store.prune("n", token_budget=budget, keep_recent_turns=1)

    assert events
    kinds = {event.kind for event in events}
    assert kinds <= {"thinking", "tool_return", "reasoning_text", "dropped_turn"}
    assert kinds == {"thinking"}
    assert all(event.turn in (1, 2) for event in events)
    assert transcript.pruned_events == events

    # a much smaller budget forces every kind, including a whole-turn drop
    store2 = _seeded_store(turns=3, size=150)
    transcript2 = store2.get("n")
    assert transcript2 is not None
    aggressive_events = store2.prune("n", token_budget=1, keep_recent_turns=1)
    aggressive_kinds = {event.kind for event in aggressive_events}
    assert aggressive_kinds == {"thinking", "tool_return", "reasoning_text", "dropped_turn"}
    assert transcript2.pruned_events == aggressive_events


def test_serialize_restore_round_trip() -> None:
    store = _seeded_store(turns=2, size=50)
    store.prune("n", token_budget=1, keep_recent_turns=1)
    original = store.get("n")
    assert original is not None

    payload = store.serialize("n")
    # the payload must be plain JSON-loadable data
    json.dumps(payload)

    restored_store = TranscriptStore()
    restored_store.restore("n", payload)
    restored = restored_store.get("n")

    assert restored is not None
    assert restored.node_id == original.node_id
    assert restored.turn_offsets == original.turn_offsets
    assert restored.pruned_events == original.pruned_events
    assert restored.messages == original.messages


# ---------------------------------------------------------------------------
# RecursiveHarness._call with a transcript
# ---------------------------------------------------------------------------


class _DummyDeps(BaseModel):
    note: str = "hello"


def _minimal_spec() -> HarnessSpec:
    return HarnessSpec(
        frame=TaskFrame(
            title="Transcript wiring",
            task="Exercise _call's transcript plumbing.",
            product_intent="Confirm message history round-trips.",
        )
    )


def test_call_passes_message_history_and_returns_new_messages(tmp_path) -> None:
    harness = RecursiveHarness(_minimal_spec(), runs_dir=tmp_path / "runs")
    agent: Agent[_DummyDeps, str] = Agent(deps_type=_DummyDeps, output_type=str)
    seen_lengths: list[int] = []

    def fn(messages: list[Any], info: Any) -> ModelResponse:
        seen_lengths.append(len(messages))
        return ModelResponse(parts=[TextPart(content="ok")])

    async def stream_fn(messages, info):
        seen_lengths.append(len(messages))
        yield "ok"

    transcript = ParticipantTranscript(node_id="n1")
    transcript.messages = [
        _request(UserPromptPart(content="turn1 prompt")),
        _response(TextPart(content="turn1 answer")),
    ]
    transcript.turn_offsets = [0]

    execution = asyncio.run(
        harness._call(
            agent,
            _DummyDeps(),
            role="probe_role",
            model_name=FunctionModel(fn, stream_function=stream_fn),
            max_tokens=100,
            transcript=transcript,
            prompt="turn2 dossier",
        )
    )

    assert seen_lengths == [3]  # 2 seeded history messages + 1 new request
    assert execution.output == "ok"
    assert len(execution.new_messages) == 2
    assert execution.prompt_sha256 is not None

    # the caller (not _call) owns appending on success
    transcript.turn_offsets.append(len(transcript.messages))
    transcript.messages.extend(execution.new_messages)

    seen_lengths.clear()
    execution2 = asyncio.run(
        harness._call(
            agent,
            _DummyDeps(),
            role="probe_role",
            model_name=FunctionModel(fn, stream_function=stream_fn),
            max_tokens=100,
            transcript=transcript,
            prompt="turn3 dossier",
        )
    )
    # the second call sees the first call's messages as history
    assert seen_lengths == [5]  # 4 accumulated history messages + 1 new request
    assert execution2.output == "ok"


def test_call_records_failed_attempt_messages_and_appends_to_transcript(
    tmp_path,
) -> None:
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
                prompt="turn1 dossier",
            )
        )

    # the failed attempt's messages are real history: appended as one turn
    assert transcript.turns() == 1
    assert len(transcript.messages) >= 1

    error_files = sorted((harness.journal.root / "02-call-errors").glob("*.json"))
    assert len(error_files) == 1
    payload = json.loads(error_files[0].read_text(encoding="utf-8"))
    assert payload["type"] == "RuntimeError"
    assert "messages" in payload
    assert len(payload["messages"]) >= 1
    assert harness.journal.verify() == []


# ---------------------------------------------------------------------------
# _run_participant: turn dossiers and pushed wave results
# ---------------------------------------------------------------------------


class WaveResultParticipantHarness(AdaptiveHarness):
    """Scripts participant turns directly, bypassing the model, so the real
    `_choose_turn` / `_run_participant` / `_delegate` / `_commit_post` control
    flow (transcript bookkeeping, turn dossiers, wave-result pushing, and
    read-set validation) runs unmodified."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.calls: list[dict[str, Any]] = []

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
        self.calls.append({"role": role, "prompt": prompt, "deps": deps})

        output: Any
        if role == "adaptive_finalizer":
            output = AdaptiveFinalArtifact(content="final", format="text", limitations=[])
        elif role.startswith("adaptive_participant"):
            output = self._turn_output(deps)
        else:  # pragma: no cover
            raise AssertionError(role)

        await self._record_knowledge_queries(call_id, deps)
        new_messages = [
            ModelRequest(parts=[UserPromptPart(content=prompt or "full dossier")]),
            ModelResponse(
                parts=[TextPart(content=f"synthetic turn for {deps.assignment.id}")]
            ),
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

    def _turn_output(self, deps: AdaptiveDeps) -> ParticipantTurn:
        node_id = deps.assignment.id
        if node_id == "root":
            if not deps.wave_results:
                return ParticipantTurn.model_validate(
                    {
                        "account": "Delegate a single bounded child.",
                        "contribution": None,
                        "action": {
                            "kind": "delegate",
                            "wave_rationale": "One grounded subquestion suffices.",
                            "delegations": [
                                {
                                    "local_id": "leaf",
                                    "question": "What supports the leaf claim?",
                                    "rationale": "Ground the root synthesis.",
                                    "acceptance_condition": (
                                        "Return one bounded observation."
                                    ),
                                    "target_question_ids": ["question:root"],
                                    "demand_ids": ["D1"],
                                    "tags": ["evidence"],
                                    "independence_account": (
                                        "It is the only delegation."
                                    ),
                                }
                            ],
                        },
                    }
                )
            pushed = deps.wave_results[0]
            assert pushed.answer_id is not None
            return ParticipantTurn.model_validate(
                {
                    "account": "Use the pushed wave result without re-retrieving it.",
                    "contribution": {
                        "body": f"Root synthesis incorporates: {pushed.body}",
                        "responds_to": [
                            {
                                "question_id": "question:root",
                                "effect": "resolves",
                                "scope_or_reason": (
                                    "The pushed wave result answers the mandate."
                                ),
                            },
                            {
                                "question_id": "question:demand:D1",
                                "effect": "resolves",
                                "scope_or_reason": (
                                    "The delegated leaf covers the demand."
                                ),
                            },
                        ],
                        "new_questions": [],
                        "links": [
                            {
                                "target_id": pushed.answer_id,
                                "relation": "derived_from",
                                "rationale": (
                                    "Directly used the pushed wave result; "
                                    "never re-retrieved it."
                                ),
                            }
                        ],
                        "seam_signal": None,
                    },
                    "action": {
                        "kind": "finish",
                        "answer_ids": ["self"],
                        "rationale": "The pushed wave result completes the mandate.",
                        "unresolved_question_ids": [],
                    },
                }
            )

        own_question = f"question:{node_id}"
        return ParticipantTurn.model_validate(
            {
                "account": "Answer the delegated mandate directly.",
                "contribution": {
                    "body": "Leaf posterior answer body with concrete support.",
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
                    "rationale": "The leaf mandate is answered.",
                    "unresolved_question_ids": [],
                },
            }
        )


def _wave_result_spec() -> HarnessSpec:
    return HarnessSpec(
        frame=TaskFrame(
            title="Wave push test",
            task="Combine one delegated leaf into a root synthesis.",
            product_intent="Exercise pushed wave results.",
            demands=[Demand(id="D1", statement="Use the leaf finding")],
        )
    )


def test_second_turn_gets_turn_dossier_and_pushed_wave_results(tmp_path) -> None:
    spec = _wave_result_spec()
    harness = WaveResultParticipantHarness(
        spec,
        runs_dir=tmp_path / "runs",
        policy=RecursivePolicy(max_depth=2, max_nodes=5, max_concurrency=2),
    )

    result = asyncio.run(harness.run())

    root_calls = [call for call in harness.calls if call["deps"].assignment.id == "root"]
    assert len(root_calls) == 2
    first_prompt, second_prompt = root_calls[0]["prompt"], root_calls[1]["prompt"]

    # first turn: today's full dossier (no prompt override)
    assert first_prompt is None

    # second turn: a compact turn dossier, not the full dossier
    assert second_prompt is not None
    assert "TURN DOSSIER" in second_prompt
    assert '"wave_results"' in second_prompt
    assert spec.frame.task not in second_prompt
    assert spec.frame.product_intent not in second_prompt
    assert "Use the leaf finding" not in second_prompt  # a demand statement: stable

    # stable fields remain on deps even though the prompt omits them
    second_deps = root_calls[1]["deps"]
    assert second_deps.task == spec.frame.task
    assert second_deps.product_intent == spec.frame.product_intent

    # the completed delegate wave's result is pushed into the second turn
    wave_results = second_deps.wave_results
    assert len(wave_results) == 1
    assert wave_results[0].status == "answered"
    assert "Leaf posterior answer body" in wave_results[0].body
    pushed_answer_id = wave_results[0].answer_id
    assert pushed_answer_id is not None
    assert second_deps.pushed_entry_ids == [pushed_answer_id]

    # the pushed answer counts as disclosed: the derived_from link validated
    # without a retrieval, and the run completed and recorded it as such.
    root_post = next(
        post for post in harness._posts_by_id.values() if post.node_id == "root"
    )
    assert pushed_answer_id in root_post.pushed_entry_ids
    assert pushed_answer_id in root_post.read_entry_ids

    root_answer_id = next(
        answer_id
        for answer_id, answer in result.knowledge_board.answers_by_id.items()
        if answer.node_id == "root"
    )
    derived_edges = {
        (link.source_id, link.target_id)
        for link in result.knowledge_board.links_by_id.values()
        if link.relation == KnowledgeRelation.DERIVED_FROM
    }
    assert (root_answer_id, pushed_answer_id) in derived_edges
    assert harness.journal.verify() == []


def test_resume_restores_transcripts(tmp_path) -> None:
    spec = _wave_result_spec()
    policy = RecursivePolicy(max_depth=2, max_nodes=5, max_concurrency=2)

    source = WaveResultParticipantHarness(
        spec, runs_dir=tmp_path / "source-runs", policy=policy
    )
    asyncio.run(source.run())
    checkpoint = source.journal.root

    source_root_transcript = source.transcripts.get("root")
    assert source_root_transcript is not None
    assert source_root_transcript.turns() == 2

    leaf_node_id = next(
        post.node_id for post in source._posts_by_id.values() if post.node_id != "root"
    )
    source_leaf_transcript = source.transcripts.get(leaf_node_id)
    assert source_leaf_transcript is not None

    target = WaveResultParticipantHarness(
        spec,
        runs_dir=tmp_path / "target-runs",
        policy=policy,
        resume_run=checkpoint,
    )
    asyncio.run(target._restore_checkpoint(checkpoint))

    restored_root = target.transcripts.get("root")
    assert restored_root is not None
    assert restored_root.turns() == source_root_transcript.turns()
    assert restored_root.turn_offsets == source_root_transcript.turn_offsets
    assert restored_root.messages == source_root_transcript.messages

    restored_leaf = target.transcripts.get(leaf_node_id)
    assert restored_leaf is not None
    assert restored_leaf.messages == source_leaf_transcript.messages

    marker_path = target.journal.root / "13-transcripts" / "restored-root.json"
    assert marker_path.is_file()
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker["node_id"] == "root"
    assert marker["source"] == str(checkpoint.resolve())
    assert target.journal.verify() == []


# ---------------------------------------------------------------------------
# Policy bounds and CLI flags
# ---------------------------------------------------------------------------


def test_policy_max_tokens_bounds_widened_and_transcript_defaults() -> None:
    policy = RecursivePolicy()
    assert policy.transcript_token_budget == 400_000
    assert policy.transcript_keep_recent_turns == 2
    assert policy.push_wave_results is True

    # the four *_max_tokens fields now accept up to 262144 (were capped at 32000)
    widened = RecursivePolicy(
        planner_max_tokens=262_144,
        research_max_tokens=262_144,
        synthesis_max_tokens=262_144,
        final_max_tokens=262_144,
    )
    assert widened.planner_max_tokens == 262_144

    with pytest.raises(ValidationError):
        RecursivePolicy(planner_max_tokens=262_145)
    with pytest.raises(ValidationError):
        RecursivePolicy(transcript_token_budget=19_999)
    with pytest.raises(ValidationError):
        RecursivePolicy(transcript_token_budget=1_000_001)
    with pytest.raises(ValidationError):
        RecursivePolicy(transcript_keep_recent_turns=0)
    with pytest.raises(ValidationError):
        RecursivePolicy(transcript_keep_recent_turns=11)


def test_cli_wires_transcript_and_wave_result_flags() -> None:
    spec = HarnessSpec(
        frame=TaskFrame(title="T", task="Task.", product_intent="Intent.")
    )

    args = _parser().parse_args(
        [
            "solve",
            "task.json",
            "--transcript-token-budget",
            "50000",
            "--transcript-keep-recent-turns",
            "5",
            "--no-push-wave-results",
        ]
    )
    policy = _policy(spec, args)
    assert policy.transcript_token_budget == 50_000
    assert policy.transcript_keep_recent_turns == 5
    assert policy.push_wave_results is False

    default_args = _parser().parse_args(["solve", "task.json"])
    default_policy = _policy(spec, default_args)
    assert default_policy.transcript_token_budget == 400_000
    assert default_policy.transcript_keep_recent_turns == 2
    assert default_policy.push_wave_results is True
