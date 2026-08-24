"""Per-node pydantic-ai message history, with deterministic budget-bound pruning.

A `ParticipantTranscript` is the durable conversation a single forum
participant (a `NodeTask`) has with its model across every turn it takes. The
harness passes it as `message_history` on each call so a participant keeps its
own prior posts and tool results in context instead of re-deriving them from
the forum. `TranscriptStore` owns one transcript per node and journals it.

Pruning (`TranscriptStore.prune`) is deterministic: given the same messages,
budget, and keep-recent window it always removes the same content in the same
order. It never touches the protected recent-turn window, a `ToolCallPart`, or
the return of an output tool (`participant_turn` / `adaptive_final_artifact`).
Each prune of a node's transcript changes the cached prefix an inference
provider would otherwise reuse for that node exactly once — the pruned
messages replace the originals in place, so the next call's prompt no longer
matches the previously cached prefix beyond the point of the earliest edit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import Field
from pydantic_ai.messages import (
    ModelMessage,
    ModelMessagesTypeAdapter,
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolReturnPart,
)

from .models import StrictModel


# Output-tool returns carry the runtime's acknowledgement of a committed turn,
# never the model's own reasoning or forum content; pruning must never stub them.
_OUTPUT_TOOL_NAMES = frozenset({"participant_turn", "adaptive_final_artifact"})
_STUB_PREFIX = "[pruned "


class PrunedEvent(StrictModel):
    turn: int = Field(ge=1)
    kind: Literal["thinking", "tool_return", "reasoning_text", "dropped_turn"]
    message_index: int = Field(ge=0)
    part_index: int | None = Field(default=None, ge=0)
    original_chars: int = Field(ge=0)


def _part_chars(part: Any) -> int:
    content = getattr(part, "content", None)
    args = getattr(part, "args", None)
    value = content or args
    return len(str(value)) if value is not None else 0


def _is_stub(text: str) -> bool:
    return text.startswith(_STUB_PREFIX)


@dataclass
class ParticipantTranscript:
    node_id: str
    messages: list[ModelMessage] = field(default_factory=list)
    turn_offsets: list[int] = field(default_factory=list)
    pruned_events: list[PrunedEvent] = field(default_factory=list)

    def turns(self) -> int:
        return len(self.turn_offsets)

    def estimated_tokens(self) -> int:
        total_chars = sum(
            _part_chars(part) for message in self.messages for part in message.parts
        )
        return total_chars // 4


class TranscriptStore:
    """Owns every node's `ParticipantTranscript` for the life of a run."""

    def __init__(self) -> None:
        self._transcripts: dict[str, ParticipantTranscript] = {}

    def get(self, node_id: str) -> ParticipantTranscript | None:
        return self._transcripts.get(node_id)

    def get_or_create(self, node_id: str) -> ParticipantTranscript:
        transcript = self._transcripts.get(node_id)
        if transcript is None:
            transcript = ParticipantTranscript(node_id=node_id)
            self._transcripts[node_id] = transcript
        return transcript

    def append(self, node_id: str, new_messages: list[ModelMessage]) -> None:
        if not new_messages:
            return
        transcript = self.get_or_create(node_id)
        transcript.turn_offsets.append(len(transcript.messages))
        transcript.messages.extend(new_messages)

    def prune(
        self, node_id: str, *, token_budget: int, keep_recent_turns: int
    ) -> list[PrunedEvent]:
        transcript = self.get(node_id)
        if transcript is None or transcript.estimated_tokens() <= token_budget:
            return []

        events: list[PrunedEvent] = []
        original_offsets = list(transcript.turn_offsets)
        n_turns = len(original_offsets)
        protected_start = (
            original_offsets[n_turns - keep_recent_turns]
            if n_turns > keep_recent_turns
            else 0
        )

        def over_budget() -> bool:
            return transcript.estimated_tokens() > token_budget

        def turn_of(message_index: int) -> int:
            turn = 0
            for offset in original_offsets:
                if offset <= message_index:
                    turn += 1
                else:
                    break
            return turn

        # a. Remove ThinkingParts, oldest message forward.
        for message_index in range(protected_start):
            if not over_budget():
                break
            message = transcript.messages[message_index]
            if not isinstance(message, ModelResponse):
                continue
            kept_parts = []
            changed = False
            for part_index, part in enumerate(message.parts):
                if over_budget() and isinstance(part, ThinkingPart):
                    events.append(
                        PrunedEvent(
                            turn=turn_of(message_index),
                            kind="thinking",
                            message_index=message_index,
                            part_index=part_index,
                            original_chars=_part_chars(part),
                        )
                    )
                    changed = True
                    continue
                kept_parts.append(part)
            if changed:
                message.parts = kept_parts

        # b. Stub ToolReturnParts (never the output tool's own return).
        for message_index in range(protected_start):
            if not over_budget():
                break
            message = transcript.messages[message_index]
            if not isinstance(message, ModelRequest):
                continue
            for part_index, part in enumerate(message.parts):
                if not over_budget():
                    break
                if not isinstance(part, ToolReturnPart):
                    continue
                if part.tool_name in _OUTPUT_TOOL_NAMES:
                    continue
                content_str = str(part.content)
                if _is_stub(content_str):
                    continue
                original_chars = len(content_str)
                part.content = (
                    f"[pruned tool result: {part.tool_name} — "
                    f"{content_str[:80]!r}… ({original_chars} chars)]"
                )
                events.append(
                    PrunedEvent(
                        turn=turn_of(message_index),
                        kind="tool_return",
                        message_index=message_index,
                        part_index=part_index,
                        original_chars=original_chars,
                    )
                )

        # c. Stub assistant TextParts.
        for message_index in range(protected_start):
            if not over_budget():
                break
            message = transcript.messages[message_index]
            if not isinstance(message, ModelResponse):
                continue
            for part_index, part in enumerate(message.parts):
                if not over_budget():
                    break
                if not isinstance(part, TextPart):
                    continue
                if _is_stub(part.content):
                    continue
                original_chars = len(part.content)
                part.content = f"[pruned reasoning: {original_chars} chars]"
                events.append(
                    PrunedEvent(
                        turn=turn_of(message_index),
                        kind="reasoning_text",
                        message_index=message_index,
                        part_index=part_index,
                        original_chars=original_chars,
                    )
                )

        # d. Drop whole turns, oldest first, never the transcript's first turn
        #    (which holds the first user message).
        turn_index = 1
        dropped_turns = 0
        while over_budget():
            n_turns_now = len(transcript.turn_offsets)
            protected_turn_count = min(keep_recent_turns, n_turns_now)
            prunable_turn_count = n_turns_now - protected_turn_count
            if turn_index >= prunable_turn_count:
                break
            start = transcript.turn_offsets[turn_index]
            end = (
                transcript.turn_offsets[turn_index + 1]
                if turn_index + 1 < n_turns_now
                else len(transcript.messages)
            )
            dropped_messages = transcript.messages[start:end]
            original_chars = sum(
                _part_chars(part)
                for message in dropped_messages
                for part in message.parts
            )
            events.append(
                PrunedEvent(
                    # Positions shift down after each drop, so the original
                    # turn number of the k-th drop at position 1 is 1+k+1.
                    turn=turn_index + dropped_turns + 1,
                    kind="dropped_turn",
                    message_index=start,
                    part_index=None,
                    original_chars=original_chars,
                )
            )
            dropped_turns += 1
            del transcript.messages[start:end]
            del transcript.turn_offsets[turn_index]
            removed_count = end - start
            for i in range(turn_index, len(transcript.turn_offsets)):
                transcript.turn_offsets[i] -= removed_count

        transcript.pruned_events.extend(events)
        return events

    def serialize(self, node_id: str) -> dict[str, Any]:
        transcript = self.get_or_create(node_id)
        return {
            "node_id": transcript.node_id,
            "turn_offsets": list(transcript.turn_offsets),
            "pruned_events": [
                event.model_dump(mode="json") for event in transcript.pruned_events
            ],
            "messages": ModelMessagesTypeAdapter.dump_python(
                transcript.messages, mode="json"
            ),
        }

    def restore(self, node_id: str, payload: dict[str, Any]) -> None:
        messages = list(
            ModelMessagesTypeAdapter.validate_python(payload.get("messages", []))
        )
        pruned_events = [
            PrunedEvent.model_validate(item)
            for item in payload.get("pruned_events", [])
        ]
        self._transcripts[node_id] = ParticipantTranscript(
            node_id=node_id,
            messages=messages,
            turn_offsets=list(payload.get("turn_offsets", [])),
            pruned_events=pruned_events,
        )
