"""Per-loop, invlang-based context compaction — the pure core (Phase B).

Design: `defender/docs/runtime-per-loop-compaction-design.md`.

This module is the engine-agnostic heart of Phase B compaction. It operates
on the **PydanticAI message-dump dict** form (what `ModelMessagesTypeAdapter.
dump_python` produces and what `runtime/observe.py` writes to
`llm_requests.jsonl`), so the same code drives both the offline dry-run
harness (`scripts/compaction_dryrun.py`, over recorded runs) and — later —
the live `before_model_request` hook in `driver.py` (which adapts between
PydanticAI message objects and this dict form via the type adapter).

The strategy is **freeze-per-loop**, not rewrite-per-request: we recompute
the compacted prefix only when the investigation advances to a new invlang
loop, then hold it byte-stable for every request within that loop. Within a
loop the history is back to its append-only Phase-A shape, so the cache
stays warm; the one-time rewrite cost is paid once per loop boundary. See
the design doc §Mechanism for why per-request rewriting would thrash the
cache.

Nothing here mutates state or does I/O. `detect_loop` parses text;
`compact` is a pure function of (history, investigation_md, prior state).
On any failure it returns the original history unchanged (Phase-A fallback)
— compaction never costs correctness, only savings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

# Lenient invlang parser — same surface the validator and corpus queries use,
# so loop detection rides the validator-guarded committed artifact rather than
# a bespoke regex. Import errors degrade to "loop undetermined" (fallback).
try:
    from defender.skills.invlang.parser import parse_dense_companion
except Exception:  # pragma: no cover - import guard; absence → always-fallback
    parse_dense_companion = None  # type: ignore[assignment]

Message = dict[str, Any]


# --------------------------------------------------------------------------
# Loop detection
# --------------------------------------------------------------------------

def detect_loop(investigation_md: str) -> int | None:
    """The current investigation loop number, or None if undetermined.

    The signal is `max(:L loop)` over the committed `:L findings` rows — the
    same `loop` column the SKILL writes (`l-005|2|…`) and the markdown
    `## GATHER (loop N)` headers mirror. Composite resolution rows (a
    `resolved_by` list as id) carry no loop and are skipped.

    Returns None when there is nothing to go on (no investigation.md yet, no
    `:L` rows, or a parse failure). The caller treats None as "don't regress":
    pass through if we've never frozen, else keep reusing the last prefix.
    """
    if not investigation_md or parse_dense_companion is None:
        return None
    try:
        companion, _warnings = parse_dense_companion(investigation_md)
    except Exception:
        return None
    loops = [
        f["loop"]
        for f in companion.get("findings", [])
        if isinstance(f.get("loop"), int)
    ]
    return max(loops) if loops else None


# --------------------------------------------------------------------------
# Frozen-prefix state
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FrozenState:
    """The compacted prefix held stable for the duration of one loop.

    `prefix` is the synthetic preamble (orientation message + one frontier
    message) substituted for the real history `[0:freeze_index]`.
    `freeze_index` is the count of real messages folded into the prefix; the
    live tail is `history[freeze_index:]`. `frozen_through` is the highest
    loop whose work has been folded in — we fold loops `1..L-1` once the
    agent enters loop `L` (loop L is still active, so its turns stay live).
    """

    prefix: tuple[Message, ...]
    freeze_index: int
    frozen_through: int


@dataclass(frozen=True)
class CompactionStep:
    """Result of one compaction decision — the history to send plus telemetry.

    `action` is one of: ``passthrough`` (nothing folded yet), ``froze`` (a new
    loop boundary, prefix recomputed), ``reused`` (within a frozen loop), or
    ``fallback`` (a failure; original history returned). `reason` annotates
    the non-trivial actions for the dry-run report / structured warning.
    """

    history: list[Message]
    state: FrozenState | None
    action: str
    loop: int | None
    reason: str | None = None


# --------------------------------------------------------------------------
# Prefix construction
# --------------------------------------------------------------------------

def render_frontier_message(
    investigation_md: str, summary_pointers: dict[str, str] | None = None
) -> Message:
    """A synthetic user-role ModelRequest carrying the invlang frontier.

    The frontier (the whole append-only `investigation.md`) is the
    authoritative carry-over. `summary_pointers` maps a resolved lead id to
    the on-disk path of its persisted gather summary, so the agent can Read
    detail the structured frontier dropped instead of re-dispatching gather
    (design doc §Recovery). Kept deterministic: same inputs → byte-identical
    message, which is what lets the prefix cache across a loop.
    """
    lines = [
        "Investigation state so far — the authoritative committed frontier. "
        "Earlier raw gather summaries have been compacted out; reason from "
        "this frontier.",
        "",
        "```invlang",
        investigation_md.strip(),
        "```",
    ]
    if summary_pointers:
        lines.append("")
        lines.append(
            "Full gather summaries for resolved leads are persisted on disk "
            "(Read one only if you need detail this frontier omits):"
        )
        for lead_id in sorted(summary_pointers):
            lines.append(f"- {lead_id} → {summary_pointers[lead_id]}")
    return {
        "kind": "request",
        "parts": [{"part_kind": "user-prompt", "content": "\n".join(lines)}],
    }


def _build_prefix(
    history: list[Message],
    investigation_md: str,
    orientation_index: int,
    summary_pointers: dict[str, str] | None,
) -> tuple[Message, ...]:
    """Orientation message (verbatim) + the synthetic frontier message.

    Orientation (real message 0: alert, lessons, workspace map, invlang
    catalog) is byte-stable, so folding it into the 1h-cached prefix is a
    bonus over its current 5m tail slot.
    """
    orientation = history[orientation_index]
    return (orientation, render_frontier_message(investigation_md, summary_pointers))


# --------------------------------------------------------------------------
# The compaction decision
# --------------------------------------------------------------------------

def compact(
    history: list[Message],
    investigation_md: str,
    state: FrozenState | None,
    *,
    orientation_index: int = 0,
    summary_pointers: dict[str, str] | None = None,
) -> CompactionStep:
    """Decide the history to send for one model request (freeze-per-loop).

    `history` is the full real main-loop message list as of this request;
    `investigation_md` is its committed state at this point; `state` is the
    frozen prefix carried from the previous request (None on the first).

    We fold loops `1..L-1` into the prefix once the agent reaches loop `L`,
    recomputing only when `L` advances (``froze``); otherwise we reuse the
    held prefix (``reused``). Loop 1 is never compacted — there is nothing
    redundant yet (``passthrough``). Any anomaly returns the original history
    (``fallback``); correctness is preserved, savings forgone.
    """
    current_loop = detect_loop(investigation_md)

    # Loop undetermined: never regress. Reuse a held prefix if we have one,
    # else pass the full history through (Phase-A behaviour).
    if current_loop is None:
        if state is None:
            return CompactionStep(history, None, "passthrough", None, "loop-undetermined")
        return _reuse(history, state, state.frozen_through + 1, "loop-undetermined")

    target_fold = current_loop - 1  # loop `current_loop` is active; fold below it
    already = state.frozen_through if state else 0

    if target_fold <= 0:
        # Still in loop 1 (or earlier) — nothing to fold yet.
        return CompactionStep(history, state, "passthrough", current_loop)

    if target_fold > already:
        # The investigation advanced into a new loop: (re)freeze the prefix
        # from the now-larger frontier and absorb everything up to here. The
        # cut lands just past the current request, so the live tail (which
        # starts empty and grows with loop `current_loop`) begins on a model
        # *response* — its tool-calls and their tool-returns both live in the
        # tail, so no tool_use/tool_return pair is ever orphaned across the
        # cut. (The folded region is replaced wholesale by the tool-call-free
        # synthetic prefix, so the dropped side can't orphan a pair either.)
        try:
            prefix = _build_prefix(
                history, investigation_md, orientation_index, summary_pointers
            )
        except Exception as exc:  # malformed history / missing orientation
            return CompactionStep(history, state, "fallback", current_loop, f"prefix-build: {exc}")
        new_state = FrozenState(
            prefix=prefix, freeze_index=len(history), frozen_through=target_fold
        )
        rewritten = list(prefix)  # tail is empty at the freeze moment
        if not _smaller(rewritten, history):
            # Degenerate: the "compacted" prefix isn't actually smaller.
            return CompactionStep(history, state, "fallback", current_loop, "no-saving")
        return CompactionStep(rewritten, new_state, "froze", current_loop)

    # Within an already-frozen loop: reuse the held prefix + live tail.
    return _reuse(history, state, current_loop, None)  # type: ignore[arg-type]


def _reuse(
    history: list[Message], state: FrozenState, loop: int | None, reason: str | None
) -> CompactionStep:
    """Held prefix + live tail, with an orphaned-pair guard at the cut."""
    tail = history[state.freeze_index :]
    if tail and tail[0].get("kind") != "response":
        # The cut should land on a request boundary so the tail opens on a
        # model response. If it doesn't, a tool-return could be orphaned —
        # bail to the full history rather than send an invalid request.
        return CompactionStep(history, state, "fallback", loop, "cut-not-on-boundary")
    rewritten = list(state.prefix) + tail
    if not _smaller(rewritten, history):
        return CompactionStep(history, state, "fallback", loop, "no-saving")
    return CompactionStep(rewritten, state, "reused", loop, reason)


# --------------------------------------------------------------------------
# Size accounting (token-bearing payload, tokenizer-free)
# --------------------------------------------------------------------------

def payload_chars(message: Message) -> int:
    """Characters of token-bearing content in one message dump.

    Sums the textual content of each part (user-prompt / tool-return / text /
    retry-prompt / system-prompt) and the serialized args of tool-calls. JSON
    structural overhead is ignored — it's small and roughly constant — so this
    is a faithful, tokenizer-free proxy for the part of the prompt compaction
    actually shrinks.
    """
    total = 0
    for part in message.get("parts", []):
        pk = part.get("part_kind")
        if pk == "tool-call":
            total += len(str(part.get("tool_name", "")))
            total += len(json.dumps(part.get("args", ""), default=str, ensure_ascii=False))
        elif "content" in part:
            total += len(_stringify(part["content"]))
        else:  # unknown part shape — count its serialization
            total += len(json.dumps(part, default=str, ensure_ascii=False))
    return total


def history_chars(history: list[Message]) -> int:
    return sum(payload_chars(m) for m in history)


def _stringify(content: Any) -> str:
    if isinstance(content, str):
        return content
    return json.dumps(content, default=str, ensure_ascii=False)


def _smaller(rewritten: list[Message], original: list[Message]) -> bool:
    return history_chars(rewritten) < history_chars(original)


# --------------------------------------------------------------------------
# investigation.md reconstruction from a recorded response stream
# --------------------------------------------------------------------------

def apply_writes(current: str, response: Message) -> str:
    """Fold one model response's investigation.md writes into `current`.

    Mirrors `runtime/tools.py`: `write_file` sets the full content;
    `edit_file` replaces the first (validator-guaranteed-unique) occurrence
    of `old_string`. Used by the dry-run harness to reconstruct what the live
    hook would have read from disk at each request. Non-investigation.md
    writes are ignored.
    """
    for part in response.get("parts", []):
        if part.get("part_kind") != "tool-call":
            continue
        args = part.get("args") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (ValueError, TypeError):
                continue
        if not str(args.get("path", "")).endswith("investigation.md"):
            continue
        name = part.get("tool_name")
        if name == "write_file":
            current = args.get("content", current)
        elif name == "edit_file":
            old, new = args.get("old_string", ""), args.get("new_string", "")
            current = current.replace(old, new, 1) if old else new
    return current
