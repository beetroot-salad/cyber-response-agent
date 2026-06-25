"""Per-loop, invlang-based context compaction — the pure core (Phase B).

Design: `defender/docs/runtime-per-loop-compaction-design.md`.

This module is the engine-agnostic heart of Phase B compaction. It operates
on the **PydanticAI message-dump dict** form (what `ModelMessagesTypeAdapter.
dump_python` produces and what `runtime/observe.py` writes to
`llm_requests.jsonl`), so the same code drives both the offline dry-run
harness (`scripts/testing/compaction_dryrun.py`, over recorded runs) and — later —
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
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from defender.skills.invlang.schema import FindingRecord

# Lenient invlang parser — same surface the validator and corpus queries use,
# so loop detection rides the validator-guarded committed artifact rather than
# a bespoke regex. Import errors degrade to "loop undetermined" (fallback).
try:
    from defender.skills.invlang.parser import parse_dense_companion
except Exception:  # pragma: no cover - import guard; absence → always-fallback
    parse_dense_companion = None  # type: ignore[assignment]

Message = dict[str, Any]

# Sentinel that marks our synthetic frontier message. The live processor locates
# it in PydanticAI's accumulated history to find the live tail (everything after
# it); keep it stable and distinctive, and always emit it verbatim in
# `render_frontier_message`.
FRONTIER_SENTINEL = "Settled investigation frontier (completed loops)."


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


def _lead_resolved(finding: FindingRecord) -> bool:
    """True once a lead has committed results — any `outcome` (observations,
    attribute updates, authz resolutions) or a resolution row. A planned-but-not-
    yet-gathered-and-analyzed lead has neither."""
    if finding.get("resolutions"):
        return True
    return bool(finding.get("outcome"))


def fold_boundary(investigation_md: str) -> int:
    """Highest loop safe to fold into the frozen prefix.

    Fold the **contiguous run of loops 1..L that the agent has explicitly marked
    closed** (`:T close`, parsed as `companion["closed_loops"]`), gated by two
    safety conditions that survive from the earlier inferential design:

    - *The marker is the trigger.* A loop is foldable only once the agent writes
      `:T close / loop N` — the in-the-moment, validator-guarded "I am leaving
      this loop" signal. This replaces the old retrospective inference (`fold the
      executed loops below the active one`), which read a loop's *end* off the
      *next* loop opening and misfired repeatedly (draft-ahead empty freeze,
      dead-end block, `max(:L loop)` early-fire — see the design doc's A/B
      ladder). The final loop loops to REPORT (→ `:T conclude`), not to PLAN, so
      it never gets a `:T close` and so never folds.
    - *Data floor (kept as a guard).* A folded loop must still have ≥1 committed
      finding (`any` lead resolved — observations, attr updates, authz/impact
      resolutions, or a `:T` transition). The validator already blocks closing an
      empty loop (rule 6), so this is belt-and-suspenders: even a mis-authored
      `:T close` on a bare drafted-ahead plan (zero committed findings) cannot
      fold it. `any`, not `all`, so a dead-end lead in an otherwise-worked loop
      doesn't block the fold.
    - *Never fold the active loop.* `< active` (the highest loop carrying any
      finding) keeps the loop the agent is mid-investigation on in the live tail
      even if a stray close marker named it.

    Combined with `_frontier_through`, the active loop — plan, in-flight gathers,
    analysis — stays entirely in the live tail. Returns 0 when nothing is safely
    foldable (no closed-and-executed loop below the active one) or on parse
    failure. **Marker-gated**: with no `:T close` in the file (an old SKILL, or
    an agent that hasn't emitted one) this returns 0 and the run is byte-identical
    Phase A — the feature is dormant, never wrong; the caller passes through /
    reuses and never regresses."""
    if not investigation_md or parse_dense_companion is None:
        return 0
    try:
        companion, _warnings = parse_dense_companion(investigation_md)
    except Exception:
        return 0
    by_loop: dict[int, list[bool]] = {}
    for f in companion.get("findings", []):
        loop = f.get("loop")
        if isinstance(loop, int):
            by_loop.setdefault(loop, []).append(_lead_resolved(f))
    if not by_loop:
        return 0
    closed = {n for n in companion.get("closed_loops", []) if isinstance(n, int)}
    active = max(by_loop)
    fold = 0
    loop = 1
    while loop < active and loop in closed and by_loop.get(loop) and any(by_loop[loop]):
        fold = loop
        loop += 1
    return fold


def _frontier_through(investigation_md: str, fold_through: int) -> str:
    """`investigation.md` text trimmed to loops 1..`fold_through` — the settled
    frontier. Cuts at the `:L findings` block that first introduces a lead of a
    higher loop, so the active loop's plan rows (and anything after) never enter
    the frozen snapshot; they stay in the live tail. The result is read by the
    model, not written back, so it needn't be validator-clean — we only re-close a
    dangling ```invlang fence so it renders."""
    lines = investigation_md.split("\n")
    cut: int | None = None
    last_l_header: int | None = None
    for i, ln in enumerate(lines):
        if ln.startswith(":L "):
            last_l_header = i
        m = _LEAD_ROW_RE.match(ln)
        if m and int(m.group(1)) > fold_through:
            cut = last_l_header if last_l_header is not None else i
            break
    if cut is None:
        return investigation_md.strip()
    kept = "\n".join(lines[:cut]).rstrip()
    if kept.count("```") % 2 == 1:  # cut inside a fence → re-close it
        kept += "\n```"
    return kept


_LEAD_ROW_RE = re.compile(r"l-\S*\|(\d+)\|")


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

def render_frontier_message(frontier_md: str) -> Message:
    """A synthetic user-role ModelRequest carrying the settled invlang frontier.

    `frontier_md` is `investigation.md` trimmed to the folded (settled) loops by
    `_frontier_through` — it never contains the active loop's rows, so the message
    can't advertise an in-flight lead as needing work. The framing is a
    **continuation, not a pointer dump** (the 4th-A/B fix): the folded loops are
    COMPLETE and the inlined invlang is their authoritative committed result, so
    the agent has no reason to re-dispatch a lead, re-read a gather summary, or
    re-derive a finding. The earlier version listed each completed lead's on-disk
    summary path — that read as a to-do list and the agent pulled the folded
    detail straight back into context, undoing the fold (and a too-thin frontier
    triggered a full re-orientation). We now state the work is done and inline the
    record; the persisted summaries still exist on disk, just unadvertised, as a
    genuine last resort. Deterministic: same input → byte-identical message, so
    the prefix caches across the loop.
    """
    # `frontier_md` is trimmed investigation.md — already markdown with its own
    # fenced ```invlang blocks + prose, so we present it verbatim (wrapping it in
    # another fence would nest fences and break the markdown).
    n = detect_loop(frontier_md)
    if n is None:
        scope = "The completed loops below are"
    elif n <= 1:
        scope = "Loop 1 is"
    else:
        scope = f"Loops 1–{n} are"
    header = (
        f"{FRONTIER_SENTINEL} {scope} COMPLETE; the invlang record that follows is "
        "their authoritative, committed result — treat it as ground truth already "
        "in hand. Do NOT re-dispatch these leads, re-read their gather summaries, "
        "or re-derive their findings; that work is done and folded in here. Resume "
        "the CURRENT loop from the messages after this one."
    )
    return {
        "kind": "request",
        "parts": [{"part_kind": "user-prompt", "content": header + "\n\n" + frontier_md.strip()}],
    }


def _build_prefix(
    history: list[Message],
    investigation_md: str,
    fold_through: int,
    orientation_index: int,
) -> tuple[Message, ...]:
    """Orientation message (verbatim) + the synthetic frontier message.

    Orientation (real message 0: alert, lessons, workspace map, invlang
    catalog) is byte-stable, so folding it into the 1h-cached prefix is a
    bonus over its current 5m tail slot. The frontier is trimmed to loops
    1..`fold_through` — the active loop stays in the live tail.
    """
    orientation = history[orientation_index]
    frontier_md = _frontier_through(investigation_md, fold_through)
    return (orientation, render_frontier_message(frontier_md))


# --------------------------------------------------------------------------
# The compaction decision
# --------------------------------------------------------------------------

def compact(
    history: list[Message],
    investigation_md: str,
    state: FrozenState | None,
    *,
    orientation_index: int = 0,
) -> CompactionStep:
    """Decide the history to send for one model request (freeze-per-loop).

    `history` is the full real main-loop message list as of this request;
    `investigation_md` is its committed state at this point; `state` is the
    frozen prefix carried from the previous request (None on the first).

    We fold loops `1..R` into the prefix, where `R = fold_boundary` (the highest
    contiguous run of loops the agent has marked `:T close`, each with ≥1
    committed finding, strictly below the active loop), recomputing only when `R`
    advances (``froze``); otherwise we reuse the held prefix (``reused``). Until
    the agent closes an executed loop *below* the active one there is nothing safe
    to fold (``passthrough``) — folding only closed loops below the active one
    keeps the active loop entirely in the live tail, so the frozen frontier never
    lists an unresolved lead and the agent is never asked to continue from a loop
    that was folded out from under it. Any anomaly returns the original history
    (``fallback``); correctness is preserved, savings forgone.
    """
    current_loop = detect_loop(investigation_md)   # telemetry: highest planned loop
    fold_target = fold_boundary(investigation_md)
    already = state.frozen_through if state else 0

    if fold_target <= already:
        # Nothing newly safe to fold: pre-first-freeze (pass the full history
        # through, Phase-A behaviour) or still inside the frozen loop / loop
        # undetermined (keep reusing the held prefix — never regress).
        if state is None:
            return CompactionStep(history, None, "passthrough", current_loop)
        return _reuse(history, state, current_loop, None)

    # A loop just became fully resolved → (re)freeze the prefix from the current
    # (all-resolved-through-R) frontier and absorb everything up to here. The cut
    # lands just past the current request, so the live tail (empty now, growing
    # with the active loop) begins on a model *response* — its tool-calls and
    # tool-returns both live in the tail, so no pair is orphaned across the cut.
    # The folded region is replaced wholesale by the tool-call-free synthetic
    # prefix, so the dropped side can't orphan a pair either.
    try:
        prefix = _build_prefix(
            history, investigation_md, fold_target, orientation_index
        )
    except Exception as exc:  # malformed history / missing orientation
        return CompactionStep(history, state, "fallback", current_loop, f"prefix-build: {exc}")
    new_state = FrozenState(
        prefix=prefix, freeze_index=len(history), frozen_through=fold_target
    )
    rewritten = list(prefix)  # tail is empty at the freeze moment
    if not _smaller(rewritten, history):
        # Degenerate: the "compacted" prefix isn't actually smaller.
        return CompactionStep(history, state, "fallback", current_loop, "no-saving")
    return CompactionStep(rewritten, new_state, "froze", current_loop)


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
