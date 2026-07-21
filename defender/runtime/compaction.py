
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from defender.skills.invlang.schema import FindingRecord

try:
    from defender.skills.invlang.parser import parse_dense_companion
except Exception:  # pragma: no cover - import guard; absence → always-fallback
    parse_dense_companion = None  # type: ignore[assignment]

Message = dict[str, Any]

FRONTIER_SENTINEL = "Settled investigation frontier (completed loops)."



def detect_loop(investigation_md: str) -> int | None:
    if not investigation_md or parse_dense_companion is None:
        return None
    try:
        companion, _warnings = parse_dense_companion(investigation_md)
    except Exception:
        return None
    loops = [
        n
        for f in companion.get("findings", [])
        if isinstance((n := f.get("loop")), int)
    ]
    return max(loops) if loops else None


def _lead_resolved(finding: FindingRecord) -> bool:
    if finding.get("resolutions"):
        return True
    return bool(finding.get("outcome"))


def fold_boundary(investigation_md: str) -> int:
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
    if kept.count("```") % 2 == 1:
        kept += "\n```"
    return kept


_LEAD_ROW_RE = re.compile(r"l-\S*\|(\d+)\|")



@dataclass(frozen=True)
class FrozenState:

    prefix: tuple[Message, ...]
    freeze_index: int
    frozen_through: int


@dataclass(frozen=True)
class CompactionStep:

    history: list[Message]
    state: FrozenState | None
    action: str
    loop: int | None
    reason: str | None = None



def render_frontier_message(frontier_md: str) -> Message:
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
    orientation = history[orientation_index]
    frontier_md = _frontier_through(investigation_md, fold_through)
    return (orientation, render_frontier_message(frontier_md))



def compact(
    history: list[Message],
    investigation_md: str,
    state: FrozenState | None,
    *,
    orientation_index: int = 0,
) -> CompactionStep:
    current_loop = detect_loop(investigation_md)
    fold_target = fold_boundary(investigation_md)
    already = state.frozen_through if state else 0

    if fold_target <= already:
        if state is None:
            return CompactionStep(history, None, "passthrough", current_loop)
        return _reuse(history, state, current_loop, None)

    try:
        prefix = _build_prefix(
            history, investigation_md, fold_target, orientation_index
        )
    except Exception as exc:
        return CompactionStep(history, state, "fallback", current_loop, f"prefix-build: {exc}")
    new_state = FrozenState(
        prefix=prefix, freeze_index=len(history), frozen_through=fold_target
    )
    rewritten = list(prefix)
    if not _smaller(rewritten, history):
        return CompactionStep(history, state, "fallback", current_loop, "no-saving")
    return CompactionStep(rewritten, new_state, "froze", current_loop)


def _reuse(
    history: list[Message], state: FrozenState, loop: int | None, reason: str | None
) -> CompactionStep:
    tail = history[state.freeze_index :]
    if tail and tail[0].get("kind") != "response":
        return CompactionStep(history, state, "fallback", loop, "cut-not-on-boundary")
    rewritten = list(state.prefix) + tail
    if not _smaller(rewritten, history):
        return CompactionStep(history, state, "fallback", loop, "no-saving")
    return CompactionStep(rewritten, state, "reused", loop, reason)



def payload_chars(message: Message) -> int:
    total = 0
    for part in message.get("parts", []):
        pk = part.get("part_kind")
        if pk == "tool-call":
            total += len(str(part.get("tool_name", "")))
            total += len(json.dumps(part.get("args", ""), default=str, ensure_ascii=False))
        elif "content" in part:
            total += len(_stringify(part["content"]))
        else:
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



def apply_writes(current: str, response: Message) -> str:
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
