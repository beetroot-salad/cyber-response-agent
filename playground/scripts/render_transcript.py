#!/usr/bin/env python3
"""Render an eval run transcript.jsonl as a single-file HTML timeline.

Each event row shows:
- absolute offset from t0 (the first user-event timestamp)
- duration since the previous timestamped event
- event type badge
- the phase the agent was in when the event fired
- content blocks (thinking, text, tool_use, tool_result, hook payload)

Above the rows is a phase timeline bar (CONTEXTUALIZE → GATHER → ANALYZE …)
with per-phase duration and token counts, plus a free-text search that
hides rows whose visible content doesn't match.

Usage:
    render_transcript.py <eval_dir> [-o transcript.html]

Only `user` events carry timestamps in stream-json transcripts. Events
without a timestamp inherit the next timestamped event's time (they
occurred during that wait), so an assistant message + its hooks render
as a single segment ending at the user tool_result that followed them.

Phase detection: we scan Write/Edit tool_use blocks targeting
`investigation.md` for `## <PHASE>` markdown headers. The first such
header in a given edit is treated as the new phase; subsequent rows
inherit it until the next transition.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from datetime import datetime
from pathlib import Path

SLOW_GAP_SECONDS = 5.0
CONTENT_PREVIEW_CHARS = 120

# Matches '## CONTEXTUALIZE', '## GATHER (loop 1)', etc. — the agent's
# investigation.md phase headers. We only care about the phase word;
# the optional parenthetical is stripped.
PHASE_HEADER_RE = re.compile(
    r"^##\s+([A-Z][A-Z_\-]*)(?:\s*\([^)]*\))?\s*$",
    re.MULTILINE,
)
KNOWN_PHASES = {
    "CONTEXTUALIZE", "SCREEN", "HYPOTHESIZE",
    "GATHER", "ANALYZE", "CONCLUDE",
}


def iso_parse(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def load_events(path: Path) -> list[dict]:
    out = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def attach_timestamps(events: list[dict]) -> list[tuple[dict, datetime | None]]:
    """Return list of (event, ts_dt) pairs. Events without ts inherit the
    next-seen timestamp so all rows sit on a monotonic timeline."""
    with_direct: list[tuple[dict, datetime | None]] = []
    for ev in events:
        ts = None
        if ev.get("type") in ("user", "assistant"):
            ts = iso_parse(ev.get("timestamp", ""))
        elif ev.get("type") == "system" and ev.get("subtype") in ("hook_response", "hook_started"):
            ts = iso_parse(ev.get("timestamp", ""))
        with_direct.append((ev, ts))

    next_ts: datetime | None = None
    filled: list[tuple[dict, datetime | None]] = []
    for ev, ts in reversed(with_direct):
        if ts is None:
            ts = next_ts
        else:
            next_ts = ts
        filled.append((ev, ts))
    filled.reverse()
    return filled


def detect_phase_for_event(ev: dict) -> str | None:
    """Return the phase name this event declares, or None.

    An event declares a phase when it's an assistant tool_use of
    Write/Edit targeting investigation.md and the written content
    contains a recognized phase header.
    """
    if ev.get("type") != "assistant":
        return None
    for b in ev.get("message", {}).get("content", []):
        if b.get("type") != "tool_use":
            continue
        if b.get("name") not in ("Write", "Edit"):
            continue
        inp = b.get("input", {}) or {}
        fp = inp.get("file_path", "") or ""
        if "investigation.md" not in fp:
            continue
        body = inp.get("new_string") or inp.get("content") or ""
        for m in PHASE_HEADER_RE.findall(body):
            name = m.strip().upper()
            if name in KNOWN_PHASES:
                return name
    return None


def compute_phases(events_ts: list[tuple[dict, datetime | None]]) -> list[str | None]:
    """Return a parallel list of phase names.

    The agent writes a `## PHASE` header into investigation.md at the *end*
    of that phase (the write crystallizes the findings). So each event
    belongs to the **next** phase write that follows it; the write itself
    closes the phase. Events after the final phase write inherit that
    phase (e.g. post-CONCLUDE wrap-up still counts as CONCLUDE).
    """
    declared: list[tuple[int, str]] = []
    for i, (ev, _) in enumerate(events_ts):
        p = detect_phase_for_event(ev)
        if p is not None:
            declared.append((i, p))

    phases: list[str | None] = [None] * len(events_ts)
    if not declared:
        return phases
    prev_idx = -1
    for idx, name in declared:
        for j in range(prev_idx + 1, idx + 1):
            phases[j] = name
        prev_idx = idx
    last_idx, last_name = declared[-1]
    for j in range(last_idx + 1, len(events_ts)):
        phases[j] = last_name
    return phases


def event_output_tokens(ev: dict) -> int:
    """Best-effort output-token count for an assistant message."""
    if ev.get("type") != "assistant":
        return 0
    usage = ev.get("message", {}).get("usage") or {}
    return int(usage.get("output_tokens") or 0)


def build_subagent_index(events: list[dict]) -> dict[str, dict]:
    """Map Task/Agent tool_use.id → {subagent_type, description, short}.

    Assistant events running inside a subagent carry `parent_tool_use_id`
    matching the Task tool_use that spawned them, so we can label each
    tool call with which instance made it.
    """
    idx: dict[str, dict] = {}
    for ev in events:
        if ev.get("type") != "assistant":
            continue
        for b in (ev.get("message", {}) or {}).get("content", []) or []:
            if b.get("type") != "tool_use":
                continue
            if b.get("name") not in ("Task", "Agent"):
                continue
            inp = b.get("input", {}) or {}
            tuid = b.get("id")
            if not tuid:
                continue
            desc = inp.get("description", "") or ""
            st = inp.get("subagent_type", "") or "general-purpose"
            idx[tuid] = {
                "subagent_type": st,
                "description": desc,
                "short": f"{st}:{desc[:40]}" if desc else st,
            }
    return idx


def instance_label(ev: dict, subagent_idx: dict[str, dict]) -> str:
    """Human-readable label for which agent instance produced this event.

    Assistant/user events carry `parent_tool_use_id` when emitted from a
    subagent. Missing parent = main agent. Unknown id = stray subagent.
    """
    if ev.get("type") not in ("assistant", "user"):
        return ""
    pid = ev.get("parent_tool_use_id")
    if not pid:
        return "main"
    info = subagent_idx.get(pid)
    if info:
        return info["short"]
    return f"subagent:{pid[:8]}"


def _empty_bucket() -> dict:
    return {
        # Wall-clock time attributed to this (scope, phase). Sums across
        # all events whose scope maps here.
        "total_s": 0.0,
        # LLM output metrics (from assistant message content).
        "output_tokens": 0,
        "thinking_blocks": 0, "thinking_tokens": 0,
        "text_blocks": 0, "text_tokens": 0,
        "tool_calls": 0, "subagent_spawns": 0,
        # Tool execution metrics (from user tool_result blocks).
        "tool_results": 0, "tool_result_bytes": 0,
        # Hook metrics (PostToolUse/PreToolUse responses).
        "hook_count": 0,
    }


def compute_breakdowns(
    events_ts: list[tuple[dict, datetime | None]],
    phases: list[str | None],
) -> dict:
    """Recursive per-phase, per-scope breakdown of time and activity.

    Each event's wall-clock delta (since the previous timestamped event) is
    attributed to the scope that produced it (main or subagent tuid) for
    the phase that was active at the time. A subagent's total time is
    therefore the sum of deltas from its internal events.

    Returns:
        {
            "main":        {phase_label -> bucket},
            "subs":        {scope_id (tuid) -> {phase_label -> bucket}},
            "parent":      {scope_id -> parent_scope_id_or_None},
            "info":        {scope_id -> {"type": str, "description": str}},
            "spawn_phase": {scope_id -> phase_label at spawn time},
        }

    Note on time granularity: only `user` events carry raw timestamps in
    stream-json transcripts; everything else inherits the next real ts.
    As a result we cannot split a single turn's time into LLM vs. tool vs.
    hook — the whole gap between consecutive user events is one turn. We
    report the aggregate (total_s) and let the recursive subagent split
    carry most of the explanatory weight. Token and call counts are exact.
    """
    # Walk once to discover every Task/Agent spawn, its parent scope, and
    # which phase it was issued in. Sub-agents can spawn sub-sub-agents;
    # the tree is built from parent_tool_use_id on the spawning assistant.
    scope_parent: dict[str, str | None] = {}
    scope_info: dict[str, dict] = {}
    scope_spawn_phase: dict[str, str] = {}
    for (ev, _), phase in zip(events_ts, phases):
        if ev.get("type") != "assistant":
            continue
        my_scope = ev.get("parent_tool_use_id")
        for b in (ev.get("message", {}) or {}).get("content", []) or []:
            if b.get("type") != "tool_use":
                continue
            if b.get("name") not in ("Task", "Agent"):
                continue
            cid = b.get("id")
            if not cid:
                continue
            scope_parent[cid] = my_scope
            inp = b.get("input") or {}
            scope_info[cid] = {
                "type": inp.get("subagent_type") or "general-purpose",
                "description": inp.get("description") or "",
            }
            scope_spawn_phase[cid] = phase or "pre-phase"

    deltas: list[float] = []
    prev_ts: datetime | None = None
    for _, ts in events_ts:
        if ts is not None and prev_ts is not None:
            deltas.append(max(0.0, (ts - prev_ts).total_seconds()))
        else:
            deltas.append(0.0)
        if ts is not None:
            prev_ts = ts

    main_br: dict[str, dict] = {}
    sub_br: dict[str, dict[str, dict]] = {}

    def bucket_for(scope: str | None, phase_label: str) -> dict:
        if scope is None:
            return main_br.setdefault(phase_label, _empty_bucket())
        return sub_br.setdefault(scope, {}).setdefault(phase_label, _empty_bucket())

    seen_msg: set[tuple[str | None, str]] = set()
    last_scope: str | None = None
    for (ev, _ts), phase, delta in zip(events_ts, phases, deltas):
        et = ev.get("type")
        phase_label = phase or "pre-phase"
        if et in ("assistant", "user"):
            scope = ev.get("parent_tool_use_id")
        else:
            # System/hook/task events carry no parent_tool_use_id but run
            # within whatever scope last emitted real work — attribute to
            # the last seen assistant/user scope so hooks fired inside a
            # subagent's tool call land in the subagent's bucket.
            scope = last_scope
        b = bucket_for(scope, phase_label)
        b["total_s"] += delta

        if et == "assistant":
            msg = ev.get("message") or {}
            mid = msg.get("id")
            if mid and (scope, mid) not in seen_msg:
                seen_msg.add((scope, mid))
                usage = msg.get("usage") or {}
                b["output_tokens"] += int(usage.get("output_tokens") or 0)
            for blk in msg.get("content", []) or []:
                bt = blk.get("type")
                if bt == "thinking":
                    b["thinking_blocks"] += 1
                    b["thinking_tokens"] += len(blk.get("thinking", "")) // 4
                elif bt == "text":
                    b["text_blocks"] += 1
                    b["text_tokens"] += len(blk.get("text", "")) // 4
                elif bt == "tool_use":
                    b["tool_calls"] += 1
                    if blk.get("name") in ("Task", "Agent"):
                        b["subagent_spawns"] += 1
        elif et == "user":
            content = (ev.get("message") or {}).get("content", [])
            if isinstance(content, list):
                for blk in content:
                    if not isinstance(blk, dict) or blk.get("type") != "tool_result":
                        continue
                    b["tool_results"] += 1
                    cc = blk.get("content", "")
                    if isinstance(cc, list):
                        cc = "".join(
                            x.get("text", "") if isinstance(x, dict) else str(x)
                            for x in cc
                        )
                    b["tool_result_bytes"] += len(str(cc))
        elif et == "system" and ev.get("subtype") == "hook_response":
            b["hook_count"] += 1

        if et in ("assistant", "user"):
            last_scope = scope

    return {
        "main": main_br,
        "subs": sub_br,
        "parent": scope_parent,
        "info": scope_info,
        "spawn_phase": scope_spawn_phase,
    }


def summarize_phases(
    events_ts: list[tuple[dict, datetime | None]],
    phases: list[str | None],
    t0: datetime | None,
) -> list[dict]:
    """Contiguous phase segments with offsets + token counts.

    Returns dicts: {phase, start_s, end_s, duration_s, output_tokens, row_count}.
    Rows with no phase yet are bucketed as "pre-phase".
    """
    if not events_ts or t0 is None:
        return []
    segments: list[dict] = []
    cur_name: str | None = None
    cur: dict | None = None
    for (ev, ts), phase in zip(events_ts, phases):
        label = phase or "pre-phase"
        if label != cur_name:
            if cur is not None:
                segments.append(cur)
            cur_name = label
            cur = {
                "phase": label,
                "start_s": (ts - t0).total_seconds() if ts else None,
                "end_s": None,
                "output_tokens": 0,
                "row_count": 0,
            }
        if cur is not None:
            if ts is not None:
                cur["end_s"] = (ts - t0).total_seconds()
                if cur["start_s"] is None:
                    cur["start_s"] = cur["end_s"]
            cur["output_tokens"] += event_output_tokens(ev)
            cur["row_count"] += 1
    if cur is not None:
        segments.append(cur)
    for s in segments:
        if s["start_s"] is None:
            s["start_s"] = 0.0
        if s["end_s"] is None:
            s["end_s"] = s["start_s"]
        s["duration_s"] = max(0.0, s["end_s"] - s["start_s"])
    return segments


def _short(s: str, n: int = CONTENT_PREVIEW_CHARS) -> str:
    s = s.replace("\n", " ")
    if len(s) > n:
        return s[:n] + "…"
    return s


def render_content_block(block: dict) -> str:
    """Render one assistant/user content block."""
    btype = block.get("type", "other")
    if btype == "thinking":
        body = block.get("thinking", "")
        return (
            '<details class="blk thinking"><summary>'
            '<span class="btype">thinking</span> '
            f'<span class="meta">{html.escape(_short(body))}</span>'
            '</summary><pre>'
            f"{html.escape(body)}"
            "</pre></details>"
        )
    if btype == "text":
        body = block.get("text", "")
        return (
            '<details class="blk text" open><summary>'
            '<span class="btype">text</span> '
            f'<span class="meta">{html.escape(_short(body))}</span>'
            '</summary><pre>'
            f"{html.escape(body)}"
            "</pre></details>"
        )
    if btype == "tool_use":
        name = block.get("name", "?")
        tool_input = block.get("input", {})
        try:
            input_str = json.dumps(tool_input, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            input_str = repr(tool_input)
        preview = ""
        if isinstance(tool_input, dict):
            for key in ("description", "command", "file_path", "pattern", "prompt", "query"):
                if tool_input.get(key):
                    preview = str(tool_input[key])
                    break
        return (
            '<details class="blk tool_use" open><summary>'
            '<span class="btype">tool_use</span> '
            f'<span class="toolname">{html.escape(name)}</span> '
            f'<span class="meta">{html.escape(_short(preview))}</span>'
            '</summary><pre>'
            f"{html.escape(input_str)}"
            "</pre></details>"
        )
    if btype == "tool_result":
        content = block.get("content", "")
        is_error = block.get("is_error", False)
        if isinstance(content, list):
            content = "\n".join(
                c.get("text", "") if isinstance(c, dict) else str(c) for c in content
            )
        else:
            content = str(content)
        cls = "blk tool_result error" if is_error else "blk tool_result"
        return (
            f'<details class="{cls}"><summary>'
            '<span class="btype">tool_result</span> '
            f'<span class="meta">{html.escape(_short(content))}</span>'
            "</summary><pre>"
            f"{html.escape(content)}"
            "</pre></details>"
        )
    return (
        '<details class="blk other"><summary>'
        f'<span class="btype">{html.escape(btype)}</span>'
        "</summary><pre>"
        f"{html.escape(json.dumps(block, indent=2, ensure_ascii=False, default=str))}"
        "</pre></details>"
    )


def render_event(ev: dict, instance: str = "") -> str:
    """Return HTML for the content column of one event row.

    `instance` names the agent that produced this event (main / subagent
    label) so the reader can tell whose tool call this is.
    """
    etype = ev.get("type")
    subtype = ev.get("subtype")
    inst_html = (
        f'<span class="instance">{html.escape(instance)}</span>'
        if instance else ""
    )

    if etype == "assistant":
        msg = ev.get("message", {})
        model = msg.get("model", "?")
        content = msg.get("content", [])
        usage = msg.get("usage") or {}
        out_tok = usage.get("output_tokens")
        in_tok = usage.get("input_tokens")
        tok_meta = ""
        if out_tok is not None or in_tok is not None:
            tok_meta = f" in={in_tok or 0} out={out_tok or 0}"
        blocks_html = "".join(render_content_block(b) for b in content)
        return (
            f'<div class="ev-header">{inst_html}'
            f'<span class="tlabel assistant">assistant</span> '
            f'<span class="meta">model={html.escape(model)}{html.escape(tok_meta)}</span></div>'
            f"{blocks_html}"
        )
    if etype == "user":
        msg = ev.get("message", {})
        content = msg.get("content", [])
        if isinstance(content, list):
            blocks_html = "".join(render_content_block(b) for b in content)
        else:
            blocks_html = (
                '<details class="blk text" open><summary>'
                '<span class="btype">text</span></summary><pre>'
                f"{html.escape(str(content))}</pre></details>"
            )
        return (
            f'<div class="ev-header">{inst_html}'
            '<span class="tlabel user">user</span></div>'
            f"{blocks_html}"
        )
    if etype == "system" and subtype in ("hook_started", "hook_response"):
        hook_name = ev.get("hook_name", "?")
        event_name = ev.get("hook_event", "?")
        output = ev.get("output", "") or ev.get("stdout", "")
        stderr = ev.get("stderr", "")
        exit_code = ev.get("exit_code", "")
        outcome = ev.get("outcome", "")
        is_err = subtype == "hook_response" and (exit_code not in (0, "", None) or outcome == "error")
        cls = f"hook {'error' if is_err else ''}"
        meta = f"{event_name}:{hook_name}"
        if subtype == "hook_response":
            meta += f" exit={exit_code} outcome={outcome}"
        body_parts: list[str] = []
        if output:
            body_parts.append(output)
        if stderr:
            body_parts.append(f"--- stderr ---\n{stderr}")
        body = "\n".join(body_parts)
        # Only render the raw <details> if there's something to show — a
        # success-no-output hook is adequately described by the header meta.
        raw_html = ""
        if body:
            raw_html = (
                '<details class="blk other"><summary>raw</summary><pre>'
                f"{html.escape(body)}</pre></details>"
            )
        return (
            f'<div class="ev-header"><span class="tlabel {cls}">{html.escape(subtype)}</span> '
            f'<span class="meta">{html.escape(meta)}</span></div>'
            f"{raw_html}"
        )
    if etype == "system" and subtype in ("task_started", "task_notification", "task_progress"):
        desc = ev.get("description", "") or ev.get("summary", "")
        task_id = ev.get("task_id", "")
        return (
            f'<div class="ev-header"><span class="tlabel task">task/'
            f'{html.escape(str(subtype))}</span> '
            f'<span class="meta">{html.escape(task_id)} {html.escape(desc)}</span></div>'
        )
    if etype == "system" and subtype == "init":
        model = ev.get("model", "") or ev.get("session_id", "")
        return (
            '<div class="ev-header"><span class="tlabel system">init</span> '
            f'<span class="meta">model={html.escape(str(model))}</span></div>'
            '<details class="blk other"><summary>raw</summary><pre>'
            f"{html.escape(json.dumps(ev, indent=2, default=str))}</pre></details>"
        )
    if etype == "system":
        return (
            '<div class="ev-header"><span class="tlabel system">system/'
            f'{html.escape(str(subtype))}</span></div>'
        )
    if etype == "result":
        result = ev.get("result", "")
        cost = ev.get("total_cost_usd", "")
        duration = ev.get("duration_ms", 0)
        return (
            '<div class="ev-header"><span class="tlabel result">result</span> '
            f'<span class="meta">{subtype} '
            f'duration={int(duration)/1000:.1f}s cost=${cost}</span></div>'
            '<details class="blk text" open><summary>'
            '<span class="btype">result</span></summary><pre>'
            f"{html.escape(str(result))}</pre></details>"
        )
    if etype == "rate_limit_event":
        info = ev.get("rate_limit_info", {})
        return (
            '<div class="ev-header"><span class="tlabel ratelimit">rate_limit</span> '
            f'<span class="meta">{html.escape(json.dumps(info, default=str))}</span></div>'
        )
    return (
        '<div class="ev-header"><span class="tlabel other">'
        f"{html.escape(str(etype))}</span></div>"
        '<details class="blk other"><summary>raw</summary><pre>'
        f"{html.escape(json.dumps(ev, indent=2, default=str))}</pre></details>"
    )


def row_type_class(ev: dict) -> str:
    """Row-level class. Hook events get their own `type-hook` class so
    filters can target them directly; the 'hide system' filter covers
    hooks as well (they're system infrastructure, not user-visible work)."""
    etype = ev.get("type", "other")
    subtype = ev.get("subtype", "")
    if etype == "system" and subtype in ("hook_started", "hook_response"):
        return "type-hook"
    if etype == "system" and subtype in ("task_started", "task_notification", "task_progress"):
        return "type-task"
    return f"type-{etype}"


def fmt_delta(seconds: float | None) -> str:
    if seconds is None:
        return ""
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{int(m)}m{int(s):02d}s"
    h, m = divmod(m, 60)
    return f"{int(h)}h{int(m):02d}m"


PHASE_COLORS = {
    "pre-phase": "#bdbdbd",
    "CONTEXTUALIZE": "#90caf9",
    "SCREEN": "#ce93d8",
    "HYPOTHESIZE": "#f48fb1",
    "GATHER": "#a5d6a7",
    "ANALYZE": "#ffcc80",
    "CONCLUDE": "#ef9a9a",
}


def render_timeline_bar(segments: list[dict]) -> str:
    if not segments:
        return ""
    total = sum(s["duration_s"] for s in segments) or 1.0
    parts = []
    legend = []
    for seg in segments:
        if seg["duration_s"] <= 0 and len(segments) > 1:
            # Zero-width phases would collapse; show them as a thin sliver.
            pct = 0.5
        else:
            pct = max(0.5, 100.0 * seg["duration_s"] / total)
        color = PHASE_COLORS.get(seg["phase"], "#cfd8dc")
        title = (
            f"{seg['phase']} · {fmt_delta(seg['duration_s'])} · "
            f"{seg['output_tokens']} out tok · {seg['row_count']} rows"
        )
        parts.append(
            f'<div class="tl-seg" style="flex:{pct:.2f} 0 0;background:{color}" '
            f'title="{html.escape(title)}">'
            f'<span class="tl-name">{html.escape(seg["phase"])}</span>'
            f'<span class="tl-meta">{fmt_delta(seg["duration_s"])} · '
            f'{seg["output_tokens"]}tok</span>'
            "</div>"
        )
        legend.append(
            f'<span class="tl-legend-item"><span class="tl-sw" '
            f'style="background:{color}"></span>{html.escape(seg["phase"])} '
            f'({fmt_delta(seg["duration_s"])}, {seg["output_tokens"]}tok)</span>'
        )
    return (
        '<div class="timeline">'
        f'<div class="tl-bar">{"".join(parts)}</div>'
        f'<div class="tl-legend">{" ".join(legend)}</div>'
        "</div>"
    )


def _sum_subtree_s(
    scope_id: str,
    children: dict[str | None, list[str]],
    sub_br: dict[str, dict[str, dict]],
) -> float:
    """Recursive total wall time spent inside `scope_id` and its descendants."""
    own = sum(b["total_s"] for b in sub_br.get(scope_id, {}).values())
    for child in children.get(scope_id, []):
        own += _sum_subtree_s(child, children, sub_br)
    return own


def _render_metric_row(
    label: str, seconds: float | None, denom: float, extras: str, cls: str = "",
) -> str:
    """One metric row. `seconds` may be None for count-only rows (tokens,
    tool calls) where wall time isn't separable from the turn total."""
    if seconds is None:
        dur_cell = '<td class="br-dur br-dur-na">—</td><td class="br-pct"></td><td class="br-bar"></td>'
    else:
        pct = (100.0 * seconds / denom) if denom > 0 else 0.0
        bar_w = min(100.0, pct)
        dur_cell = (
            f'<td class="br-dur">{fmt_delta(seconds)}</td>'
            f'<td class="br-pct">{pct:4.1f}%</td>'
            f'<td class="br-bar"><div class="br-fill" style="width:{bar_w:.1f}%"></div></td>'
        )
    return (
        f'<tr class="br-row {cls}">'
        f'<td class="br-lbl">{html.escape(label)}</td>'
        f'{dur_cell}'
        f'<td class="br-x">{extras}</td>'
        "</tr>"
    )


def _render_scope_breakdown(
    scope_title: str,
    scope_color: str,
    bucket: dict,
    scope_id: str | None,
    phase_label: str,
    children: dict[str | None, list[str]],
    sub_br: dict[str, dict[str, dict]],
    scope_info: dict[str, dict],
    scope_spawn_phase: dict[str, str],
    outer_total_s: float,
    depth: int = 0,
) -> str:
    """Render one scope's breakdown (main or subagent) as a details block.

    `outer_total_s` is the enclosing block's wall-clock span — for a phase
    that's the phase duration, for a subagent it's the subagent's own
    lifetime. It's used to compute percentage bars.

    Two rows carry real wall-clock time:
      • self-work   = bucket.total_s (time when events in this scope fired)
      • subagents   = Σ descendant scope totals (time spent inside children)
    The rest (thinking, text, tool calls, tool results, hooks) are counts
    only — stream-json transcripts only carry real timestamps on `user`
    events, so we can't split a single turn's time into LLM vs tool vs
    hook. Subagent recursion is what actually separates work by actor.
    """
    if scope_id is None:
        own_children = [cid for cid in children.get(None, [])
                        if scope_spawn_phase.get(cid) == phase_label]
    else:
        own_children = list(children.get(scope_id, []))

    sub_total_s = sum(_sum_subtree_s(c, children, sub_br) for c in own_children)
    self_total_s = bucket["total_s"]
    denom = outer_total_s if outer_total_s > 0 else (self_total_s + sub_total_s)

    thinking_extra = (
        f'{bucket["thinking_tokens"]:,} tok · {bucket["thinking_blocks"]} blocks'
    )
    text_extra = (
        f'{bucket["text_tokens"]:,} tok · {bucket["text_blocks"]} blocks'
    )
    tool_call_extra = (
        f'{bucket["tool_calls"]} calls' + (
            f' · {bucket["subagent_spawns"]} subagent spawn(s)'
            if bucket["subagent_spawns"] else ""
        )
    )
    tool_result_extra = (
        f'{bucket["tool_results"]} results · {bucket["tool_result_bytes"]:,} B'
    )
    hook_extra = f'{bucket["hook_count"]} hook calls'

    rows: list[str] = []
    rows.append(_render_metric_row("self-work wall time", self_total_s, denom,
                                    f'{bucket["output_tokens"]:,} out tok',
                                    "br-self"))
    rows.append(_render_metric_row("  thinking", None, denom, thinking_extra, "br-think"))
    rows.append(_render_metric_row("  text output", None, denom, text_extra, "br-text"))
    rows.append(_render_metric_row("  tool calls", None, denom, tool_call_extra, "br-toolcall"))
    rows.append(_render_metric_row("  tool results", None, denom, tool_result_extra, "br-toolres"))
    if bucket["hook_count"]:
        rows.append(_render_metric_row("  hooks", None, denom, hook_extra, "br-hook"))
    if own_children:
        rows.append(_render_metric_row(
            f"subagents ({len(own_children)})", sub_total_s, denom,
            "expand for recursive breakdown", "br-subagents",
        ))

    children_html = ""
    if own_children:
        parts: list[str] = []
        for cid in own_children:
            info = scope_info.get(cid, {})
            stype = info.get("type", "?")
            desc = info.get("description", "")
            # A subagent runs synchronously inside its parent turn; its
            # events all inherit the phase that was active at spawn, so
            # collapse its per-phase buckets into a single aggregate.
            agg: dict = _empty_bucket()
            for ph_b in sub_br.get(cid, {}).values():
                for k in agg:
                    agg[k] += ph_b[k]
            sub_full_s = _sum_subtree_s(cid, children, sub_br)
            title = stype + (f' — {desc}' if desc else '')
            parts.append(_render_scope_breakdown(
                title,
                "#dcdcdc",
                agg,
                cid,
                phase_label,
                children,
                sub_br,
                scope_info,
                scope_spawn_phase,
                sub_full_s,
                depth + 1,
            ))
        children_html = f'<div class="br-children">{"".join(parts)}</div>'

    open_attr = " open" if depth < 1 else ""
    header_total = outer_total_s if outer_total_s > 0 else (self_total_s + sub_total_s)
    header_html = (
        '<summary class="br-summary">'
        f'<span class="br-swatch" style="background:{scope_color}"></span>'
        f'<span class="br-title">{html.escape(scope_title)}</span>'
        f'<span class="br-total">{fmt_delta(header_total)}</span>'
        f'<span class="br-meta">{bucket["output_tokens"]:,} out tok</span>'
        "</summary>"
    )
    return (
        f'<details class="br-scope depth-{depth}"{open_attr}>'
        f'{header_html}'
        f'<table class="br-table"><tbody>{"".join(rows)}</tbody></table>'
        f'{children_html}'
        "</details>"
    )


def render_breakdown_tree(
    segments: list[dict],
    breakdowns: dict,
) -> str:
    """Top-level recursive breakdown: one block per phase, nested per scope.

    Phase duration comes from the timeline segments (authoritative wall
    clock). Within each phase the main agent's self-work and subagent
    spawns are rendered; subagents recursively expand into the same shape.
    """
    if not breakdowns or not segments:
        return ""
    main_br = breakdowns["main"]
    sub_br = breakdowns["subs"]
    scope_parent = breakdowns["parent"]
    scope_info = breakdowns["info"]
    scope_spawn_phase = breakdowns["spawn_phase"]

    children: dict[str | None, list[str]] = {}
    for cid, pid in scope_parent.items():
        children.setdefault(pid, []).append(cid)

    phase_dur: dict[str, float] = {}
    phase_order: list[str] = []
    seen_phases: set[str] = set()
    for s in segments:
        name = s["phase"]
        phase_dur[name] = phase_dur.get(name, 0.0) + s["duration_s"]
        if name not in seen_phases:
            seen_phases.add(name)
            phase_order.append(name)

    blocks: list[str] = []
    for phase in phase_order:
        dur = phase_dur.get(phase, 0.0)
        color = PHASE_COLORS.get(phase, "#cfd8dc")
        main_bucket = main_br.get(phase, _empty_bucket())
        blocks.append(_render_scope_breakdown(
            phase, color, main_bucket, None, phase,
            children, sub_br, scope_info, scope_spawn_phase,
            dur, depth=0,
        ))

    return (
        '<details class="activity" open>'
        '<summary>phase activity breakdown</summary>'
        f'<div class="br-tree">{"".join(blocks)}</div>'
        "</details>"
    )


def render_html(
    eval_dir: Path,
    events_ts: list[tuple[dict, datetime | None]],
    phases: list[str | None],
) -> str:
    t0 = next((ts for _, ts in events_ts if ts is not None), None)
    segments = summarize_phases(events_ts, phases, t0)
    raw_events = [ev for ev, _ in events_ts]
    subagent_idx = build_subagent_index(raw_events)
    breakdowns = compute_breakdowns(events_ts, phases)

    rows: list[str] = []
    prev_ts: datetime | None = None
    for (ev, ts), phase in zip(events_ts, phases):
        offset = fmt_delta((ts - t0).total_seconds()) if (ts and t0) else ""
        delta_s = (ts - prev_ts).total_seconds() if (ts and prev_ts) else None
        delta_txt = fmt_delta(delta_s) if delta_s is not None else ""
        slow = (delta_s is not None and delta_s >= SLOW_GAP_SECONDS)
        if ts is not None:
            prev_ts = ts

        subtype = ev.get("subtype", "")
        row_class = f"row {row_type_class(ev)}"
        if subtype:
            row_class += f" sub-{subtype}"
        if slow:
            row_class += " slow"
        phase_label = phase or "pre-phase"
        phase_color = PHASE_COLORS.get(phase_label, "#cfd8dc")

        inst = instance_label(ev, subagent_idx)
        rows.append(
            f'<div class="{row_class}" data-phase="{html.escape(phase_label)}">'
            f'<div class="ts">'
            f'<span class="offset">{offset}</span>'
            f'<span class="delta{" slow" if slow else ""}">{delta_txt}</span>'
            f'<span class="phase-chip" style="background:{phase_color}">{html.escape(phase_label)}</span>'
            f'</div>'
            f'<div class="content">{render_event(ev, inst)}</div>'
            "</div>"
        )

    rows_html = "\n".join(rows)
    title = f"Transcript · {eval_dir.name}"
    timeline_html = render_timeline_bar(segments)
    activity_html = render_breakdown_tree(segments, breakdowns)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif;
       font-size: 13px; margin: 0; padding: 0; background: #fafafa; color: #222; }}
header {{ position: sticky; top: 0; background: #fff; border-bottom: 1px solid #ddd;
         padding: 10px 16px; z-index: 10; }}
header h1 {{ font-size: 15px; margin: 0 0 6px 0; font-weight: 600; }}
header .filters {{ display: flex; gap: 12px; flex-wrap: wrap; font-size: 12px;
                  align-items: center; margin-top: 6px; }}
header label {{ cursor: pointer; user-select: none; }}
header button {{ font-size: 12px; padding: 2px 8px; cursor: pointer; }}
header input[type="search"] {{ font-size: 12px; padding: 3px 6px; width: 260px;
                              border: 1px solid #bbb; border-radius: 3px; }}
.timeline {{ margin: 6px 0 4px 0; }}
.tl-bar {{ display: flex; height: 28px; border: 1px solid #ccc; border-radius: 3px;
          overflow: hidden; }}
.tl-seg {{ display: flex; flex-direction: column; justify-content: center;
          align-items: center; font-size: 10px; color: #222; padding: 0 4px;
          min-width: 0; overflow: hidden; white-space: nowrap; border-right: 1px solid rgba(0,0,0,0.1); }}
.tl-seg:last-child {{ border-right: none; }}
.tl-name {{ font-weight: 600; }}
.tl-meta {{ color: #444; }}
.tl-legend {{ margin-top: 4px; font-size: 11px; color: #555;
             display: flex; gap: 10px; flex-wrap: wrap; }}
.tl-sw {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px;
         margin-right: 3px; vertical-align: middle; }}
.row {{ display: flex; border-bottom: 1px solid #eee; padding: 6px 12px; gap: 12px; }}
.row:hover {{ background: #f3f6fb; }}
.row.slow {{ background: #fff6f6; }}
.ts {{ flex: 0 0 110px; color: #666; font-family: monospace; font-size: 11px;
       display: flex; flex-direction: column; }}
.ts .offset {{ color: #222; font-weight: 500; }}
.ts .delta {{ color: #999; }}
.ts .delta.slow {{ color: #c33; font-weight: 600; }}
.ts .phase-chip {{ font-family: -apple-system, sans-serif; font-size: 9px;
                  font-weight: 600; padding: 1px 4px; border-radius: 2px;
                  margin-top: 2px; color: #222; text-align: center; }}
.content {{ flex: 1 1 auto; min-width: 0; }}
.ev-header {{ margin-bottom: 4px; }}
.tlabel {{ display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px;
          font-weight: 600; margin-right: 6px; }}
.tlabel.assistant {{ background: #e3f2fd; color: #0d47a1; }}
.tlabel.user {{ background: #f3e5f5; color: #4a148c; }}
.tlabel.hook {{ background: #fff3e0; color: #e65100; }}
.tlabel.hook.error {{ background: #ffebee; color: #b71c1c; }}
.tlabel.task {{ background: #e8f5e9; color: #1b5e20; }}
.tlabel.system {{ background: #eceff1; color: #37474f; }}
.tlabel.result {{ background: #fce4ec; color: #880e4f; }}
.tlabel.ratelimit {{ background: #fffde7; color: #827717; }}
.tlabel.other {{ background: #eee; color: #555; }}
.meta {{ color: #666; font-size: 11px; }}
.blk {{ margin: 3px 0; padding: 0; font-size: 12px; }}
.blk > summary {{ cursor: pointer; padding: 3px 6px; border-radius: 3px;
                 background: #f0f0f0; list-style: none; }}
.blk > summary::-webkit-details-marker {{ display: none; }}
.blk > summary::before {{ content: '▸ '; color: #888; }}
.blk[open] > summary::before {{ content: '▾ '; }}
.blk.thinking > summary {{ background: #f8f3ff; color: #4a148c; }}
.blk.text > summary {{ background: #f0f7ff; }}
.blk.tool_use > summary {{ background: #e8f5e9; }}
.blk.tool_use .toolname {{ font-weight: 600; font-family: monospace; }}
.blk.tool_result > summary {{ background: #fff8e1; }}
.blk.tool_result.error > summary {{ background: #ffebee; color: #b71c1c; }}
.btype {{ font-weight: 600; font-size: 11px; text-transform: uppercase;
          letter-spacing: 0.5px; }}
pre {{ white-space: pre-wrap; word-wrap: break-word; margin: 6px 0 0 18px;
       padding: 6px 8px; background: #fff; border: 1px solid #ddd;
       border-radius: 3px; max-height: 500px; overflow: auto;
       font-family: Menlo, Monaco, Consolas, monospace; font-size: 11px; }}
/* Filters */
body.hide-system .row.type-system,
body.hide-system .row.type-hook {{ display: none; }}
body.hide-task .row.type-task {{ display: none; }}
body.hide-hook .row.type-hook {{ display: none; }}
body.hide-ratelimit .row.type-rate_limit_event {{ display: none; }}
body.only-slow .row:not(.slow) {{ display: none; }}
/* Instance badge (main / subagent) */
.instance {{ display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px;
            font-weight: 600; background: #e0e0e0; color: #333; margin-right: 6px;
            font-family: monospace; }}
/* Activity breakdown tree (per-phase, recursive into subagents) */
.activity {{ margin: 6px 0 0 0; font-size: 11px; }}
.activity > summary {{ cursor: pointer; color: #444; padding: 2px 0; }}
.br-tree {{ margin-top: 4px; display: flex; flex-direction: column; gap: 4px; }}
.br-scope {{ border: 1px solid #e0e0e0; border-radius: 4px; background: #fff; }}
.br-scope.depth-0 {{ border-left: 3px solid #888; }}
.br-scope.depth-1 {{ border-left: 3px solid #b0b0b0; margin: 2px 0 2px 14px; }}
.br-scope.depth-2 {{ border-left: 3px solid #ccc; margin: 2px 0 2px 14px; }}
.br-summary {{ cursor: pointer; padding: 4px 8px; list-style: none;
               display: flex; align-items: center; gap: 8px; font-size: 11px;
               background: #fafafa; border-radius: 3px; }}
.br-summary::-webkit-details-marker {{ display: none; }}
.br-summary::before {{ content: '▸'; color: #888; width: 10px; display: inline-block; }}
.br-scope[open] > .br-summary::before {{ content: '▾'; }}
.br-swatch {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px; }}
.br-title {{ font-weight: 600; font-family: monospace; font-size: 11px; color: #222;
             flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis;
             white-space: nowrap; }}
.br-total {{ font-family: monospace; color: #333; font-weight: 600; }}
.br-meta {{ color: #666; font-family: monospace; font-size: 10px; }}
.br-table {{ width: 100%; border-collapse: collapse; font-size: 11px;
             margin: 0; padding: 4px 8px 6px 8px; }}
.br-table td {{ padding: 2px 6px; vertical-align: middle; }}
.br-row .br-lbl {{ width: 160px; color: #444; font-weight: 500; white-space: pre; }}
.br-row .br-dur {{ width: 60px; font-family: monospace; text-align: right; color: #222; }}
.br-row .br-dur-na {{ color: #bbb; }}
.br-row .br-pct {{ width: 52px; font-family: monospace; text-align: right; color: #777; }}
.br-row .br-bar {{ width: 22%; min-width: 80px; }}
.br-row .br-bar .br-fill {{ height: 6px; border-radius: 3px; background: #90caf9; }}
.br-row .br-x {{ color: #555; font-size: 10px; }}
.br-row.br-self .br-fill {{ background: #90caf9; }}
.br-row.br-subagents .br-fill {{ background: #ce93d8; }}
.br-row.br-think {{ color: #7e57c2; }}
.br-row.br-text {{ color: #546e7a; }}
.br-row.br-toolcall {{ color: #2e7d32; }}
.br-row.br-toolres {{ color: #ef6c00; }}
.br-row.br-hook {{ color: #8d6e63; }}
.br-children {{ padding: 2px 6px 6px 6px; }}
/* Search: JS sets .row.search-hit on matches and body.search-active when
   the query is non-empty. Non-matches are hidden only while search-active. */
body.search-active .row:not(.search-hit) {{ display: none; }}
</style></head><body>
<header>
  <h1>{html.escape(title)}</h1>
  {timeline_html}
  {activity_html}
  <div class="filters">
    <input type="search" id="q" placeholder="search rows… (case-insensitive)">
    <label><input type="checkbox" id="f-system" checked> hide system (incl. hooks)</label>
    <label><input type="checkbox" id="f-task" checked> hide task</label>
    <label><input type="checkbox" id="f-hook"> hide hooks only</label>
    <label><input type="checkbox" id="f-ratelimit" checked> hide rate_limit</label>
    <label><input type="checkbox" id="f-slow"> only slow rows (≥{SLOW_GAP_SECONDS:.0f}s)</label>
    <button id="expand-all">expand all</button>
    <button id="collapse-all">collapse all</button>
    <span class="meta">{len(events_ts)} events · {len(segments)} phase segments</span>
  </div>
</header>
<main>
{rows_html}
</main>
<script>
const body = document.body;
function bind(id, cls) {{
  const el = document.getElementById(id);
  const apply = () => body.classList.toggle(cls, el.checked);
  el.addEventListener('change', apply); apply();
}}
bind('f-system', 'hide-system');
bind('f-task', 'hide-task');
bind('f-hook', 'hide-hook');
bind('f-ratelimit', 'hide-ratelimit');
bind('f-slow', 'only-slow');
document.getElementById('expand-all').addEventListener('click', () =>
  document.querySelectorAll('details').forEach(d => d.open = true));
document.getElementById('collapse-all').addEventListener('click', () =>
  document.querySelectorAll('details').forEach(d => d.open = false));

// Free-text search: hide rows whose textContent doesn't include the query.
const rows = Array.from(document.querySelectorAll('.row'));
const q = document.getElementById('q');
let timer = null;
q.addEventListener('input', () => {{
  clearTimeout(timer);
  timer = setTimeout(runSearch, 80);
}});
function runSearch() {{
  const needle = q.value.trim().toLowerCase();
  if (!needle) {{
    body.classList.remove('search-active');
    rows.forEach(r => r.classList.remove('search-hit'));
    return;
  }}
  body.classList.add('search-active');
  for (const r of rows) {{
    if (r.textContent.toLowerCase().includes(needle)) {{
      r.classList.add('search-hit');
    }} else {{
      r.classList.remove('search-hit');
    }}
  }}
}}
</script>
</body></html>
"""


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("eval_dir", help="Path to eval run dir containing transcript.jsonl")
    p.add_argument("-o", "--output",
                   help="Output HTML path (default: <eval_dir>/transcript.html)")
    args = p.parse_args()

    eval_dir = Path(args.eval_dir).resolve()
    transcript = eval_dir / "transcript.jsonl"
    if not transcript.exists():
        print(f"error: {transcript} not found", file=sys.stderr)
        return 1

    events = load_events(transcript)
    events_ts = attach_timestamps(events)
    phases = compute_phases(events_ts)

    out_path = Path(args.output) if args.output else eval_dir / "transcript.html"
    out_path.write_text(render_html(eval_dir, events_ts, phases))
    print(f"wrote {out_path} ({len(events)} events)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
