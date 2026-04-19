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
    """Return a parallel list of phase names (None before the first header)."""
    phases: list[str | None] = []
    current: str | None = None
    for ev, _ in events_ts:
        new_phase = detect_phase_for_event(ev)
        if new_phase is not None:
            current = new_phase
        phases.append(current)
    return phases


def event_output_tokens(ev: dict) -> int:
    """Best-effort output-token count for an assistant message."""
    if ev.get("type") != "assistant":
        return 0
    usage = ev.get("message", {}).get("usage") or {}
    return int(usage.get("output_tokens") or 0)


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


def render_event(ev: dict) -> str:
    """Return HTML for the content column of one event row."""
    etype = ev.get("type")
    subtype = ev.get("subtype")

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
            f'<div class="ev-header"><span class="tlabel assistant">assistant</span> '
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
            '<div class="ev-header"><span class="tlabel user">user</span></div>'
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
        body = output
        if stderr:
            body += f"\n--- stderr ---\n{stderr}"
        return (
            f'<div class="ev-header"><span class="tlabel {cls}">{html.escape(subtype)}</span> '
            f'<span class="meta">{html.escape(meta)}</span></div>'
            '<details class="blk other"><summary>raw</summary><pre>'
            f"{html.escape(body)}</pre></details>"
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
    """Row-level class. Hook events get their own type (`type-tool`) so the
    'hide system' filter doesn't also hide them — they represent tool-call
    lifecycle, not system infra."""
    etype = ev.get("type", "other")
    subtype = ev.get("subtype", "")
    if etype == "system" and subtype in ("hook_started", "hook_response"):
        return "type-tool"
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


def render_html(
    eval_dir: Path,
    events_ts: list[tuple[dict, datetime | None]],
    phases: list[str | None],
) -> str:
    t0 = next((ts for _, ts in events_ts if ts is not None), None)
    segments = summarize_phases(events_ts, phases, t0)

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

        rows.append(
            f'<div class="{row_class}" data-phase="{html.escape(phase_label)}">'
            f'<div class="ts">'
            f'<span class="offset">{offset}</span>'
            f'<span class="delta{" slow" if slow else ""}">{delta_txt}</span>'
            f'<span class="phase-chip" style="background:{phase_color}">{html.escape(phase_label)}</span>'
            f'</div>'
            f'<div class="content">{render_event(ev)}</div>'
            "</div>"
        )

    rows_html = "\n".join(rows)
    title = f"Transcript · {eval_dir.name}"
    timeline_html = render_timeline_bar(segments)
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
body.hide-system .row.type-system {{ display: none; }}
body.hide-task .row.type-task {{ display: none; }}
body.hide-tool .row.type-tool {{ display: none; }}
body.hide-ratelimit .row.type-rate_limit_event {{ display: none; }}
body.only-slow .row:not(.slow) {{ display: none; }}
/* Search: JS sets .row.search-hit on matches and body.search-active when
   the query is non-empty. Non-matches are hidden only while search-active. */
body.search-active .row:not(.search-hit) {{ display: none; }}
</style></head><body>
<header>
  <h1>{html.escape(title)}</h1>
  {timeline_html}
  <div class="filters">
    <input type="search" id="q" placeholder="search rows… (case-insensitive)">
    <label><input type="checkbox" id="f-system" checked> hide system</label>
    <label><input type="checkbox" id="f-task" checked> hide task</label>
    <label><input type="checkbox" id="f-tool"> hide tool events</label>
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
bind('f-tool', 'hide-tool');
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
