#!/usr/bin/env python3
"""Render an eval run transcript.jsonl as a single-file HTML timeline.

Each event row shows:
- absolute offset from t0 (the first user-event timestamp)
- duration since the previous timestamped event
- event type badge
- content blocks (thinking, text, tool_use, tool_result, hook payload)

Usage:
    render_transcript.py <eval_dir> [-o transcript.html]

Only `user` events carry timestamps in stream-json transcripts. Events
without a timestamp inherit the next timestamped event's time (they
occurred during that wait), so an assistant message + its hooks render
as a single segment ending at the user tool_result that followed them.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SLOW_GAP_SECONDS = 5.0
CONTENT_PREVIEW_CHARS = 120


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
    # First pass: direct timestamps.
    with_direct: list[tuple[dict, datetime | None]] = []
    for ev in events:
        ts = None
        if ev.get("type") == "user":
            ts = iso_parse(ev.get("timestamp", ""))
        elif ev.get("type") == "assistant":
            ts = iso_parse(ev.get("timestamp", ""))
        elif ev.get("type") == "system" and ev.get("subtype") in ("hook_response", "hook_started"):
            # Hook events sometimes carry their own timestamp field.
            ts = iso_parse(ev.get("timestamp", ""))
        with_direct.append((ev, ts))

    # Second pass: forward-fill from the next timestamped event.
    # Walk backwards; any None inherits the next (later) ts we already saw.
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
        # Preview: description or first input field value.
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
        blocks_html = "".join(render_content_block(b) for b in content)
        return (
            f'<div class="ev-header"><span class="tlabel assistant">assistant</span> '
            f'<span class="meta">model={html.escape(model)}</span></div>'
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


def render_html(eval_dir: Path, events_ts: list[tuple[dict, datetime | None]],
                run_dir: Path | None) -> str:
    # t0 = first non-None timestamp.
    t0 = next((ts for _, ts in events_ts if ts is not None), None)

    rows: list[str] = []
    prev_ts: datetime | None = None
    for ev, ts in events_ts:
        offset = fmt_delta((ts - t0).total_seconds()) if (ts and t0) else ""
        delta_s = (ts - prev_ts).total_seconds() if (ts and prev_ts) else None
        delta_txt = fmt_delta(delta_s) if delta_s is not None else ""
        slow = (delta_s is not None and delta_s >= SLOW_GAP_SECONDS)
        if ts is not None:
            prev_ts = ts

        etype = ev.get("type", "other")
        subtype = ev.get("subtype", "")
        row_class = f"row type-{etype}"
        if subtype:
            row_class += f" sub-{subtype}"
        if slow:
            row_class += " slow"

        rows.append(
            f'<div class="{row_class}">'
            f'<div class="ts"><span class="offset">{offset}</span>'
            f'<span class="delta{" slow" if slow else ""}">{delta_txt}</span></div>'
            f'<div class="content">{render_event(ev)}</div>'
            "</div>"
        )

    rows_html = "\n".join(rows)
    title = f"Transcript · {eval_dir.name}"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif;
       font-size: 13px; margin: 0; padding: 0; background: #fafafa; color: #222; }}
header {{ position: sticky; top: 0; background: #fff; border-bottom: 1px solid #ddd;
         padding: 10px 16px; z-index: 10; }}
header h1 {{ font-size: 15px; margin: 0 0 6px 0; font-weight: 600; }}
header .filters {{ display: flex; gap: 12px; flex-wrap: wrap; font-size: 12px; }}
header label {{ cursor: pointer; user-select: none; }}
header button {{ font-size: 12px; padding: 2px 8px; cursor: pointer; }}
.row {{ display: flex; border-bottom: 1px solid #eee; padding: 6px 12px; gap: 12px; }}
.row:hover {{ background: #f3f6fb; }}
.row.slow {{ background: #fff6f6; }}
.ts {{ flex: 0 0 110px; color: #666; font-family: monospace; font-size: 11px;
       display: flex; flex-direction: column; }}
.ts .offset {{ color: #222; font-weight: 500; }}
.ts .delta {{ color: #999; }}
.ts .delta.slow {{ color: #c33; font-weight: 600; }}
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
body.hide-ratelimit .row.type-rate_limit_event {{ display: none; }}
body.only-slow .row:not(.slow) {{ display: none; }}
</style></head><body>
<header>
  <h1>{html.escape(title)}</h1>
  <div class="filters">
    <label><input type="checkbox" id="f-system" checked> hide system/task events</label>
    <label><input type="checkbox" id="f-ratelimit" checked> hide rate_limit</label>
    <label><input type="checkbox" id="f-slow"> only slow rows (≥{SLOW_GAP_SECONDS:.0f}s)</label>
    <button id="expand-all">expand all</button>
    <button id="collapse-all">collapse all</button>
    <span class="meta">{len(events_ts)} events</span>
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
bind('f-ratelimit', 'hide-ratelimit');
bind('f-slow', 'only-slow');
document.getElementById('expand-all').addEventListener('click', () =>
  document.querySelectorAll('details').forEach(d => d.open = true));
document.getElementById('collapse-all').addEventListener('click', () =>
  document.querySelectorAll('details').forEach(d => d.open = false));
</script>
</body></html>
"""


def find_run_dir(eval_dir: Path) -> Path | None:
    runs = eval_dir / "runs"
    if not runs.exists():
        return None
    candidates = [d for d in runs.iterdir() if d.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda d: d.stat().st_mtime)


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
    run_dir = find_run_dir(eval_dir)

    out_path = Path(args.output) if args.output else eval_dir / "transcript.html"
    out_path.write_text(render_html(eval_dir, events_ts, run_dir))
    print(f"wrote {out_path} ({len(events)} events)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
