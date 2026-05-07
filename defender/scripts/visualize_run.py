#!/usr/bin/env python3
"""Render a defender run as a single self-contained HTML transcript.

Reads `tool_trace.jsonl` (the stream-json output captured by run.sh),
plus the artifact files in the run dir, and writes `transcript.html`
in the same dir.

Usage:
    python3 defender/scripts/visualize_run.py <run_dir>

The HTML is intentionally self-contained — no external CSS, no JS
beyond a tiny collapse toggle — so it can be opened from any browser
or shipped as a review artifact alongside the rest of the run.
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path


def esc(s: str) -> str:
    return html.escape(s if isinstance(s, str) else json.dumps(s, indent=2))


def load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    events: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"type": "_parse_error", "raw": line})
    return events


def block_html(kind: str, title: str, body: str, *, open_: bool = True) -> str:
    open_attr = " open" if open_ else ""
    return (
        f'<details class="block {kind}"{open_attr}>'
        f'<summary>{esc(title)}</summary>'
        f'<div class="body">{body}</div>'
        f'</details>'
    )


def render_text(text: str) -> str:
    return f'<pre class="text">{esc(text)}</pre>'


def render_json(obj) -> str:
    try:
        rendered = json.dumps(obj, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        rendered = str(obj)
    return f'<pre class="json">{esc(rendered)}</pre>'


def render_tool_use(block: dict) -> str:
    name = block.get("name", "?")
    tid = block.get("id", "")
    inp = block.get("input", {})
    return block_html(
        "tool-use",
        f"→ {name}  ({tid})",
        render_json(inp),
    )


def render_tool_result(block: dict) -> str:
    tid = block.get("tool_use_id", "")
    content = block.get("content", "")
    is_error = block.get("is_error", False)
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                parts.append(c.get("text", ""))
            else:
                parts.append(json.dumps(c))
        body = "\n".join(parts)
    else:
        body = str(content)
    label = "← tool_result" + (" [error]" if is_error else "")
    return block_html(
        "tool-result" + (" error" if is_error else ""),
        f"{label}  ({tid})",
        render_text(body),
        open_=False,
    )


def render_thinking(block: dict) -> str:
    return block_html(
        "thinking",
        "thinking",
        render_text(block.get("thinking", "")),
        open_=False,
    )


def render_text_block(block: dict) -> str:
    return f'<div class="text-block">{esc(block.get("text", ""))}</div>'


def render_assistant(message: dict) -> str:
    content = message.get("content", [])
    parts: list[str] = []
    for blk in content:
        t = blk.get("type")
        if t == "text":
            parts.append(render_text_block(blk))
        elif t == "thinking":
            parts.append(render_thinking(blk))
        elif t == "tool_use":
            parts.append(render_tool_use(blk))
        else:
            parts.append(render_json(blk))
    return "\n".join(parts)


def render_user(message: dict) -> str:
    content = message.get("content", [])
    if isinstance(content, str):
        return render_text(content)
    parts: list[str] = []
    for blk in content:
        if not isinstance(blk, dict):
            parts.append(render_json(blk))
            continue
        if blk.get("type") == "tool_result":
            parts.append(render_tool_result(blk))
        else:
            parts.append(render_json(blk))
    return "\n".join(parts)


def render_event(event: dict) -> str:
    t = event.get("type", "?")
    if t == "system":
        sub = event.get("subtype", "")
        return block_html(
            "system",
            f"system: {sub}",
            render_json({k: v for k, v in event.items() if k != "type"}),
            open_=False,
        )
    if t == "assistant":
        return block_html(
            "assistant",
            "assistant",
            render_assistant(event.get("message", {})),
        )
    if t == "user":
        return block_html(
            "user",
            "user / tool results",
            render_user(event.get("message", {})),
        )
    if t == "result":
        cost = event.get("total_cost_usd")
        usage = event.get("usage") or {}
        title = f"result: {event.get('subtype', '')}"
        if cost is not None:
            title += f"  ${cost:.4f}"
        if usage:
            title += (
                f"  in={usage.get('input_tokens', 0)}"
                f" out={usage.get('output_tokens', 0)}"
                f" cache_r={usage.get('cache_read_input_tokens', 0)}"
                f" cache_w={usage.get('cache_creation_input_tokens', 0)}"
            )
        body = render_text(event.get("result", "")) + render_json(
            {k: v for k, v in event.items() if k not in ("type", "result")}
        )
        return block_html("result", title, body)
    if t == "hook":
        return block_html(
            "hook",
            f"hook: {event.get('hook_event_name', '')}",
            render_json(event),
            open_=False,
        )
    return block_html(t, t, render_json(event), open_=False)


def render_artifact_panel(run_dir: Path) -> str:
    panels: list[str] = []
    for name in ("alert.json", "investigation.md", "report.md", "lead_sequence.yaml"):
        path = run_dir / name
        if not path.is_file():
            panels.append(block_html("artifact missing", name, "<em>(missing)</em>", open_=False))
            continue
        text = path.read_text()
        if name.endswith(".json"):
            try:
                text = json.dumps(json.loads(text), indent=2)
            except json.JSONDecodeError:
                pass
        panels.append(block_html("artifact", name, render_text(text), open_=(name != "investigation.md")))

    gather_raw_dir = run_dir / "gather_raw"
    if gather_raw_dir.is_dir():
        for entry in sorted(gather_raw_dir.iterdir()):
            if not entry.is_file():
                continue
            try:
                text = entry.read_text()
                if entry.suffix == ".json":
                    text = json.dumps(json.loads(text), indent=2)
            except (OSError, json.JSONDecodeError):
                text = "<unreadable>"
            panels.append(
                block_html(
                    "artifact gather-raw",
                    f"gather_raw/{entry.name}",
                    render_text(text),
                    open_=False,
                )
            )
    return "\n".join(panels)


CSS = """
body { font: 13px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #0d1117; color: #c9d1d9; }
header { padding: 12px 20px; background: #161b22; border-bottom: 1px solid #30363d; position: sticky; top: 0; z-index: 10; }
header h1 { margin: 0 0 4px 0; font-size: 16px; color: #f0f6fc; }
header .meta { font-size: 11px; color: #8b949e; }
main { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 50px); }
.col { overflow-y: auto; padding: 12px 20px; border-right: 1px solid #30363d; }
.col h2 { font-size: 12px; text-transform: uppercase; color: #8b949e; margin: 0 0 8px 0; letter-spacing: 0.5px; }
.block { margin: 4px 0; border-radius: 4px; border-left: 3px solid #30363d; padding-left: 8px; }
.block summary { cursor: pointer; padding: 4px 0; font-weight: 500; user-select: none; }
.block summary:hover { color: #f0f6fc; }
.block .body { padding: 4px 0 8px 0; }
.block.assistant { border-left-color: #58a6ff; }
.block.user { border-left-color: #d29922; }
.block.tool-use { border-left-color: #a371f7; margin-left: 12px; }
.block.tool-result { border-left-color: #3fb950; margin-left: 12px; }
.block.tool-result.error { border-left-color: #f85149; }
.block.thinking { border-left-color: #6e7681; margin-left: 12px; opacity: 0.7; }
.block.system { border-left-color: #6e7681; opacity: 0.6; }
.block.result { border-left-color: #f0883e; }
.block.hook { border-left-color: #db61a2; opacity: 0.7; }
.block.artifact { border-left-color: #58a6ff; }
.block.artifact.gather-raw { border-left-color: #6e7681; opacity: 0.85; }
.block.artifact.missing { border-left-color: #f85149; opacity: 0.5; }
pre { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 8px 12px; margin: 4px 0; overflow-x: auto; white-space: pre-wrap; word-break: break-word; font: 12px/1.4 'SF Mono', Menlo, Consolas, monospace; }
pre.json { color: #79c0ff; }
pre.text { color: #c9d1d9; }
.text-block { padding: 4px 0; white-space: pre-wrap; }
"""


def render(run_dir: Path) -> str:
    events = load_jsonl(run_dir / "tool_trace.jsonl")
    case_id = run_dir.name

    # tally
    n_events = len(events)
    cost = sum(e.get("total_cost_usd") or 0 for e in events if e.get("type") == "result")
    n_tool_calls = sum(
        1
        for e in events
        if e.get("type") == "assistant"
        for blk in (e.get("message") or {}).get("content", [])
        if isinstance(blk, dict) and blk.get("type") == "tool_use"
    )

    transcript_html = "\n".join(render_event(e) for e in events) or "<em>(no events)</em>"
    artifact_html = render_artifact_panel(run_dir)

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>defender run: {esc(case_id)}</title>
<style>{CSS}</style></head><body>
<header>
  <h1>defender run: {esc(case_id)}</h1>
  <div class="meta">events={n_events} · tool_calls={n_tool_calls} · cost=${cost:.4f} · run_dir={esc(str(run_dir))}</div>
</header>
<main>
  <div class="col">
    <h2>transcript</h2>
    {transcript_html}
  </div>
  <div class="col">
    <h2>artifacts</h2>
    {artifact_html}
  </div>
</main>
</body></html>
"""


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: visualize_run.py <run_dir>", file=sys.stderr)
        return 64
    run_dir = Path(argv[1]).resolve()
    if not run_dir.is_dir():
        print(f"not a directory: {run_dir}", file=sys.stderr)
        return 1
    out = run_dir / "transcript.html"
    out.write_text(render(run_dir))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
