#!/usr/bin/env python3
"""Render a Claude Code subagent transcript JSONL to a single HTML page.

Walks the JSONL transcript at /root/.claude/projects/<project>/<session>.jsonl
and emits a sequential view of: the input prompt (queue-operation enqueue),
each assistant block (thinking, tool_use, text) and each user tool_result,
in the order they happened. Useful for inspecting what a subagent saw,
thought, read, and produced in one self-contained file.

Usage:
  render_subagent_transcript.py <session_id_or_jsonl_path> [-o out.html]
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

PROJECTS_ROOT = Path("/root/.claude/projects")


def find_transcript(arg: str) -> Path:
    p = Path(arg)
    if p.exists():
        return p
    # treat as session id; search across project dirs
    matches = list(PROJECTS_ROOT.rglob(f"{arg}.jsonl"))
    if not matches:
        sys.exit(f"transcript for session {arg!r} not found under {PROJECTS_ROOT}")
    if len(matches) > 1:
        sys.exit(f"ambiguous session id {arg!r}: {matches}")
    return matches[0]


def load_lines(path: Path) -> list[dict]:
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def esc(s: str) -> str:
    return html.escape(s, quote=False)


def block_html(kind: str, header: str, body: str, *, pre: bool = True) -> str:
    body_html = f"<pre>{esc(body)}</pre>" if pre else body
    return (
        f'<details class="blk {kind}" open>'
        f'<summary><span class="kind">{esc(kind)}</span> '
        f'<span class="hdr">{esc(header)}</span></summary>'
        f'{body_html}</details>'
    )


def render_tool_use(tu: dict) -> str:
    name = tu.get("name", "?")
    inp = tu.get("input", {}) or {}
    if name == "Read":
        body = inp.get("file_path", "")
        return block_html("tool_use", f"Read {body}", body)
    if name == "Bash":
        cmd = inp.get("command", "")
        desc = inp.get("description", "")
        return block_html("tool_use", f"Bash — {desc}", cmd)
    if name == "Write":
        body = (
            f"file_path: {inp.get('file_path','')}\n"
            f"---\n{inp.get('content','')}"
        )
        return block_html("tool_use", f"Write {inp.get('file_path','')}", body)
    # generic
    return block_html("tool_use", name, json.dumps(inp, indent=2))


def render_tool_result(tr: dict) -> str:
    content = tr.get("content", "")
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
    is_err = tr.get("is_error", False)
    kind = "tool_result_error" if is_err else "tool_result"
    truncated = body if len(body) <= 8000 else body[:8000] + f"\n… [truncated, {len(body)-8000} more chars]"
    return block_html(kind, f"({len(body)} chars){' ERROR' if is_err else ''}", truncated)


def render(events: list[dict]) -> str:
    rows: list[str] = []
    for ev in events:
        t = ev.get("type")
        ts = ev.get("timestamp", "")
        if t == "queue-operation" and ev.get("operation") == "enqueue":
            rows.append(
                f'<div class="ts">{esc(ts)} — input prompt (enqueue)</div>'
            )
            rows.append(block_html("input", "subagent prompt", ev.get("content", "")))
        elif t == "assistant":
            msg = ev.get("message", {})
            for c in msg.get("content", []) or []:
                ctype = c.get("type")
                if ctype == "thinking":
                    rows.append(
                        f'<div class="ts">{esc(ts)} — thinking</div>'
                    )
                    rows.append(block_html("thinking", "thinking", c.get("thinking", "")))
                elif ctype == "tool_use":
                    rows.append(
                        f'<div class="ts">{esc(ts)} — tool_use {esc(c.get("name",""))}</div>'
                    )
                    rows.append(render_tool_use(c))
                elif ctype == "text":
                    rows.append(f'<div class="ts">{esc(ts)} — assistant text</div>')
                    rows.append(block_html("text", "assistant text", c.get("text", "")))
        elif t == "user":
            msg = ev.get("message", {})
            for c in msg.get("content", []) or []:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    rows.append(f'<div class="ts">{esc(ts)} — tool_result</div>')
                    rows.append(render_tool_result(c))
    return "\n".join(rows)


CSS = """
body { font-family: ui-monospace, Menlo, Consolas, monospace; max-width: 1100px; margin: 1rem auto; padding: 0 1rem; background: #fafafa; color: #222; }
h1 { font-size: 1.1rem; }
.ts { color: #888; font-size: 0.75rem; margin-top: 0.6rem; }
.blk { border-left: 3px solid #ccc; padding: 0.4rem 0.6rem; margin: 0.2rem 0; background: #fff; border-radius: 4px; }
.blk pre { white-space: pre-wrap; word-break: break-word; margin: 0.4rem 0 0 0; font-size: 0.78rem; line-height: 1.35; max-height: 600px; overflow: auto; background: #f4f4f4; padding: 0.5rem; border-radius: 3px; }
.blk summary { cursor: pointer; font-size: 0.82rem; }
.blk .kind { display: inline-block; min-width: 8em; padding: 0 0.3em; border-radius: 3px; font-weight: 600; font-size: 0.72rem; margin-right: 0.4em; }
.input .kind { background: #e3f2fd; color: #0d47a1; }
.thinking { border-left-color: #9c27b0; } .thinking .kind { background: #f3e5f5; color: #4a148c; }
.tool_use { border-left-color: #1976d2; } .tool_use .kind { background: #e3f2fd; color: #0d47a1; }
.tool_result { border-left-color: #2e7d32; } .tool_result .kind { background: #e8f5e9; color: #1b5e20; }
.tool_result_error { border-left-color: #c62828; } .tool_result_error .kind { background: #ffebee; color: #b71c1c; }
.text { border-left-color: #ef6c00; } .text .kind { background: #fff3e0; color: #e65100; }
.hdr { color: #555; }
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("session", help="session id or path to JSONL transcript")
    ap.add_argument("-o", "--out", default=None, help="output HTML path")
    args = ap.parse_args()

    path = find_transcript(args.session)
    events = load_lines(path)
    body = render(events)

    out = Path(args.out) if args.out else path.with_suffix(".html")
    out.write_text(
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{esc(path.name)}</title><style>{CSS}</style></head><body>"
        f"<h1>{esc(path.name)} — {len(events)} events</h1>"
        f"{body}</body></html>"
    )
    print(out)


if __name__ == "__main__":
    main()
