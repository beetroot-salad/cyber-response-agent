#!/usr/bin/env python3
"""Render a defender run as a single self-contained HTML transcript.

Reads `tool_trace.jsonl` (the stream-json output captured by run.py),
the artifact files in the run dir, and — when present — the matching
learning-loop artifacts under `defender/learning/runs/<run_id>/`. Writes
`transcript.html` in the run dir.

The page has three regions:
    1. Headline — disposition + report paragraph + lesson changes since
       the run started.
    2. Subagents — every Task/Agent call in the main run plus the
       learning-loop subagents (actor / oracle / judge), each with a
       drill-down showing input prompt and full output.
    3. Transcript + artifacts (the original two-column body).

Usage:
    python3 defender/scripts/visualize_run.py <run_dir>
"""
from __future__ import annotations

import datetime as _dt
import html
import json
import subprocess
import sys
from pathlib import Path

try:
    import yaml  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover — yaml is in defender deps
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[2]


def esc(s) -> str:
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


# ---------------------------------------------------------------------------
# Transcript rendering (left column)
# ---------------------------------------------------------------------------


def render_tool_use(block: dict) -> str:
    name = block.get("name", "?")
    tid = block.get("id", "")
    inp = block.get("input", {})
    return block_html(
        "tool-use",
        f"→ {name}  ({tid})",
        render_json(inp),
    )


def _flatten_tool_result_content(content) -> str:
    if isinstance(content, list):
        parts: list[str] = []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                parts.append(c.get("text", ""))
            else:
                parts.append(json.dumps(c))
        return "\n".join(parts)
    return str(content)


def render_tool_result(block: dict) -> str:
    tid = block.get("tool_use_id", "")
    is_error = block.get("is_error", False)
    body = _flatten_tool_result_content(block.get("content", ""))
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


# ---------------------------------------------------------------------------
# Headline
# ---------------------------------------------------------------------------


def parse_report(run_dir: Path) -> dict:
    """Return {disposition, confidence, body} from report.md, or {}."""
    p = run_dir / "report.md"
    if not p.is_file():
        return {}
    text = p.read_text()
    if not text.startswith("---\n"):
        return {"body": text}
    end = text.find("\n---", 4)
    if end == -1:
        return {"body": text}
    fm_text = text[4:end]
    body = text[end + 4 :].lstrip("\n")
    fm: dict = {}
    if yaml is not None:
        try:
            loaded = yaml.safe_load(fm_text)
            if isinstance(loaded, dict):
                fm = loaded
        except yaml.YAMLError:
            fm = {}
    return {**fm, "body": body}


def lesson_changes(run_dir: Path, run_id: str) -> dict:
    """Detect lesson-corpus commits triggered by this run.

    Heuristic: list commits touching ``defender/lessons/`` newer than the
    run's tool_trace.jsonl (a stable proxy for run-start). Author runs
    only when the pending threshold is hit, so most runs return [].
    """
    trace = run_dir / "tool_trace.jsonl"
    if not trace.is_file():
        return {"available": False, "reason": "no tool_trace.jsonl"}
    since_epoch = trace.stat().st_mtime
    since_iso = (
        _dt.datetime.fromtimestamp(since_epoch, tz=_dt.timezone.utc)
        .isoformat()
    )
    try:
        log = subprocess.run(
            [
                "git", "-C", str(REPO_ROOT), "log",
                f"--since={since_iso}",
                "--pretty=format:%H%x09%cI%x09%s",
                "--name-status",
                "--", "defender/lessons/",
            ],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"available": False, "reason": f"git unavailable: {e}"}
    if log.returncode != 0:
        return {"available": False, "reason": log.stderr.strip() or "git log failed"}

    commits: list[dict] = []
    cur: dict | None = None
    for line in log.stdout.splitlines():
        if not line.strip():
            if cur:
                commits.append(cur); cur = None
            continue
        if "\t" in line and len(line.split("\t")) >= 3 and len(line.split("\t")[0]) == 40:
            sha, when, subject = line.split("\t", 2)
            if cur:
                commits.append(cur)
            cur = {"sha": sha, "when": when, "subject": subject, "files": []}
        elif cur is not None:
            cur["files"].append(line)
    if cur:
        commits.append(cur)

    for c in commits:
        diff = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "show", c["sha"],
             "--pretty=format:", "--", "defender/lessons/"],
            capture_output=True, text=True,
        )
        c["diff"] = diff.stdout if diff.returncode == 0 else ""

    return {"available": True, "since": since_iso, "commits": commits, "run_id": run_id}


def render_headline(run_dir: Path, run_id: str) -> str:
    report = parse_report(run_dir)
    disposition = report.get("disposition", "?")
    confidence = report.get("confidence", "?")
    body = report.get("body", "").strip() or "<em>(no report body)</em>"
    disp_class = f"disp-{esc(str(disposition))}"

    lc = lesson_changes(run_dir, run_id)
    if not lc.get("available"):
        lessons_html = (
            f'<div class="lessons-empty">lesson change tracking unavailable '
            f'({esc(lc.get("reason", "?"))})</div>'
        )
    elif not lc.get("commits"):
        lessons_html = (
            '<div class="lessons-empty">no lesson commits since this run started '
            f'({esc(lc["since"])})</div>'
        )
    else:
        rows: list[str] = []
        for c in lc["commits"]:
            files = "\n".join(c.get("files", []))
            diff = c.get("diff", "")
            inner = (
                f'<div class="commit-meta">{esc(c["when"])} · {esc(c["sha"][:10])}</div>'
                f'<pre class="text files">{esc(files)}</pre>'
            )
            if diff.strip():
                inner += f'<pre class="json diff">{esc(diff)}</pre>'
            rows.append(block_html("lesson-commit", c["subject"], inner, open_=False))
        lessons_html = "\n".join(rows)

    return f"""
<section class="headline">
  <div class="hero">
    <div class="hero-disposition {disp_class}">
      <div class="label">disposition</div>
      <div class="value">{esc(str(disposition))}</div>
      <div class="confidence">confidence: {esc(str(confidence))}</div>
    </div>
    <div class="hero-report">
      <div class="label">report.md</div>
      <div class="report-body">{esc(body)}</div>
    </div>
  </div>
  <div class="lessons">
    <h2>lesson changes</h2>
    {lessons_html}
  </div>
</section>
"""


# ---------------------------------------------------------------------------
# Subagent panel (middle / right)
# ---------------------------------------------------------------------------


def extract_main_subagents(events: list[dict]) -> list[dict]:
    """Pair every Task/Agent tool_use with its matching tool_result."""
    calls: dict[str, dict] = {}
    order: list[str] = []
    for ev in events:
        if ev.get("type") == "assistant":
            for blk in (ev.get("message") or {}).get("content", []):
                if (
                    isinstance(blk, dict)
                    and blk.get("type") == "tool_use"
                    and blk.get("name") in ("Task", "Agent")
                ):
                    calls[blk["id"]] = {
                        "id": blk["id"],
                        "name": blk["name"],
                        "input": blk.get("input", {}),
                        "result": None,
                        "is_error": False,
                    }
                    order.append(blk["id"])
        elif ev.get("type") == "user":
            c = (ev.get("message") or {}).get("content", [])
            if not isinstance(c, list):
                continue
            for blk in c:
                if not isinstance(blk, dict) or blk.get("type") != "tool_result":
                    continue
                tid = blk.get("tool_use_id")
                if tid in calls:
                    calls[tid]["result"] = _flatten_tool_result_content(
                        blk.get("content", "")
                    )
                    calls[tid]["is_error"] = blk.get("is_error", False)
    return [calls[i] for i in order]


def render_main_subagent(idx: int, call: dict) -> str:
    inp = call.get("input", {}) or {}
    description = inp.get("description") or "(no description)"
    subagent_type = inp.get("subagent_type") or "(default)"
    prompt = inp.get("prompt", "")
    result = call.get("result")
    err = " [error]" if call.get("is_error") else ""

    title = f"#{idx} [{call['name']}/{subagent_type}] {description}{err}"

    inner = (
        block_html("subagent-input", "input prompt", render_text(prompt), open_=False)
        + (
            block_html(
                "subagent-output",
                "output",
                render_text(result if isinstance(result, str) else json.dumps(result, indent=2)),
                open_=True,
            )
            if result is not None
            else '<div class="lessons-empty">(no result captured)</div>'
        )
    )
    return block_html(
        "subagent gather" + (" error" if call.get("is_error") else ""),
        title,
        inner,
        open_=False,
    )


def render_learning_subagents(run_id: str) -> str:
    learn_dir = REPO_ROOT / "defender" / "learning" / "runs" / run_id
    if not learn_dir.is_dir():
        return (
            '<div class="lessons-empty">no learning-loop artifacts at '
            f'{esc(str(learn_dir))}</div>'
        )

    panels: list[str] = []

    actor_input = learn_dir / "actor_input.yaml"
    actor_story = learn_dir / "actor_story.md"
    if actor_story.is_file():
        body = (
            block_html(
                "subagent-input",
                "input: actor_input.yaml",
                render_text(actor_input.read_text() if actor_input.is_file() else "(missing)"),
                open_=False,
            )
            + block_html(
                "subagent-output",
                "output: actor_story.md",
                render_text(actor_story.read_text()),
                open_=True,
            )
        )
        panels.append(block_html("subagent actor", "[learning] actor", body, open_=False))

    proj = learn_dir / "projected_telemetry.yaml"
    if proj.is_file():
        panels.append(
            block_html(
                "subagent oracle",
                "[learning] oracle (projected_telemetry.yaml)",
                render_text(proj.read_text()),
                open_=False,
            )
        )

    judge = learn_dir / "judge_findings.yaml"
    if judge.is_file():
        panels.append(
            block_html(
                "subagent judge",
                "[learning] judge (judge_findings.yaml)",
                render_text(judge.read_text()),
                open_=False,
            )
        )

    # Surface any *.raw.txt fallbacks the loop wrote when YAML failed validation.
    for raw in sorted(learn_dir.glob("*.raw.txt")):
        panels.append(
            block_html(
                "subagent raw error",
                f"[learning] raw fallback: {raw.name}",
                render_text(raw.read_text()),
                open_=False,
            )
        )

    if not panels:
        return f'<div class="lessons-empty">{esc(str(learn_dir))}: no recognised artifacts</div>'
    return "\n".join(panels)


def render_subagent_panel(events: list[dict], run_id: str) -> str:
    main_calls = extract_main_subagents(events)
    if main_calls:
        main_html = "\n".join(
            render_main_subagent(i, c) for i, c in enumerate(main_calls)
        )
    else:
        main_html = '<div class="lessons-empty">(no Task/Agent calls in trace)</div>'

    learning_html = render_learning_subagents(run_id)

    return (
        f'<h3>main run · {len(main_calls)} subagent call(s)</h3>\n{main_html}\n'
        f'<h3>learning loop</h3>\n{learning_html}'
    )


# ---------------------------------------------------------------------------
# Artifact panel (right column)
# ---------------------------------------------------------------------------


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
header.top { padding: 12px 20px; background: #161b22; border-bottom: 1px solid #30363d; position: sticky; top: 0; z-index: 10; }
header.top h1 { margin: 0 0 4px 0; font-size: 16px; color: #f0f6fc; }
header.top .meta { font-size: 11px; color: #8b949e; }

section.headline { padding: 16px 20px; background: #0f1620; border-bottom: 1px solid #30363d; }
.hero { display: grid; grid-template-columns: 240px 1fr; gap: 16px; align-items: stretch; margin-bottom: 12px; }
.hero-disposition { padding: 12px 16px; border-radius: 6px; border: 1px solid #30363d; background: #161b22; }
.hero-disposition .label { text-transform: uppercase; font-size: 10px; color: #8b949e; letter-spacing: 0.5px; }
.hero-disposition .value { font-size: 22px; font-weight: 600; margin: 4px 0; color: #f0f6fc; text-transform: uppercase; }
.hero-disposition .confidence { font-size: 11px; color: #8b949e; }
.hero-disposition.disp-benign { border-left: 4px solid #3fb950; }
.hero-disposition.disp-inconclusive { border-left: 4px solid #d29922; }
.hero-disposition.disp-malicious { border-left: 4px solid #f85149; }
.hero-report { padding: 12px 16px; border-radius: 6px; border: 1px solid #30363d; background: #161b22; }
.hero-report .label { text-transform: uppercase; font-size: 10px; color: #8b949e; letter-spacing: 0.5px; margin-bottom: 6px; }
.hero-report .report-body { white-space: pre-wrap; color: #c9d1d9; font-size: 13px; line-height: 1.55; }
.lessons h2 { font-size: 12px; text-transform: uppercase; color: #8b949e; margin: 8px 0; letter-spacing: 0.5px; }
.lessons-empty { font-size: 11px; color: #8b949e; padding: 6px 0; font-style: italic; }
.commit-meta { font-size: 11px; color: #8b949e; margin-bottom: 4px; }

main { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0; height: calc(100vh - 50px); min-height: 600px; }
.col { overflow-y: auto; padding: 12px 20px; border-right: 1px solid #30363d; }
.col:last-child { border-right: none; }
.col h2 { font-size: 12px; text-transform: uppercase; color: #8b949e; margin: 0 0 8px 0; letter-spacing: 0.5px; }
.col h3 { font-size: 11px; text-transform: uppercase; color: #8b949e; margin: 12px 0 6px 0; letter-spacing: 0.5px; }

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
.block.subagent { border-left-color: #a371f7; }
.block.subagent.gather { border-left-color: #a371f7; }
.block.subagent.actor { border-left-color: #f85149; }
.block.subagent.oracle { border-left-color: #d29922; }
.block.subagent.judge { border-left-color: #3fb950; }
.block.subagent.error { border-left-color: #f85149; }
.block.subagent-input { border-left-color: #6e7681; margin-left: 12px; opacity: 0.85; }
.block.subagent-output { border-left-color: #58a6ff; margin-left: 12px; }
.block.lesson-commit { border-left-color: #db61a2; }

pre { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 8px 12px; margin: 4px 0; overflow-x: auto; white-space: pre-wrap; word-break: break-word; font: 12px/1.4 'SF Mono', Menlo, Consolas, monospace; }
pre.json { color: #79c0ff; }
pre.text { color: #c9d1d9; }
pre.diff { color: #c9d1d9; }
.text-block { padding: 4px 0; white-space: pre-wrap; }
"""


def render(run_dir: Path) -> str:
    events = load_jsonl(run_dir / "tool_trace.jsonl")
    case_id = run_dir.name

    n_events = len(events)
    cost = sum(e.get("total_cost_usd") or 0 for e in events if e.get("type") == "result")
    n_tool_calls = sum(
        1
        for e in events
        if e.get("type") == "assistant"
        for blk in (e.get("message") or {}).get("content", [])
        if isinstance(blk, dict) and blk.get("type") == "tool_use"
    )

    headline_html = render_headline(run_dir, case_id)
    subagent_html = render_subagent_panel(events, case_id)
    transcript_html = "\n".join(render_event(e) for e in events) or "<em>(no events)</em>"
    artifact_html = render_artifact_panel(run_dir)

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>defender run: {esc(case_id)}</title>
<style>{CSS}</style></head><body>
<header class="top">
  <h1>defender run: {esc(case_id)}</h1>
  <div class="meta">events={n_events} · tool_calls={n_tool_calls} · cost=${cost:.4f} · run_dir={esc(str(run_dir))}</div>
</header>
{headline_html}
<main>
  <div class="col">
    <h2>subagents</h2>
    {subagent_html}
  </div>
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
