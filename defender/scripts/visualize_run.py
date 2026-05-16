#!/usr/bin/env python3
"""Render a defender run as a single self-contained HTML transcript.

Reads `tool_trace.jsonl` (the stream-json output captured by run.py),
the artifact files in the run dir, and — when present — the matching
learning-loop artifacts under `defender/learning/runs/<run_id>/`. Writes
`transcript.html` in the run dir.

Layout: sticky TOC sidebar + temporally-ordered content stream.

    Headline           disposition + report body + judge findings
    § Alert            alert.json
    § Defender         investigation.md / report.md / lead_sequence.yaml
                       + gather subagent calls + gather_raw/*
    § Learning         actor / oracle / judge artifacts
    § Raw transcript   (collapsed) full stream-json
    Footer             concurrent lesson commits (queue-decoupled,
                       not necessarily caused by this run)

Defender (runtime) and Learning (offline) are first-class siblings.
Lesson commits are demoted to a footer because the author queue can
flush findings from prior runs.

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


def load_yaml(path: Path) -> dict | list | None:
    if not path.is_file() or yaml is None:
        return None
    try:
        return yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        return None


def block(kind: str, title: str, body: str, *, open_: bool = False, anchor: str | None = None) -> str:
    """Collapsible disclosure. Inner blocks deliberately have no left-border
    accent — accents are reserved for top-level stages to reduce nesting noise.
    """
    open_attr = " open" if open_ else ""
    id_attr = f' id="{esc(anchor)}"' if anchor else ""
    return (
        f'<details class="block {kind}"{open_attr}{id_attr}>'
        f'<summary>{esc(title)}</summary>'
        f'<div class="body">{body}</div>'
        f'</details>'
    )


def pre_text(text: str) -> str:
    return f'<pre class="text">{esc(text)}</pre>'


def pre_json(obj) -> str:
    try:
        rendered = json.dumps(obj, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        rendered = str(obj)
    return f'<pre class="json">{esc(rendered)}</pre>'


# ---------------------------------------------------------------------------
# Raw transcript helpers (used by § Raw transcript section)
# ---------------------------------------------------------------------------


def render_tool_use(blk: dict) -> str:
    return block(
        "tool-use",
        f"→ {blk.get('name', '?')}  ({blk.get('id', '')})",
        pre_json(blk.get("input", {})),
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


def render_tool_result(blk: dict) -> str:
    is_error = blk.get("is_error", False)
    body = _flatten_tool_result_content(blk.get("content", ""))
    label = "← tool_result" + (" [error]" if is_error else "")
    return block(
        "tool-result" + (" error" if is_error else ""),
        f"{label}  ({blk.get('tool_use_id', '')})",
        pre_text(body),
    )


def render_thinking(blk: dict) -> str:
    return block("thinking", "thinking", pre_text(blk.get("thinking", "")))


def render_text_block(blk: dict) -> str:
    return f'<div class="text-block">{esc(blk.get("text", ""))}</div>'


def render_assistant(message: dict) -> str:
    parts: list[str] = []
    for blk in message.get("content", []):
        t = blk.get("type")
        if t == "text":
            parts.append(render_text_block(blk))
        elif t == "thinking":
            parts.append(render_thinking(blk))
        elif t == "tool_use":
            parts.append(render_tool_use(blk))
        else:
            parts.append(pre_json(blk))
    return "\n".join(parts)


def render_user(message: dict) -> str:
    content = message.get("content", [])
    if isinstance(content, str):
        return pre_text(content)
    parts: list[str] = []
    for blk in content:
        if not isinstance(blk, dict):
            parts.append(pre_json(blk))
            continue
        if blk.get("type") == "tool_result":
            parts.append(render_tool_result(blk))
        else:
            parts.append(pre_json(blk))
    return "\n".join(parts)


def render_event(event: dict) -> str:
    t = event.get("type", "?")
    if t == "system":
        return block(
            "system",
            f"system: {event.get('subtype', '')}",
            pre_json({k: v for k, v in event.items() if k != "type"}),
        )
    if t == "assistant":
        return block("assistant", "assistant", render_assistant(event.get("message", {})), open_=True)
    if t == "user":
        return block("user", "user / tool results", render_user(event.get("message", {})), open_=True)
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
        body = pre_text(event.get("result", "")) + pre_json(
            {k: v for k, v in event.items() if k not in ("type", "result")}
        )
        return block("result", title, body, open_=True)
    if t == "hook":
        return block("hook", f"hook: {event.get('hook_event_name', '')}", pre_json(event))
    return block(t, t, pre_json(event))


# ---------------------------------------------------------------------------
# Headline: disposition + report body + judge findings
# ---------------------------------------------------------------------------


def parse_report(run_dir: Path) -> dict:
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


def load_judge_findings(run_id: str) -> dict | None:
    learn_dir = REPO_ROOT / "defender" / "learning" / "runs" / run_id
    data = load_yaml(learn_dir / "judge_findings.yaml")
    return data if isinstance(data, dict) else None


def render_findings_summary(judge: dict | None) -> str:
    """Headline list of judge findings: type + subject_topic only.

    Full detail lives in § Learning. Findings *are* the headline result
    of the run, not a side panel.
    """
    if not judge:
        return '<div class="empty">no judge findings (no learning-loop output)</div>'
    findings = judge.get("defender_findings") or []
    if not isinstance(findings, list) or not findings:
        return '<div class="empty">judge ran but emitted no findings</div>'
    rows: list[str] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        ftype = esc(str(f.get("type", "?")))
        topic = esc(str(f.get("subject_topic", "")))
        anchor = esc(str(f.get("subject_anchor", "")))
        rows.append(
            f'<li class="finding finding-{ftype}">'
            f'<span class="ftype">{ftype}</span>'
            f'<span class="ftopic">{topic}</span>'
            f'<span class="fanchor">{anchor}</span>'
            f'</li>'
        )
    return f'<ul class="findings-list">{"".join(rows)}</ul>'


def render_headline(run_dir: Path, run_id: str, judge: dict | None) -> str:
    report = parse_report(run_dir)
    disposition = str(report.get("disposition", "?"))
    confidence = str(report.get("confidence", "?"))
    body = report.get("body", "").strip() or "(no report body)"
    disp_class = f"disp-{esc(disposition)}"

    outcome = str((judge or {}).get("outcome", "—"))
    out_class = f"out-{esc(outcome)}"

    return f"""
<section class="headline">
  <div class="tiles">
    <div class="tile tile-disp {disp_class}">
      <div class="tile-label">defender disposition</div>
      <div class="tile-value">{esc(disposition)}</div>
      <div class="tile-sub">confidence: {esc(confidence)}</div>
    </div>
    <div class="tile tile-out {out_class}">
      <div class="tile-label">judge outcome</div>
      <div class="tile-value">{esc(outcome)}</div>
      <div class="tile-sub">{("findings: " + str(len((judge or {}).get("defender_findings") or []))) if judge else "no learning loop"}</div>
    </div>
  </div>
  <div class="headline-body">
    <div class="hb-label">report.md</div>
    <div class="hb-text">{esc(body)}</div>
  </div>
  <div class="headline-findings">
    <div class="hb-label">judge findings (this run)</div>
    {render_findings_summary(judge)}
  </div>
</section>
"""


# ---------------------------------------------------------------------------
# § Alert
# ---------------------------------------------------------------------------


def render_alert_section(run_dir: Path) -> str:
    p = run_dir / "alert.json"
    if not p.is_file():
        body = '<div class="empty">no alert.json</div>'
    else:
        try:
            text = json.dumps(json.loads(p.read_text()), indent=2)
        except json.JSONDecodeError:
            text = p.read_text()
        body = pre_text(text)
    return f"""
<section id="sec-alert" class="stage stage-alert">
  <h2>§ Alert</h2>
  <div class="stage-meta">input to the defender runtime</div>
  {body}
</section>
"""


# ---------------------------------------------------------------------------
# § Defender (runtime)
# ---------------------------------------------------------------------------


def extract_main_subagents(events: list[dict]) -> list[dict]:
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
                    calls[tid]["result"] = _flatten_tool_result_content(blk.get("content", ""))
                    calls[tid]["is_error"] = blk.get("is_error", False)
    return [calls[i] for i in order]


def render_artifact_file(run_dir: Path, name: str, *, open_: bool = False) -> str:
    p = run_dir / name
    if not p.is_file():
        return block("artifact missing", name, '<div class="empty">(missing)</div>')
    text = p.read_text()
    if name.endswith(".json"):
        try:
            text = json.dumps(json.loads(text), indent=2)
        except json.JSONDecodeError:
            pass
    return block("artifact", name, pre_text(text), open_=open_)


def render_gather_subagent(idx: int, call: dict) -> str:
    inp = call.get("input", {}) or {}
    description = inp.get("description") or "(no description)"
    subagent_type = inp.get("subagent_type") or "(default)"
    prompt = inp.get("prompt", "")
    result = call.get("result")
    err = " [error]" if call.get("is_error") else ""
    title = f"#{idx} [{subagent_type}] {description}{err}"
    inner = block("subagent-input", "input prompt", pre_text(prompt))
    if result is not None:
        inner += block(
            "subagent-output",
            "output",
            pre_text(result if isinstance(result, str) else json.dumps(result, indent=2)),
            open_=True,
        )
    else:
        inner += '<div class="empty">(no result captured)</div>'
    return block(
        "subcall" + (" error" if call.get("is_error") else ""),
        title,
        inner,
        anchor=f"sec-defender-gather-{idx}",
    )


def render_gather_raw(run_dir: Path) -> str:
    gather_dir = run_dir / "gather_raw"
    if not gather_dir.is_dir():
        return '<div class="empty">no gather_raw/</div>'
    panels: list[str] = []
    for entry in sorted(gather_dir.iterdir()):
        if not entry.is_file():
            continue
        try:
            text = entry.read_text()
            if entry.suffix == ".json":
                text = json.dumps(json.loads(text), indent=2)
        except (OSError, json.JSONDecodeError):
            text = "<unreadable>"
        panels.append(block("artifact gather-raw", entry.name, pre_text(text)))
    return "\n".join(panels) if panels else '<div class="empty">gather_raw/ is empty</div>'


def render_defender_section(run_dir: Path, events: list[dict]) -> tuple[str, list[dict]]:
    """Returns (html, subagent_calls). Caller needs the calls list for TOC."""
    calls = extract_main_subagents(events)
    gather_html = (
        "\n".join(render_gather_subagent(i, c) for i, c in enumerate(calls))
        if calls
        else '<div class="empty">(no Task/Agent calls)</div>'
    )
    html_ = f"""
<section id="sec-defender" class="stage stage-defender">
  <h2>§ Defender <span class="stage-sub">— runtime: ORIENT → PLAN → GATHER → ANALYZE → REPORT</span></h2>

  <h3 id="sec-defender-artifacts">Run artifacts</h3>
  {render_artifact_file(run_dir, "investigation.md")}
  {render_artifact_file(run_dir, "report.md", open_=False)}
  {render_artifact_file(run_dir, "lead_sequence.yaml")}

  <h3 id="sec-defender-gather">Gather subagents · {len(calls)} call(s)</h3>
  {gather_html}

  <h3 id="sec-defender-rawpayloads">gather_raw/ payloads</h3>
  {render_gather_raw(run_dir)}
</section>
"""
    return html_, calls


# ---------------------------------------------------------------------------
# § Learning pipeline
# ---------------------------------------------------------------------------


def render_learning_artifact(learn_dir: Path, name: str, *, label: str | None = None, open_: bool = False) -> str:
    p = learn_dir / name
    title = label or name
    if not p.is_file():
        return block("artifact missing", f"{title} (missing)", '<div class="empty">(file absent)</div>')
    return block("artifact", title, pre_text(p.read_text()), open_=open_)


def render_learning_section(run_id: str) -> tuple[str, list[str]]:
    """Returns (html, stage_anchors_present) for TOC composition."""
    learn_dir = REPO_ROOT / "defender" / "learning" / "runs" / run_id
    if not learn_dir.is_dir():
        body = f'<div class="empty">no learning-loop artifacts at {esc(str(learn_dir))}</div>'
        html_ = f"""
<section id="sec-learning" class="stage stage-learning">
  <h2>§ Learning pipeline <span class="stage-sub">— offline: actor → oracle → judge</span></h2>
  {body}
</section>
"""
        return html_, []

    anchors: list[str] = []
    blocks: list[str] = []

    actor_input = learn_dir / "actor_input.yaml"
    actor_story = learn_dir / "actor_story.md"
    actor_archetype = learn_dir / "actor_archetype.txt"
    actor_menu = learn_dir / "actor_menu.txt"
    if actor_story.is_file() or actor_input.is_file():
        inner = ""
        if actor_archetype.is_file() or actor_menu.is_file():
            arch = actor_archetype.read_text().strip() if actor_archetype.is_file() else "?"
            menu = actor_menu.read_text() if actor_menu.is_file() else "(missing)"
            inner += block(
                "subagent-input",
                f"actor inputs (archetype={arch})",
                pre_text(menu),
            )
        if actor_input.is_file():
            inner += block("subagent-input", "actor_input.yaml", pre_text(actor_input.read_text()))
        if actor_story.is_file():
            inner += block("subagent-output", "actor_story.md", pre_text(actor_story.read_text()), open_=True)
        blocks.append(block("subcall actor", "actor — adversarial counterfactual", inner, anchor="sec-learning-actor"))
        anchors.append("sec-learning-actor")

    proj = learn_dir / "projected_telemetry.yaml"
    proj_raw = learn_dir / "projected_telemetry.raw.txt"
    if proj.is_file() or proj_raw.is_file():
        inner = ""
        if proj.is_file():
            inner += block("subagent-output", "projected_telemetry.yaml", pre_text(proj.read_text()), open_=True)
        if proj_raw.is_file():
            inner += block("subagent-output raw", "projected_telemetry.raw.txt (raw)", pre_text(proj_raw.read_text()))
        blocks.append(block("subcall oracle", "oracle — telemetry projection", inner, anchor="sec-learning-oracle"))
        anchors.append("sec-learning-oracle")

    judge = learn_dir / "judge_findings.yaml"
    judge_raw = learn_dir / "judge_findings.raw.txt"
    if judge.is_file() or judge_raw.is_file():
        inner = ""
        if judge.is_file():
            inner += block("subagent-output", "judge_findings.yaml", pre_text(judge.read_text()), open_=True)
        if judge_raw.is_file():
            inner += block("subagent-output raw", "judge_findings.raw.txt (raw)", pre_text(judge_raw.read_text()))
        blocks.append(block("subcall judge", "judge — outcome + defender findings", inner, anchor="sec-learning-judge"))
        anchors.append("sec-learning-judge")

    body = "\n".join(blocks) if blocks else f'<div class="empty">{esc(str(learn_dir))}: no recognised artifacts</div>'
    html_ = f"""
<section id="sec-learning" class="stage stage-learning">
  <h2>§ Learning pipeline <span class="stage-sub">— offline: actor → oracle → judge</span></h2>
  {body}
</section>
"""
    return html_, anchors


# ---------------------------------------------------------------------------
# § Raw transcript (collapsed)
# ---------------------------------------------------------------------------


def render_raw_transcript(events: list[dict]) -> str:
    inner = "\n".join(render_event(e) for e in events) or '<div class="empty">(no events)</div>'
    body = block("raw-stream", f"stream-json events ({len(events)})", inner, open_=False)
    return f"""
<section id="sec-raw" class="stage stage-raw">
  <h2>§ Raw transcript <span class="stage-sub">— full stream-json, for debugging</span></h2>
  {body}
</section>
"""


# ---------------------------------------------------------------------------
# Footer: concurrent lesson commits
# ---------------------------------------------------------------------------


def lesson_changes(run_dir: Path, run_id: str) -> dict:
    """Commits to defender/lessons/ wall-clock-concurrent with this run.

    These are NOT necessarily caused by this run — the author flushes the
    pending queue when it crosses a threshold, so the folded finding can
    come from any prior run. This is why lessons are footer-rank, not
    headline-rank.
    """
    trace = run_dir / "tool_trace.jsonl"
    if not trace.is_file():
        return {"available": False, "reason": "no tool_trace.jsonl"}
    since_iso = (
        _dt.datetime.fromtimestamp(trace.stat().st_mtime, tz=_dt.timezone.utc)
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
                commits.append(cur)
                cur = None
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


def render_footer(run_dir: Path, run_id: str) -> str:
    lc = lesson_changes(run_dir, run_id)
    if not lc.get("available"):
        body = f'<div class="empty">lesson change tracking unavailable ({esc(lc.get("reason", "?"))})</div>'
    elif not lc.get("commits"):
        body = f'<div class="empty">no lesson commits since this run started ({esc(lc["since"])})</div>'
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
            rows.append(block("lesson-commit", c["subject"], inner))
        body = "\n".join(rows)
    return f"""
<footer id="sec-footer" class="footer">
  <h2>concurrent lesson commits</h2>
  <div class="footer-caveat">
    The author flushes the pending-findings queue when it crosses the threshold,
    so commits below were authored during this run's wall-clock window but may
    fold in findings from earlier runs. They are not the headline result.
  </div>
  {body}
</footer>
"""


# ---------------------------------------------------------------------------
# TOC
# ---------------------------------------------------------------------------


def render_toc(n_gather: int, learning_anchors: list[str]) -> str:
    learning_links = ""
    label_map = {
        "sec-learning-actor": "Actor",
        "sec-learning-oracle": "Oracle",
        "sec-learning-judge": "Judge",
    }
    for a in learning_anchors:
        learning_links += f'<li class="item"><a href="#{a}">{label_map.get(a, a)}</a></li>'
    if not learning_anchors:
        learning_links = '<li class="item muted">(no artifacts)</li>'

    gather_links = ""
    for i in range(n_gather):
        gather_links += f'<li class="item"><a href="#sec-defender-gather-{i}">gather #{i}</a></li>'
    if n_gather == 0:
        gather_links = '<li class="item muted">(no calls)</li>'

    return f"""
<nav class="toc">
  <ul>
    <li class="section">Headline</li>
    <li class="item"><a href="#top">disposition + findings</a></li>

    <li class="section">§ Alert</li>
    <li class="item"><a href="#sec-alert">alert.json</a></li>

    <li class="section">§ Defender</li>
    <li class="item"><a href="#sec-defender-artifacts">investigation / report</a></li>
    <li class="item"><a href="#sec-defender-gather">gather subagents</a></li>
    {gather_links}
    <li class="item"><a href="#sec-defender-rawpayloads">gather_raw/</a></li>

    <li class="section">§ Learning</li>
    {learning_links}

    <li class="section">§ Raw</li>
    <li class="item"><a href="#sec-raw">stream-json events</a></li>

    <li class="section">Footer</li>
    <li class="item"><a href="#sec-footer">lesson commits</a></li>
  </ul>
</nav>
"""


# ---------------------------------------------------------------------------
# CSS — dark, lean, no animations. Themed scrollbars; nested blocks lose
# their left-border accent (top-level stages keep theirs) so depth reads
# as indentation, not as a wall of stacked colored bars.
# ---------------------------------------------------------------------------

CSS = """
:root {
  --bg: #0d1117;
  --bg-2: #161b22;
  --bg-3: #0f1620;
  --border: #30363d;
  --border-2: #21262d;
  --text: #c9d1d9;
  --text-dim: #8b949e;
  --text-bright: #f0f6fc;
  --accent: #58a6ff;
  --accent-defender: #58a6ff;
  --accent-learning: #a371f7;
  --accent-alert: #d29922;
  --accent-raw: #6e7681;
  --good: #3fb950;
  --warn: #d29922;
  --bad: #f85149;
  --code: #79c0ff;
}

* { box-sizing: border-box; scrollbar-color: #30363d #0d1117; scrollbar-width: thin; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 5px; border: 2px solid var(--bg); }
::-webkit-scrollbar-thumb:hover { background: #484f58; }
::-webkit-scrollbar-corner { background: var(--bg); }

html, body { margin: 0; padding: 0; }
body {
  font: 13px/1.55 -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg);
  color: var(--text);
  scroll-behavior: smooth;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

header.top {
  padding: 14px 24px;
  background: var(--bg-2);
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 20;
}
header.top h1 { margin: 0 0 4px 0; font-size: 15px; font-weight: 600; color: var(--text-bright); }
header.top .meta { font-size: 11px; color: var(--text-dim); font-family: 'SF Mono', Menlo, Consolas, monospace; }

/* ----- Headline ----- */
section.headline {
  padding: 20px 24px;
  background: var(--bg-3);
  border-bottom: 1px solid var(--border);
}
.tiles { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px; }
.tile {
  padding: 12px 16px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-2);
  border-left-width: 4px;
}
.tile-label { text-transform: uppercase; font-size: 10px; color: var(--text-dim); letter-spacing: 0.6px; }
.tile-value { font-size: 22px; font-weight: 600; margin: 4px 0; color: var(--text-bright); text-transform: uppercase; letter-spacing: 0.5px; }
.tile-sub { font-size: 11px; color: var(--text-dim); }
.tile-disp.disp-benign { border-left-color: var(--good); }
.tile-disp.disp-inconclusive { border-left-color: var(--warn); }
.tile-disp.disp-malicious { border-left-color: var(--bad); }
.tile-out.out-caught { border-left-color: var(--good); }
.tile-out.out-survived { border-left-color: var(--bad); }
.tile-out.out-undecidable { border-left-color: var(--warn); }
.tile-out.out-incoherent { border-left-color: var(--bad); }
.tile-out.out-skip-passthrough { border-left-color: var(--text-dim); }

.headline-body, .headline-findings {
  padding: 12px 16px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-2);
  margin-top: 12px;
}
.hb-label { text-transform: uppercase; font-size: 10px; color: var(--text-dim); letter-spacing: 0.6px; margin-bottom: 8px; }
.hb-text { white-space: pre-wrap; color: var(--text); font-size: 13px; line-height: 1.6; }

.findings-list { list-style: none; padding: 0; margin: 0; }
.finding {
  display: grid;
  grid-template-columns: 160px 1fr 200px;
  gap: 12px;
  padding: 6px 0;
  border-bottom: 1px solid var(--border-2);
  font-size: 12px;
}
.finding:last-child { border-bottom: none; }
.finding .ftype { font-family: 'SF Mono', Menlo, Consolas, monospace; color: var(--code); font-size: 11px; }
.finding .ftopic { color: var(--text); }
.finding .fanchor { font-family: 'SF Mono', Menlo, Consolas, monospace; color: var(--text-dim); font-size: 11px; text-align: right; }
.finding-detection-confirmed .ftype { color: var(--good); }
.finding-observability .ftype { color: var(--warn); }
.finding-lead-set .ftype { color: var(--accent); }

/* ----- Layout: TOC + content ----- */
.layout {
  display: grid;
  grid-template-columns: 240px 1fr;
  align-items: start;
}
nav.toc {
  position: sticky;
  top: 53px;          /* header height */
  align-self: start;
  height: calc(100vh - 53px);
  overflow-y: auto;
  padding: 16px 12px 24px 20px;
  border-right: 1px solid var(--border);
  background: var(--bg);
}
nav.toc ul { list-style: none; padding: 0; margin: 0; }
nav.toc li.section {
  margin: 14px 0 4px;
  text-transform: uppercase;
  font-size: 10px;
  color: var(--text-dim);
  letter-spacing: 0.6px;
  font-weight: 600;
}
nav.toc li.section:first-child { margin-top: 0; }
nav.toc li.item a {
  display: block;
  padding: 3px 0 3px 12px;
  color: var(--text);
  text-decoration: none;
  font-size: 12px;
  border-left: 2px solid transparent;
  margin-left: 2px;
}
nav.toc li.item a:hover { color: var(--text-bright); border-left-color: var(--accent); background: var(--bg-2); }
nav.toc li.item.muted { padding: 3px 0 3px 14px; color: var(--text-dim); font-size: 11px; font-style: italic; }

article.content {
  padding: 24px 32px 80px;
  max-width: 1200px;
  min-width: 0;
}

/* ----- Stages ----- */
section.stage {
  margin-bottom: 40px;
  padding: 16px 18px;
  border: 1px solid var(--border);
  border-left-width: 4px;
  border-radius: 6px;
  background: var(--bg-2);
  scroll-margin-top: 64px;
}
section.stage h2 {
  margin: 0 0 4px;
  font-size: 17px;
  font-weight: 600;
  color: var(--text-bright);
}
section.stage h2 .stage-sub {
  font-size: 12px;
  font-weight: 400;
  color: var(--text-dim);
  margin-left: 6px;
}
section.stage h3 {
  margin: 18px 0 8px;
  font-size: 12px;
  text-transform: uppercase;
  color: var(--text-dim);
  letter-spacing: 0.6px;
  border-bottom: 1px solid var(--border-2);
  padding-bottom: 4px;
}
section.stage .stage-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 8px; }
section.stage-alert { border-left-color: var(--accent-alert); }
section.stage-defender { border-left-color: var(--accent-defender); }
section.stage-learning { border-left-color: var(--accent-learning); }
section.stage-raw { border-left-color: var(--accent-raw); }

/* ----- Footer ----- */
footer.footer {
  border-top: 1px solid var(--border);
  padding: 24px 32px 80px;
  background: var(--bg-3);
  color: var(--text);
  margin-left: 240px;        /* align with content column, not TOC */
}
footer.footer h2 { font-size: 12px; text-transform: uppercase; color: var(--text-dim); margin: 0 0 8px; letter-spacing: 0.6px; }
footer.footer .footer-caveat { font-size: 12px; color: var(--text-dim); margin-bottom: 12px; max-width: 760px; line-height: 1.5; }

/* ----- Blocks (collapsibles) -----
   Inner blocks intentionally have NO left-border accent — accents are
   reserved for top-level stages. Inner nesting reads as indentation plus
   a subtle background tint on hover. */
details.block { margin: 4px 0; }
details.block > summary {
  cursor: pointer;
  padding: 4px 8px;
  font-weight: 500;
  user-select: none;
  border-radius: 3px;
  color: var(--text);
  list-style: revert;
}
details.block > summary:hover { background: var(--bg-3); color: var(--text-bright); }
details.block > .body { padding: 6px 0 6px 14px; }

/* subcalls (gather/actor/oracle/judge) get a thin left accent so they
   stand out from regular collapsibles. */
details.block.subcall > summary { background: var(--bg-3); border-left: 3px solid var(--border); padding-left: 10px; }
details.block.subcall.actor > summary { border-left-color: var(--bad); }
details.block.subcall.oracle > summary { border-left-color: var(--warn); }
details.block.subcall.judge > summary { border-left-color: var(--good); }
details.block.subcall.error > summary { border-left-color: var(--bad); }

details.block.lesson-commit > summary { color: var(--text-bright); font-weight: 500; }
.commit-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 4px; font-family: 'SF Mono', Menlo, Consolas, monospace; }

/* ----- Code blocks ----- */
pre {
  background: var(--bg);
  border: 1px solid var(--border-2);
  border-radius: 4px;
  padding: 8px 12px;
  margin: 4px 0;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font: 12px/1.5 'SF Mono', Menlo, Consolas, monospace;
}
pre.json { color: var(--code); }
pre.text { color: var(--text); }
pre.diff { color: var(--text); }
pre.files { font-size: 11px; color: var(--text-dim); }
.text-block { padding: 4px 0; white-space: pre-wrap; }

.empty { font-size: 11px; color: var(--text-dim); padding: 6px 0; font-style: italic; }
"""


# ---------------------------------------------------------------------------
# Top-level render
# ---------------------------------------------------------------------------


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

    judge = load_judge_findings(case_id)
    defender_html, gather_calls = render_defender_section(run_dir, events)
    learning_html, learning_anchors = render_learning_section(case_id)

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>defender run: {esc(case_id)}</title>
<style>{CSS}</style></head><body id="top">
<header class="top">
  <h1>defender run: {esc(case_id)}</h1>
  <div class="meta">events={n_events} · tool_calls={n_tool_calls} · cost=${cost:.4f} · run_dir={esc(str(run_dir))}</div>
</header>
{render_headline(run_dir, case_id, judge)}
<div class="layout">
  {render_toc(len(gather_calls), learning_anchors)}
  <article class="content">
    {render_alert_section(run_dir)}
    {defender_html}
    {learning_html}
    {render_raw_transcript(events)}
  </article>
</div>
{render_footer(run_dir, case_id)}
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
