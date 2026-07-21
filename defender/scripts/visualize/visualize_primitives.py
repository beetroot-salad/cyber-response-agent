from __future__ import annotations

import html
import json
import re
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]

from defender._yaml import safe_load  # noqa: E402
from defender._frontmatter import FrontmatterError, parse_frontmatter  # noqa: E402
from defender._io import TEXT_READ_ERRORS, read_text_utf8  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.learning import lead_repository  # noqa: E402
from defender.learning.core import config as _loop_config  # noqa: E402




def esc(s) -> str:
    return html.escape(s if isinstance(s, str) else json.dumps(s, indent=2))


def load_yaml(path: Path) -> dict | list | None:
    if not path.is_file():
        return None
    try:
        return safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return None


def block(kind: str, title: str, body: str, *, open_: bool = False, anchor: str | None = None) -> str:
    open_attr = " open" if open_ else ""
    id_attr = f' id="{esc(anchor)}"' if anchor else ""
    return (
        f'<details class="block {kind}"{open_attr}{id_attr}>'
        f'<summary>{esc(title)}</summary>'
        f'<div class="body">{body}</div>'
        f'</details>'
    )


def section(anchor: str, stage: str, title: str, subtitle: str, body: str) -> str:
    return f"""
<section id="{esc(anchor)}" class="stage stage-{stage}">
  <h2>{title} <span class="stage-sub">{subtitle}</span></h2>
  {body}
</section>
"""


def pre_text(text: str) -> str:
    return f'<pre class="text">{esc(text)}</pre>'


def pre_json(obj) -> str:
    try:
        rendered = json.dumps(obj, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        rendered = str(obj)
    return f'<pre class="json">{esc(rendered)}</pre>'


_JSON_TOKEN_RE = re.compile(
    r'"(?:\\.|[^"\\])*"(?:\s*:)?'
    r'|\b(?:true|false|null)\b'
    r'|-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?'
)


def _json_token_class(tok: str) -> str:
    if tok.startswith('"'):
        return "j-key" if tok.rstrip().endswith(":") else "j-str"
    if tok in ("true", "false"):
        return "j-bool"
    if tok == "null":
        return "j-null"
    return "j-num"


def pretty_json_html(obj) -> str:
    try:
        text = json.dumps(obj, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        return pre_text(str(obj))

    def _wrap(m: re.Match) -> str:
        tok = m.group(0)
        return f'<span class="{_json_token_class(tok)}">{html.escape(tok)}</span>'

    return f'<pre class="json-pretty">{_JSON_TOKEN_RE.sub(_wrap, text)}</pre>'


def slugify(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "section"


def fmt_duration(ms: float | int) -> str:
    if not ms or ms <= 0:
        return "—"
    s = int(ms // 1000)
    if s < 60:
        return f"{s}s"
    return f"{s // 60}m{s % 60:02d}s"




def render_tool_use(blk: dict) -> str:
    return block(
        "tool-use",
        f"→ {blk.get('name', '?')}  ({blk.get('id', '')})",
        pre_json(blk.get("input", {})),
    )


def flatten_tool_result_content(content) -> str:
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
    body = flatten_tool_result_content(blk.get("content", ""))
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




def parse_report(run_dir: Path) -> dict:
    p = RunPaths(run_dir).report
    if not p.is_file():
        return {}
    try:
        text = read_text_utf8(p)
    except TEXT_READ_ERRORS:
        return {}
    try:
        fm, body = parse_frontmatter(text)
    except FrontmatterError:
        return {"body": text}
    return {**fm, "body": body}


def _learning_run_dir(run_id: str) -> Path:
    return _loop_config.learning_run_paths(run_id).run_dir


def load_judge_findings(run_id: str) -> dict | None:
    data = load_yaml(_learning_run_dir(run_id) / "judge_findings.yaml")
    return data if isinstance(data, dict) else None


def load_judge_benign_findings(run_id: str) -> dict | None:
    data = load_yaml(_learning_run_dir(run_id) / "judge_benign_findings.yaml")
    return data if isinstance(data, dict) else None


def render_alert_block(run_dir: Path, *, open_: bool = False, anchor: str = "sec-alert") -> str:
    p = RunPaths(run_dir).alert
    if not p.is_file():
        body = '<div class="empty">no alert.json</div>'
    else:
        try:
            body = pretty_json_html(json.loads(p.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            body = pre_text(p.read_text(encoding="utf-8"))
    return section(anchor, "alert", "Alert", "— input to the defender runtime", body)


def render_lead_sequence_compact(run_dir: Path) -> str:
    leads = lead_repository.joined(run_dir)
    if not leads:
        return '<div class="empty">no leads recorded</div>'
    rows: list[str] = []
    for jl in leads:
        goal = jl.goal or ""
        q_rows: list[str] = []
        for q in jl.queries:
            params_str = json.dumps(q.params, ensure_ascii=False) if q.params else ""
            q_rows.append(
                f'<div class="lead-query"><span class="qid">{esc(q.query_id or "?")}</span> '
                f'<span class="qparams">{esc(params_str)}</span></div>'
            )
        q_html = "".join(q_rows)
        rows.append(
            f'<div class="lead-row">'
            f'<div class="lead-head"><span class="lead-pos">{esc(jl.lead_id)}</span></div>'
            f'<div class="lead-body">'
            f'<div class="lead-goal">{esc(goal)}</div>'
            f'{q_html}'
            f'</div>'
            f'</div>'
        )
    return f'<div class="lead-list">{"".join(rows)}</div>'


def render_report_card(run_dir: Path) -> str:
    report = parse_report(run_dir)
    disposition = str(report.get("disposition", "?"))
    confidence = str(report.get("confidence", "?"))
    body = report.get("body", "").strip() or "(no report body)"
    return (
        f'<div class="report-card">'
        f'<div class="report-meta">'
        f'<span class="rm-key">disposition:</span> '
        f'<span class="rm-val disp-{esc(disposition)}">{esc(disposition)}</span>'
        f'  ·  <span class="rm-key">confidence:</span> '
        f'<span class="rm-val">{esc(confidence)}</span>'
        f'</div>'
        f'<div class="report-body">{esc(body)}</div>'
        f'</div>'
    )
