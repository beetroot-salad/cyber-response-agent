"""HTML escaping + raw event renderers + shared content fragments.

This is the "no-business-logic" tier of the visualize_run pipeline:
everything here is either a tiny HTML helper, a file-loading shim, or
a renderer that turns a single stream-json event / artifact into HTML.
The judge and runtime views both import from here.

Sibling imports work because `python3 defender/scripts/visualize_run.py`
puts ``defender/scripts/`` on sys.path; no package boilerplate needed.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

try:
    import yaml  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover — yaml is in defender deps
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Raw transcript event helpers (used by the Runtime view's § Raw section
# *and* by the per-phase inner-events expander)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Shared content fragments (used by both judge and runtime views)
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


def load_judge_benign_findings(run_id: str) -> dict | None:
    """Benign (FP-direction) judge output — the mirror of load_judge_findings.

    The two directions persist under different names so they never collide in
    one run dir; the benign direction writes ``judge_benign_findings.yaml``.
    """
    learn_dir = REPO_ROOT / "defender" / "learning" / "runs" / run_id
    data = load_yaml(learn_dir / "judge_benign_findings.yaml")
    return data if isinstance(data, dict) else None


def render_alert_block(run_dir: Path, *, open_: bool = False, anchor: str = "sec-alert") -> str:
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
<section id="{esc(anchor)}" class="stage stage-alert">
  <h2>§ Alert <span class="stage-sub">— input to the defender runtime</span></h2>
  {body}
</section>
"""


def render_lead_sequence_compact(run_dir: Path) -> str:
    """Compact lead list — position, goal one-liner, queries[].id + params.

    This is the judge's view of "what did the defender measure?". Raw
    payloads stay collapsed under § Runtime.
    """
    p = run_dir / "lead_sequence.yaml"
    data = load_yaml(p)
    if not isinstance(data, dict):
        return '<div class="empty">no lead_sequence.yaml</div>'
    entries = data.get("entries") or []
    if not entries:
        return '<div class="empty">lead_sequence has no entries</div>'
    rows: list[str] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        pos = e.get("position", "?")
        ld = e.get("lead_description") or {}
        goal = ld.get("goal", "") if isinstance(ld, dict) else ""
        queries = e.get("queries") or []
        q_html = ""
        if isinstance(queries, list):
            q_rows: list[str] = []
            for q in queries:
                if not isinstance(q, dict):
                    continue
                qid = q.get("id", "?")
                params = q.get("params") or {}
                params_str = json.dumps(params, ensure_ascii=False) if params else ""
                q_rows.append(
                    f'<div class="lead-query"><span class="qid">{esc(qid)}</span> '
                    f'<span class="qparams">{esc(params_str)}</span></div>'
                )
            q_html = "".join(q_rows)
        rows.append(
            f'<div class="lead-row">'
            f'<div class="lead-head"><span class="lead-pos">#{esc(str(pos))}</span></div>'
            f'<div class="lead-body">'
            f'<div class="lead-goal">{esc(goal)}</div>'
            f'{q_html}'
            f'</div>'
            f'</div>'
        )
    return f'<div class="lead-list">{"".join(rows)}</div>'


def render_report_card(run_dir: Path) -> str:
    """Report disposition + body, presented as a card (shared by both views)."""
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
