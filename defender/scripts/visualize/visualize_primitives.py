from __future__ import annotations

import html
import json
import re
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]

from defender._yaml import safe_load  # noqa: E402
from defender._report import ReportRead, read_report  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.learning import lead_repository  # noqa: E402
from defender.learning.core import config as _loop_config  # noqa: E402
from defender.learning.core.directions import Direction  # noqa: E402




def esc(s) -> str:
    return html.escape(s if isinstance(s, str) else json.dumps(s, indent=2))


#: An `on<word>=`-shaped event-handler attribute pattern, e.g. `onerror=`. `esc()` already
#: makes this inert HTML (the enclosing `<tag ...>` is neutralized into text), but the
#: pattern still reads as a live handler to a downstream non-HTML-aware consumer (a plain
#: text viewer, a naive markdown renderer someone pastes this into) — split it with a
#: zero-width space, invisible in any HTML rendering.
_EVENT_HANDLER_RE = re.compile(r"\bon(?=[a-zA-Z]\w*\s*=)")


def esc_untrusted(s) -> str:
    """`esc()`, plus the event-handler split above — for text whose source is
    attacker-influenced by construction (a model-authored session store payload, per
    `session_store`'s own access table), as opposed to internal/structural strings."""
    return _EVENT_HANDLER_RE.sub("on\u200b", esc(s))


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


def pre_text_untrusted(text: str) -> str:
    """`pre_text` for model-authored content — see `esc_untrusted`."""
    return f'<pre class="text">{esc_untrusted(text)}</pre>'


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




def parse_report(run_dir: Path) -> ReportRead:
    """This run's report, read through the one accessor every consumer shares (#785). Typed
    rather than a merged `{**frontmatter, "body": ...}` dict: that shape let the model's own
    frontmatter keys collide with the view's, and left each page free to invent its own
    reading of a disposition it could not validate."""
    return read_report(RunPaths(run_dir).report)


def _learning_run_dir(run_id: str) -> Path:
    return _loop_config.learning_run_paths(run_id).run_dir


def load_judge_doc(run_id: str, direction: Direction) -> dict | None:
    data = load_yaml(_learning_run_dir(run_id) / direction.judge_name)
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
        for q in jl.rows:  # run inspection — the whole table, sentinels included (#841)
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
    disposition = report.disposition_or_unknown
    confidence = str(report.frontmatter.get("confidence", "?"))
    body = report.body.strip() or "(no report body)"
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
