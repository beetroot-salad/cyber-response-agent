from __future__ import annotations

import html
import json
import math
import re
from pathlib import Path



REPO_ROOT = Path(__file__).resolve().parents[3]

#: The stylesheet every rendered page inlines, read once at import.
ASSETS = Path(__file__).resolve().parent / "assets"
CSS = (ASSETS / "styles.css").read_text(encoding="utf-8")  # lint-whole-read: ok — repo-shipped visualizer asset; operator-controlled, not on any box-writable mount

from defender._report import ReportRead, read_report  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402




def esc(s) -> str:
    return html.escape(s if isinstance(s, str) else json.dumps(s, indent=2))


#: An `on<word>=`-shaped event-handler attribute, e.g. `onerror=`. Already inert after `esc()`,
#: but it still reads as a live handler to non-HTML-aware consumers (plain text viewers, naive
#: markdown renderers), so it is split with an invisible zero-width space. Case-insensitive,
#: like HTML attribute names.
EVENT_HANDLER_RE = re.compile(r"\bon(?=[a-zA-Z]\w*\s*=)", re.IGNORECASE)


def esc_untrusted(s) -> str:
    """`esc()`, plus the event-handler split above — for attacker-influenced text (e.g. a
    model-authored session store payload), as opposed to internal/structural strings."""
    # A callable rather than the literal `"on​"`, which would case-fold `ONERROR=`.
    return EVENT_HANDLER_RE.sub(lambda m: m.group(0) + "\u200b", esc(s))


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
    # A non-finite span (a sum of walls can overflow) is the dash, not a raise.
    if not ms or ms <= 0 or not math.isfinite(ms):
        return "—"
    s = int(ms // 1000)
    if s < 60:
        return f"{s}s"
    return f"{s // 60}m{s % 60:02d}s"




def parse_report(run_dir: Path) -> ReportRead:
    """This run's report, via the shared accessor. Typed rather than a merged dict, so the
    model's frontmatter keys cannot collide with the view's and no page invents its own
    reading of an invalid disposition."""
    return read_report(RunPaths(run_dir).report)






def render_alert_block(run_dir: Path, *, open_: bool = False, anchor: str = "sec-alert") -> str:
    p = RunPaths(run_dir).alert
    if not p.is_file():
        body = '<div class="empty">no alert.json</div>'  # lint-run-records: ok — page text naming the record for a reader, not a path
    else:
        try:
            body = pretty_json_html(json.loads(p.read_text(encoding="utf-8")))  # lint-whole-read: ok — alert.json: external alert copied in by the host; also box-writable in the rw run dir, so bounded at 64 MiB by the box fsize limit; operator render at run end
        except json.JSONDecodeError:
            body = pre_text(p.read_text(encoding="utf-8"))  # lint-whole-read: ok — alert.json: external alert copied in by the host; also box-writable in the rw run dir, so bounded at 64 MiB by the box fsize limit; operator render at run end
    return section(anchor, "alert", "Alert", "— input to the defender runtime", body)
