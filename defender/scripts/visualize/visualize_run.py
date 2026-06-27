#!/usr/bin/env python3
"""Render a defender run as two self-contained HTML pages.

A run serves two first-class concerns:

    transcript.html — Judge evaluation (default landing).
        Optimized for assessing the learning loop's judgment: what did
        the defender produce, what counterfactual story did the actor
        write, what did the judge conclude. Surfaces report.md + a
        compact lead list (the judge's *input*), the actor story, then
        judge outcome + findings + encounter analysis. Oracle and raw
        artifacts collapse below the fold.

    runtime.html — Defender run inspection.
        The *process* page. A top fold answers the run at a glance — an
        ANALYSIS card (disposition + execution health + report.md + lead
        summary) beside a METRICS card (total cost / wall + per-phase
        bars) — over a muted metadata byline. Below it: investigation.md
        split by phase, a searchable / filterable chronological transcript
        (built from llm_requests.jsonl), and the § Leads & queries data
        trail. A sticky phase sidebar navigates the transcript.

The two pages cross-link via a header tab strip and share their CSS.

Module layout (all in defender/scripts/, sibling imports thanks to
Python prepending the script's directory to sys.path):

    visualize_run.py        — this file: CLI, CSS + transcript JS, page
                              composition, header / byline / top fold
    visualize_primitives.py — esc / block / pre helpers, load_*,
                              raw event renderers, shared content
                              fragments (alert, lead list, report card)
    visualize_data.py       — pricing, cost attribution, phase tagging,
                              wall times + the llm_requests.jsonl readers
                              (transcript, tool usage, cost, health)
    visualize_judge.py      — judge view sections + TOC
    visualize_runtime.py    — runtime view sections + TOC + footer

Usage:
    python3 defender/scripts/visualize/visualize_run.py <run_dir>
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning import lead_repository
from defender.scripts.visualize.visualize_data import (
    build_transcript,
    gather_cost_by_phase,
    load_messages,
    msg_phase_map,
    normalize_phase_names,
    phase_attribution,
    phase_color,
    phase_verb,
    phase_wall_times,
    run_health,
    run_metadata,
    split_investigation_phases,
    tag_events_by_phase,
    tool_usage,
)
from defender.scripts.visualize.visualize_judge import (
    render_judge_actor_benign_section,
    render_judge_actor_section,
    render_judge_benign_section,
    render_judge_defender_summary,
    render_judge_judge_section,
    render_judge_oracle_benign_section,
    render_judge_oracle_section,
    render_judge_raw_bundle,
    render_judge_toc,
)
from defender.scripts.visualize.visualize_primitives import (
    esc,
    fmt_duration,
    load_jsonl,
    load_judge_benign_findings,
    load_judge_findings,
    parse_report,
    render_alert_block,
)
from defender.scripts.visualize.visualize_runtime import (
    render_footer,
    render_runtime_investigation,
    render_runtime_leads_queries,
    render_runtime_toc,
    render_runtime_transcript,
)


JUDGE_FILENAME = "transcript.html"
RUNTIME_FILENAME = "runtime.html"

_DEFENDER_DIR = Path(__file__).resolve().parents[2]
_REPO_ROOT = _DEFENDER_DIR.parent


def render_and_mirror(run_dir: Path) -> list[Path]:
    """Render the judge + runtime pages into ``run_dir`` and mirror them into
    ``defender/run-visualizations/<run_id>/``.

    The mirror lives here (not just in run.py) so every renderer — run.py's
    pre-learn pass AND the off-process learn worker's post-learn re-render —
    refreshes it identically; the post-learn pass wins (last write), leaving the
    repo-persisted copy carrying the judge eval even if /tmp is later cleared.
    The judge page resolves its artifacts by case_id from the learning state
    dir (``load_judge_findings``), so re-rendering picks them up wherever they
    landed. Mirrored into a per-run subdir because the pages cross-link via
    relative hrefs.
    """
    (run_dir / JUDGE_FILENAME).write_text(render_judge_page(run_dir))
    (run_dir / RUNTIME_FILENAME).write_text(render_runtime_page(run_dir))
    dest_dir = _DEFENDER_DIR / "run-visualizations" / run_dir.name
    mirrored: list[Path] = []
    for fname in (JUDGE_FILENAME, RUNTIME_FILENAME):
        src = run_dir / fname
        if not src.is_file():
            continue
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / fname
        shutil.copyfile(src, dest)
        mirrored.append(dest)
    return mirrored


# ---------------------------------------------------------------------------
# Header + tabs (shared across views)
# ---------------------------------------------------------------------------


def render_header(case_id: str, active: str, byline: str) -> str:
    judge_active = " active" if active == "judge" else ""
    runtime_active = " active" if active == "runtime" else ""
    return f"""
<header class="top">
  <div class="top-row">
    <h1>defender run: {esc(case_id)}</h1>
    <nav class="tabs">
      <a class="tab{judge_active}" href="{JUDGE_FILENAME}">Judge eval</a>
      <a class="tab{runtime_active}" href="{RUNTIME_FILENAME}">Runtime inspection</a>
    </nav>
  </div>
  <div class="byline">{byline}</div>
</header>
"""


def _byline(parts: list[str]) -> str:
    """Muted 'contact-info'-style line: the items joined by dot separators. The
    items are already escaped/safe by their callers."""
    return '<span class="bl-sep">·</span>'.join(
        f'<span class="bl-item">{p}</span>' for p in parts if p
    )


# ---------------------------------------------------------------------------
# Headlines (one per view)
# ---------------------------------------------------------------------------


def render_judge_headline(run_dir: Path, judge: dict | None, judge_benign: dict | None = None) -> str:
    report = parse_report(run_dir)
    disposition = str(report.get("disposition", "?"))
    confidence = str(report.get("confidence", "?"))
    # Prefer the adversarial outcome (FN-hunt); fall back to the benign
    # (FP-hunt) direction when that's the one that ran (malicious disposition).
    if judge:
        outcome = str(judge.get("outcome", "—"))
        n_findings = len(judge.get("defender_findings") or [])
        direction_sub = f"{n_findings} finding(s)"
    elif judge_benign:
        outcome = str(judge_benign.get("outcome", "—"))
        n_findings = len(judge_benign.get("defender_findings") or [])
        direction_sub = f"{n_findings} finding(s) · benign direction"
    else:
        outcome = "—"
        direction_sub = "0 finding(s)"
    return f"""
<section class="headline">
  <div class="tiles">
    <div class="tile tile-out out-{esc(outcome)}">
      <div class="tile-label">judge outcome</div>
      <div class="tile-value">{esc(outcome)}</div>
      <div class="tile-sub">{esc(direction_sub)}</div>
    </div>
    <div class="tile tile-disp disp-{esc(disposition)}">
      <div class="tile-label">defender disposition</div>
      <div class="tile-value">{esc(disposition)}</div>
      <div class="tile-sub">confidence: {esc(confidence)}</div>
    </div>
  </div>
</section>
"""


_HEALTH_ICON = {"good": "✓", "warn": "⚠", "bad": "✗"}


def render_runtime_headline(
    run_dir: Path,
    report: dict,
    health: dict,
    attribution: dict[str, dict],
    phase_order: list[str],
    wall_times: dict[str, dict],
    totals: dict,
    leads: list,
) -> str:
    """The top fold: an ANALYSIS card (disposition + execution health + report +
    lead summary) beside a METRICS card (total cost / wall + per-phase bars)."""
    disposition = str(report.get("disposition", "?"))
    confidence = str(report.get("confidence", "?"))
    body = report.get("body", "").strip() or "(no report body)"

    icon = _HEALTH_ICON.get(health["level"], "•")
    detail = (
        f' <span class="health-detail">· {esc(" · ".join(health["details"]))}</span>'
        if health.get("details")
        else ""
    )
    health_html = (
        f'<span class="health health-{esc(health["level"])}">{icon} {esc(health["label"])}</span>{detail}'
    )

    cost_bar = _phase_bar(
        {ph: (attribution.get(ph) or {}).get("cost", 0.0) for ph in phase_order},
        phase_order, lambda v: f"${v:.3f}",
    )
    wall_bar = _phase_bar(
        {ph: (wall_times.get(ph) or {}).get("duration_sec", 0.0) for ph in phase_order},
        phase_order, lambda v: fmt_duration(v * 1000),
    )
    model_bits = " · ".join(
        f"{esc(k)} ${v:.4f}" for k, v in (totals.get("by_model") or {}).items() if v
    )
    foot = f'loops {health["loops"]} · turns {health["turns"]} · {totals.get("tool_calls", 0)} tool calls'

    return f"""
<section class="headline">
  <div class="fold">
    <div class="fold-card card-analysis">
      <div class="card-label">analysis</div>
      <div class="an-top">
        <span class="disp-badge disp-{esc(disposition)}">{esc(disposition)}</span>
        <span class="an-conf">confidence: {esc(confidence)}</span>
      </div>
      <div class="an-health">{health_html}</div>
      <div class="an-report">{esc(body)}</div>
      <div class="an-leads">{_lead_summary(leads)}</div>
    </div>
    <div class="fold-card card-metrics">
      <div class="card-label">metrics</div>
      <div class="me-top">
        <span class="me-cost">${totals.get("cost", 0.0):.4f}</span>
        <span class="me-wall">{fmt_duration(totals.get("wall_ms", 0))}</span>
      </div>
      <div class="me-models">{model_bits}</div>
      <div class="me-bar-row"><span class="me-bar-label">cost</span><div class="cost-bar">{cost_bar}</div></div>
      <div class="me-bar-row"><span class="me-bar-label">wall</span><div class="cost-bar">{wall_bar}</div></div>
      <div class="me-foot">{esc(foot)}</div>
    </div>
  </div>
</section>
"""


# ---------------------------------------------------------------------------
# Top-fold helpers: per-phase segmented bar + compact lead summary
# ---------------------------------------------------------------------------


def _phase_bar(values: dict[str, float], phase_order: list[str], fmt) -> str:
    """A segmented bar: one slice per phase, width proportional to its value
    (cost or wall seconds), colored by phase. Reuses the shared .cost-bar CSS."""
    total = sum(v for v in values.values() if v and v > 0)
    if total <= 0:
        return '<div class="empty">(no per-phase attribution)</div>'
    segs: list[str] = []
    for ph in phase_order:
        v = values.get(ph, 0.0) or 0.0
        if v <= 0:
            continue
        pct = v / total * 100
        verb = phase_verb(ph)
        title = f"{ph} · {fmt(v)} · {pct:.1f}%"
        segs.append(
            f'<div class="cb-seg" style="width:{pct:.4f}%;background:{phase_color(verb)}" '
            f'title="{esc(title)}"><span class="cb-label">{esc(verb[:3])}</span>'
            f'<span class="cb-pct">{esc(fmt(v))}</span></div>'
        )
    return "".join(segs)


def _lead_summary(leads: list) -> str:
    """The analysis card's compact lead list: id + truncated goal + a ∅ marker
    for dead-ends. The full queries live in § Leads & queries below."""
    if not leads:
        return '<span class="empty">no leads</span>'
    rows: list[str] = []
    for jl in leads:
        dead = jl.orphan or not jl.queries
        goal = (jl.goal or ("orphan" if jl.orphan else "")).strip()
        if len(goal) > 64:
            goal = goal[:61] + "…"
        mark = ' <span class="lead-dead">∅</span>' if dead else ""
        rows.append(
            f'<div class="lead-mini"><span class="lead-mini-id">{esc(jl.lead_id)}</span>'
            f'<span class="lead-mini-goal">{esc(goal)}</span>{mark}</div>'
        )
    return f'<div class="an-sublabel">leads</div><div class="lead-mini-list">{"".join(rows)}</div>'


# ---------------------------------------------------------------------------
# CSS (shared)
# ---------------------------------------------------------------------------


CSS = """
:root {
  --bg: #0d1117;
  --bg-2: #161b22;
  --bg-3: #0f1620;
  --bg-4: #1c2128;
  --border: #30363d;
  --border-2: #21262d;
  --text: #c9d1d9;
  --text-dim: #8b949e;
  --text-bright: #f0f6fc;
  --accent: #58a6ff;
  --accent-defender: #58a6ff;
  --accent-learning: #a371f7;
  --accent-actor: #f85149;
  --accent-judge: #3fb950;
  --accent-oracle: #d29922;
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

/* ----- Top header + tabs ----- */
header.top {
  padding: 12px 24px 0;
  background: var(--bg-2);
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 20;
}
.top-row { display: flex; align-items: center; gap: 24px; }
header.top h1 { margin: 0; font-size: 15px; font-weight: 600; color: var(--text-bright); flex-shrink: 0; }
nav.tabs { display: flex; gap: 4px; margin-left: auto; }
nav.tabs .tab {
  padding: 8px 16px;
  font-size: 12px;
  color: var(--text-dim);
  border: 1px solid transparent;
  border-bottom: none;
  border-radius: 4px 4px 0 0;
  text-decoration: none;
  position: relative;
  top: 1px;
}
nav.tabs .tab:hover { color: var(--text-bright); text-decoration: none; background: var(--bg-3); }
nav.tabs .tab.active {
  color: var(--text-bright);
  background: var(--bg);
  border-color: var(--border);
  border-bottom-color: var(--bg);
  font-weight: 600;
}
header.top .meta {
  font-size: 11px;
  color: var(--text-dim);
  font-family: 'SF Mono', Menlo, Consolas, monospace;
  padding: 8px 0 10px;
}

/* ----- Headline ----- */
section.headline {
  padding: 20px 24px;
  background: var(--bg-3);
  border-bottom: 1px solid var(--border);
}
.tiles { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
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

.headline-body {
  padding: 12px 16px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-2);
}
.hb-label { text-transform: uppercase; font-size: 10px; color: var(--text-dim); letter-spacing: 0.6px; margin-bottom: 8px; }
.hb-text { white-space: pre-wrap; color: var(--text); font-size: 13px; line-height: 1.6; }

/* Two-column headline: disposition tile (narrow) + report.md (wide). */
.headline-grid {
  display: grid;
  grid-template-columns: minmax(220px, 280px) 1fr;
  gap: 12px;
  align-items: stretch;
}
.headline-grid .tile { display: flex; flex-direction: column; justify-content: center; }
.headline-grid .headline-body { margin-top: 0; }

/* Timing / cost breakdown — second row of the headline. */
.timing-cost {
  margin-top: 12px;
  padding: 12px 16px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-2);
}
.tc-summary { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 12px; color: var(--text); margin-bottom: 10px; }
.tc-summary .tc-key { color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.4px; font-size: 10px; margin-right: 4px; }
.tc-summary .tc-val { color: var(--text-bright); font-weight: 600; }
.tc-summary .tc-sep { color: var(--text-dim); margin: 0 8px; }
.cost-bar {
  display: flex;
  width: 100%;
  height: 28px;
  border-radius: 4px;
  overflow: hidden;
  border: 1px solid var(--border-2);
  background: var(--bg-3);
}
.cost-bar .cb-seg {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  color: rgba(13, 17, 23, 0.92);
  font-family: 'SF Mono', Menlo, Consolas, monospace;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.3px;
  overflow: hidden;
  white-space: nowrap;
  min-width: 0;
  border-right: 1px solid rgba(0, 0, 0, 0.15);
}
.cost-bar .cb-seg:last-child { border-right: none; }
.cost-bar .cb-label { text-transform: uppercase; }
.cost-bar .cb-pct { opacity: 0.8; font-weight: 500; }
.cost-bar-caveat { font-size: 10px; color: var(--text-dim); margin-top: 6px; font-style: italic; }
.tc-bar-row {
  display: grid;
  grid-template-columns: 48px 1fr;
  gap: 10px;
  align-items: center;
  margin-top: 8px;
}
.tc-bar-row .tc-bar-label {
  font-size: 10px;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  text-align: right;
  font-family: 'SF Mono', Menlo, Consolas, monospace;
}
.tc-help { margin-top: 10px; }
.tc-help > summary {
  font-size: 11px;
  color: var(--text-dim);
  cursor: pointer;
  user-select: none;
  padding: 4px 0;
}
.tc-help > summary:hover { color: var(--text-bright); }
.tc-help-body {
  font-size: 12px;
  color: var(--text);
  padding: 8px 12px;
  background: var(--bg-3);
  border: 1px solid var(--border-2);
  border-radius: 4px;
  margin-top: 4px;
  line-height: 1.55;
}
.tc-help-body p { margin: 0 0 8px; }
.tc-help-body p:last-child { margin-bottom: 0; }
.tc-help-body code { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px; color: var(--code); background: var(--bg); padding: 1px 4px; border-radius: 2px; }

/* Per-phase / per-call inline stats line. */
.phase-stats {
  font-family: 'SF Mono', Menlo, Consolas, monospace;
  font-size: 11px;
  color: var(--text-dim);
  padding: 6px 10px;
  margin: 0 0 6px;
  background: var(--bg-3);
  border: 1px solid var(--border-2);
  border-radius: 4px;
}
.phase-stats .ps-cost { color: var(--text-bright); font-weight: 600; }
.phase-stats .ps-wall { color: var(--text-bright); font-weight: 600; }
.phase-stats .ps-sep { margin: 0 6px; opacity: 0.5; }
.phase-stats .ps-tok { color: var(--text-dim); }
.phase-stats .ps-hist { color: var(--code); }

/* Per-phase event log — collapsible drill-down inside a phase block. */
details.block.phase-events { margin-top: 8px; }
details.block.phase-events > summary {
  background: var(--bg);
  border: 1px dashed var(--border-2);
  border-radius: 3px;
  padding: 4px 10px;
  color: var(--text-dim);
  font-size: 11px;
  font-weight: 500;
}
details.block.phase-events > summary:hover { color: var(--text-bright); border-color: var(--border); }
details.block.phase-events > .body { padding: 8px 0 8px 12px; }

/* ----- Layout ----- */
.layout {
  display: grid;
  grid-template-columns: 240px 1fr;
  align-items: start;
}
nav.toc {
  position: sticky;
  top: 84px;
  align-self: start;
  height: calc(100vh - 84px);
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
  margin-bottom: 32px;
  padding: 16px 18px;
  border: 1px solid var(--border);
  border-left-width: 4px;
  border-radius: 6px;
  background: var(--bg-2);
  scroll-margin-top: 96px;
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
  scroll-margin-top: 96px;
}
section.stage .stage-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 8px; }
section.stage-alert { border-left-color: var(--accent-alert); }
section.stage-defender { border-left-color: var(--accent-defender); }
section.stage-actor { border-left-color: var(--accent-actor); }
section.stage-judge { border-left-color: var(--accent-judge); }
section.stage-oracle { border-left-color: var(--accent-oracle); }
section.stage-raw { border-left-color: var(--accent-raw); }

/* ----- Report card ----- */
.report-card {
  background: var(--bg-3);
  border: 1px solid var(--border-2);
  border-radius: 5px;
  padding: 12px 14px;
  margin: 6px 0 12px;
}
.report-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 8px; font-family: 'SF Mono', Menlo, Consolas, monospace; }
.report-meta .rm-key { text-transform: uppercase; letter-spacing: 0.4px; }
.report-meta .rm-val { color: var(--text-bright); font-weight: 500; padding: 0 4px; }
.report-meta .rm-val.disp-benign { color: var(--good); }
.report-meta .rm-val.disp-inconclusive { color: var(--warn); }
.report-meta .rm-val.disp-malicious { color: var(--bad); }
.report-body { white-space: pre-wrap; line-height: 1.6; }

/* ----- Compact lead list ----- */
.lead-list { display: flex; flex-direction: column; gap: 8px; }
.lead-row {
  display: grid;
  grid-template-columns: 48px 1fr;
  gap: 12px;
  padding: 8px 10px;
  background: var(--bg-3);
  border: 1px solid var(--border-2);
  border-radius: 4px;
}
.lead-pos {
  font-family: 'SF Mono', Menlo, Consolas, monospace;
  color: var(--text-dim);
  font-size: 12px;
  font-weight: 600;
}
.lead-goal { color: var(--text); margin-bottom: 4px; }
.lead-query { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px; line-height: 1.5; }
.lead-query .qid { color: var(--code); }
.lead-query .qparams { color: var(--text-dim); margin-left: 6px; }

/* ----- Actor ----- */
.actor-meta { font-size: 12px; color: var(--text-dim); margin: 4px 0 8px; }
.actor-meta .key { text-transform: uppercase; letter-spacing: 0.4px; }
.actor-meta .val { color: var(--text-bright); margin-left: 4px; font-family: 'SF Mono', Menlo, Consolas, monospace; }
pre.story { background: var(--bg-3); }

/* ----- Judge outcome ----- */
.judge-outcome {
  padding: 12px 14px;
  border-radius: 5px;
  background: var(--bg-3);
  border: 1px solid var(--border-2);
  border-left: 4px solid var(--border);
  margin: 6px 0 12px;
}
.judge-outcome.out-caught { border-left-color: var(--good); }
.judge-outcome.out-survived { border-left-color: var(--bad); }
.judge-outcome.out-undecidable { border-left-color: var(--warn); }
.judge-outcome.out-incoherent { border-left-color: var(--bad); }
.judge-outcome.out-skip-passthrough { border-left-color: var(--text-dim); }
.outcome-value {
  font-size: 16px;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-bright);
  margin-bottom: 6px;
  letter-spacing: 0.4px;
}
.outcome-rationale { white-space: pre-wrap; line-height: 1.55; }

/* ----- Findings ----- */
.findings-grid { display: flex; flex-direction: column; gap: 12px; margin: 8px 0; }
.finding-card {
  background: var(--bg-3);
  border: 1px solid var(--border-2);
  border-left: 4px solid var(--border);
  border-radius: 5px;
  padding: 12px 14px;
  scroll-margin-top: 96px;
}
.finding-detection-confirmed { border-left-color: var(--good); }
.finding-observability { border-left-color: var(--warn); }
.finding-lead-set { border-left-color: var(--accent); }
.finding-head {
  display: grid;
  grid-template-columns: 180px 1fr 200px;
  gap: 12px;
  padding-bottom: 8px;
  margin-bottom: 8px;
  border-bottom: 1px solid var(--border-2);
  align-items: baseline;
}
.finding-head .ftype { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px; color: var(--code); }
.finding-detection-confirmed .ftype { color: var(--good); }
.finding-observability .ftype { color: var(--warn); }
.finding-lead-set .ftype { color: var(--accent); }
.finding-head .ftopic { color: var(--text-bright); font-weight: 500; font-size: 13px; }
.finding-head .fanchor { font-family: 'SF Mono', Menlo, Consolas, monospace; color: var(--text-dim); font-size: 11px; text-align: right; }
.finding-body { white-space: pre-wrap; line-height: 1.6; color: var(--text); }
.env-obs-crit, .env-obs-ents { font-size: 11px; color: var(--text-dim); margin-top: 6px; }
.env-obs-crit .key { text-transform: uppercase; letter-spacing: 0.4px; margin-right: 4px; }
.citations { margin-top: 10px; display: flex; flex-direction: column; gap: 6px; }
.citation {
  background: var(--bg-4);
  border: 1px solid var(--border-2);
  border-left: 3px solid var(--text-dim);
  border-radius: 3px;
  padding: 8px 10px;
}
.citation .cite-src {
  font-size: 10px;
  text-transform: uppercase;
  color: var(--text-dim);
  letter-spacing: 0.5px;
  margin-bottom: 4px;
  font-family: 'SF Mono', Menlo, Consolas, monospace;
}
.citation pre { margin: 0; background: transparent; border: none; padding: 0; }
.citation.citation-investigation { border-left-color: var(--accent-defender); }
.citation.citation-actor { border-left-color: var(--accent-actor); }
.citation.citation-projected_telemetry { border-left-color: var(--accent-oracle); }

pre.encounter { background: var(--bg-3); line-height: 1.55; }
pre.invlang { background: var(--bg-3); }

/* ----- Footer ----- */
footer.footer {
  border-top: 1px solid var(--border);
  padding: 24px 32px 80px;
  background: var(--bg-3);
  color: var(--text);
  margin-left: 240px;
}
footer.footer h2 { font-size: 12px; text-transform: uppercase; color: var(--text-dim); margin: 0 0 8px; letter-spacing: 0.6px; }
footer.footer .footer-caveat { font-size: 12px; color: var(--text-dim); margin-bottom: 12px; max-width: 760px; line-height: 1.5; }

/* ----- Collapsibles ----- */
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

details.block.phase > summary {
  background: var(--bg-3);
  border-left: 3px solid var(--accent-defender);
  padding: 6px 10px;
  font-weight: 600;
  color: var(--text-bright);
}

details.block.subcall > summary { background: var(--bg-3); border-left: 3px solid var(--border); padding-left: 10px; }
details.block.subcall.gather > summary { border-left-color: var(--accent-learning); }

details.block.lesson-commit > summary { color: var(--text-bright); font-weight: 500; }
.commit-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 4px; font-family: 'SF Mono', Menlo, Consolas, monospace; }

/* ----- Code ----- */
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
pre.files { font-size: 11px; color: var(--text-dim); }
.text-block { padding: 4px 0; white-space: pre-wrap; }

.empty { font-size: 11px; color: var(--text-dim); padding: 6px 0; font-style: italic; }

/* ----- Header byline (muted contact-info line) ----- */
.byline { font-size: 11px; color: var(--text-dim); font-family: 'SF Mono', Menlo, Consolas, monospace; padding: 8px 0 10px; }
.byline .bl-sep { margin: 0 8px; opacity: 0.5; }
.byline .bl-item { color: var(--text-dim); }

/* ----- Top fold: ANALYSIS | METRICS ----- */
.fold { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr); gap: 12px; align-items: stretch; }
.fold-card {
  position: relative;
  padding: 14px 16px 12px;
  border: 1px solid var(--border);
  border-left-width: 4px;
  border-radius: 6px;
  background: var(--bg-2);
  min-width: 0;
}
.card-analysis { border-left-color: var(--accent-defender); }
.card-metrics { border-left-color: var(--accent-learning); }
.card-label { position: absolute; top: 10px; right: 14px; text-transform: uppercase; font-size: 9px; letter-spacing: 0.8px; color: var(--text-dim); }

.an-top { display: flex; align-items: baseline; gap: 10px; margin-bottom: 8px; }
.disp-badge {
  font-size: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
  padding: 2px 10px; border-radius: 4px; color: var(--bg);
}
.disp-badge.disp-benign { background: var(--good); }
.disp-badge.disp-inconclusive { background: var(--warn); }
.disp-badge.disp-malicious { background: var(--bad); }
.disp-badge.disp-\\? { background: var(--text-dim); }
.an-conf { font-size: 11px; color: var(--text-dim); }
.an-health { font-size: 12px; margin-bottom: 10px; }
.health { font-weight: 600; }
.health-good { color: var(--good); }
.health-warn { color: var(--warn); }
.health-bad { color: var(--bad); }
.health-detail { color: var(--text-dim); font-weight: 400; }
.an-report { white-space: pre-wrap; line-height: 1.55; color: var(--text); font-size: 12.5px; margin-bottom: 10px; }
.an-sublabel { text-transform: uppercase; font-size: 9px; letter-spacing: 0.7px; color: var(--text-dim); margin: 6px 0 4px; }
.lead-mini-list { display: flex; flex-direction: column; gap: 3px; }
.lead-mini { display: flex; gap: 8px; font-size: 11px; align-items: baseline; }
.lead-mini-id { font-family: 'SF Mono', Menlo, Consolas, monospace; color: var(--code); flex-shrink: 0; }
.lead-mini-goal { color: var(--text-dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.lead-dead { color: var(--warn); font-weight: 700; }

.me-top { display: flex; gap: 20px; align-items: baseline; margin-bottom: 2px; }
.me-cost { font-size: 22px; font-weight: 700; color: var(--text-bright); font-family: 'SF Mono', Menlo, Consolas, monospace; }
.me-wall { font-size: 16px; font-weight: 600; color: var(--text); font-family: 'SF Mono', Menlo, Consolas, monospace; }
.me-models { font-size: 10px; color: var(--text-dim); font-family: 'SF Mono', Menlo, Consolas, monospace; margin-bottom: 8px; }
.me-bar-row { display: grid; grid-template-columns: 38px 1fr; gap: 8px; align-items: center; margin-top: 6px; }
.me-bar-label { font-size: 9px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; text-align: right; font-family: 'SF Mono', Menlo, Consolas, monospace; }
.me-foot { font-size: 11px; color: var(--text-dim); font-family: 'SF Mono', Menlo, Consolas, monospace; margin-top: 10px; }

.phase-stats .ps-gather { color: var(--accent-learning); margin-left: 6px; }

/* ----- Transcript ----- */
.tx-toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 4px 0 8px; }
.tx-toolbar input[type=search], .tx-toolbar select {
  background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
  color: var(--text); font-size: 12px; padding: 5px 9px;
}
.tx-toolbar .tx-search { flex: 1 1 240px; min-width: 160px; }
.tx-errtoggle { font-size: 11px; color: var(--text-dim); display: flex; align-items: center; gap: 4px; cursor: pointer; }
.tx-clear { background: var(--bg-3); border: 1px solid var(--border); border-radius: 4px; color: var(--text-dim); font-size: 11px; padding: 5px 10px; cursor: pointer; }
.tx-clear:hover { color: var(--text-bright); border-color: var(--accent); }
.tx-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
.tx-chip {
  background: var(--bg-3); border: 1px solid var(--border-2); border-radius: 12px;
  color: var(--text); font-size: 11px; padding: 3px 10px; cursor: pointer;
  font-family: 'SF Mono', Menlo, Consolas, monospace;
}
.tx-chip:hover { border-color: var(--accent); color: var(--text-bright); }
.tx-chip.chip-active { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.tx-chip .chip-n { opacity: 0.7; margin-left: 4px; }
.tx-chip .chip-err { color: var(--warn); margin-left: 5px; }
.tx-chip.chip-active .chip-err { color: var(--bg); }

.tx-stream { display: flex; flex-direction: column; gap: 6px; }
.tx-entry { display: grid; grid-template-columns: 56px 1fr; gap: 10px; padding: 8px 10px; border: 1px solid var(--border-2); border-radius: 5px; background: var(--bg-3); scroll-margin-top: 100px; }
.tx-entry[hidden] { display: none; }
.tx-assistant { border-left: 3px solid var(--accent-defender); }
.tx-result { border-left: 3px solid var(--border); background: var(--bg); }
.tx-retry { border-left: 3px solid var(--warn); }
.tx-gutter { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 10px; color: var(--text-dim); text-align: right; line-height: 1.6; }
.tx-turn { display: block; color: var(--text-dim); }
.tx-phasetag { display: block; font-weight: 700; font-size: 10px; }
.tx-body { min-width: 0; }
.tx-head { font-size: 11px; margin-bottom: 4px; }
.tx-head .tx-role { font-weight: 600; color: var(--text-bright); }
.tx-head .tx-meta { color: var(--text-dim); font-family: 'SF Mono', Menlo, Consolas, monospace; margin-left: 6px; }
.tx-text { white-space: pre-wrap; line-height: 1.5; color: var(--text); margin: 2px 0; }
.tx-call > summary { color: var(--code); font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 12px; }
.tx-noresults { padding: 16px; text-align: center; }

/* ----- Leads & queries table ----- */
.lq-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.lq-table th { text-align: left; text-transform: uppercase; font-size: 9px; letter-spacing: 0.6px; color: var(--text-dim); padding: 6px 8px; border-bottom: 1px solid var(--border); }
.lq-table td { padding: 6px 8px; border-bottom: 1px solid var(--border-2); vertical-align: top; }
.lq-lead { background: var(--bg-3); border-right: 1px solid var(--border-2); }
.lq-leadid { font-family: 'SF Mono', Menlo, Consolas, monospace; color: var(--code); font-weight: 600; }
.lq-goal { color: var(--text-dim); font-size: 11px; margin-top: 2px; max-width: 220px; }
.lq-qid, .lq-sys, .lq-params, .lq-payload { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px; }
.lq-qid { color: var(--code); }
.lq-params { color: var(--text-dim); max-width: 260px; overflow-wrap: anywhere; }
.lq-exit { text-align: center; font-weight: 600; }
.lq-exit.lq-ok { color: var(--good); }
.lq-exit.lq-bad { color: var(--bad); }
.lq-payload { color: var(--text-dim); }
.lq-deadend .lq-empty { color: var(--warn); font-style: italic; }

/* ----- Sticky sidebar: phase nav ----- */
nav.toc .toc-hint { text-transform: none; font-weight: 400; font-style: italic; opacity: 0.8; }
nav.toc li.phase-nav a { display: flex; align-items: baseline; gap: 8px; }
nav.toc li.phase-nav .pn-tag { font-family: 'SF Mono', Menlo, Consolas, monospace; font-weight: 700; font-size: 10px; flex-shrink: 0; min-width: 22px; }
nav.toc li.phase-nav a.pn-active { color: var(--text-bright); border-left-color: var(--accent); background: var(--bg-2); }
"""


# ---------------------------------------------------------------------------
# Runtime-page interactivity: transcript search / filter + phase scroll-spy
# ---------------------------------------------------------------------------


RUNTIME_JS = """
(function () {
  var stream = document.querySelector('.tx-stream');
  if (stream) {
    var entries = [].slice.call(stream.querySelectorAll('.tx-entry'));
    var search = document.querySelector('.tx-search');
    var typeSel = document.querySelector('.tx-type');
    var errToggle = document.querySelector('.tx-errors');
    var chips = [].slice.call(document.querySelectorAll('.tx-chip'));
    var clearBtn = document.querySelector('.tx-clear');
    var noRes = document.querySelector('.tx-noresults');
    var activeTool = null;
    function apply() {
      var q = (search && search.value || '').toLowerCase().trim();
      var ty = typeSel ? typeSel.value : '';
      var errOnly = errToggle ? errToggle.checked : false;
      var shown = 0;
      entries.forEach(function (el) {
        var ok = true;
        if (ty && el.dataset.kind !== ty) ok = false;
        if (ok && errOnly && el.dataset.kind !== 'retry') ok = false;
        if (ok && activeTool) {
          var t = el.dataset.tool, ts = (el.dataset.tools || '').split(' ');
          if (t !== activeTool && ts.indexOf(activeTool) < 0) ok = false;
        }
        if (ok && q && el.textContent.toLowerCase().indexOf(q) < 0) ok = false;
        el.hidden = !ok;
        if (ok) shown++;
      });
      if (noRes) noRes.hidden = shown > 0;
    }
    if (search) search.addEventListener('input', apply);
    if (typeSel) typeSel.addEventListener('change', apply);
    if (errToggle) errToggle.addEventListener('change', apply);
    chips.forEach(function (c) {
      c.addEventListener('click', function () {
        var t = c.dataset.tool;
        if (activeTool === t) { activeTool = null; c.classList.remove('chip-active'); }
        else { activeTool = t; chips.forEach(function (x) { x.classList.toggle('chip-active', x === c); }); }
        apply();
      });
    });
    if (clearBtn) clearBtn.addEventListener('click', function () {
      if (search) search.value = '';
      if (typeSel) typeSel.value = '';
      if (errToggle) errToggle.checked = false;
      activeTool = null;
      chips.forEach(function (x) { x.classList.remove('chip-active'); });
      apply();
    });
    // Phase scroll-spy: highlight the sidebar link of the phase in view.
    var navLinks = [].slice.call(document.querySelectorAll('.phase-nav a'));
    var byPhase = {};
    navLinks.forEach(function (a) { byPhase[a.getAttribute('data-phase-link')] = a; });
    var markers = entries.filter(function (e) { return e.id && e.id.indexOf('tx-') === 0; });
    if ('IntersectionObserver' in window && markers.length) {
      var obs = new IntersectionObserver(function (es) {
        es.forEach(function (en) {
          if (en.isIntersecting) {
            var a = byPhase[en.target.dataset.phase];
            if (a) { navLinks.forEach(function (x) { x.classList.remove('pn-active'); }); a.classList.add('pn-active'); }
          }
        });
      }, { rootMargin: '-90px 0px -70% 0px' });
      markers.forEach(function (m) { obs.observe(m); });
    }
  }
})();
"""


# ---------------------------------------------------------------------------
# Page composition + CLI entry
# ---------------------------------------------------------------------------


def _stats(events: list[dict]) -> tuple[int, int, float]:
    n_events = len(events)
    cost = sum(e.get("total_cost_usd") or 0 for e in events if e.get("type") == "result")
    n_tool_calls = sum(
        1
        for e in events
        if e.get("type") == "assistant"
        for blk in (e.get("message") or {}).get("content", [])
        if isinstance(blk, dict) and blk.get("type") == "tool_use"
    )
    return n_events, n_tool_calls, cost


def render_judge_page(run_dir: Path) -> str:
    case_id = run_dir.name
    events = load_jsonl(run_dir / "tool_trace.jsonl")
    n_events, n_tool_calls, cost = _stats(events)
    judge = load_judge_findings(case_id)
    n_findings = len((judge or {}).get("defender_findings") or []) if judge else 0
    judge_benign = load_judge_benign_findings(case_id)
    n_benign_findings = (
        len(judge_benign.get("defender_findings") or []) if judge_benign else None
    )

    byline = _byline([
        f"events={n_events}",
        f"tool_calls={n_tool_calls}",
        f"cost=${cost:.4f}",
        f"run_dir={esc(str(run_dir))}",
    ])

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>judge eval — {esc(case_id)}</title>
<style>{CSS}</style></head><body id="top">
{render_header(case_id, active="judge", byline=byline)}
{render_judge_headline(run_dir, judge, judge_benign)}
<div class="layout">
  {render_judge_toc(n_findings, n_benign_findings)}
  <article class="content">
    {render_alert_block(run_dir, open_=True)}
    {render_judge_defender_summary(run_dir)}
    {render_judge_actor_section(case_id)}
    {render_judge_judge_section(judge)}
    {render_judge_oracle_section(case_id)}
    {render_judge_actor_benign_section(case_id)}
    {render_judge_benign_section(judge_benign)}
    {render_judge_oracle_benign_section(case_id)}
    {render_judge_raw_bundle(case_id)}
  </article>
</div>
</body></html>
"""


def render_runtime_page(run_dir: Path) -> str:
    case_id = run_dir.name
    events = load_jsonl(run_dir / "tool_trace.jsonl")
    messages = load_messages(run_dir)
    # _stats' n_events / cost are unused on this page; only the tool-call count
    # and the result-event cost total (== _stats' cost) are. Read the lead/query
    # join + report once here and thread them into the consumers below.
    _, n_tool_calls, result_total = _stats(events)
    report = parse_report(run_dir)
    leads = lead_repository.joined(run_dir)

    # Drop "preamble" from the attribution order — agent work before the first
    # ## header is functionally ORIENT-bucket work. The phase still renders.
    raw_phases = normalize_phase_names(split_investigation_phases(run_dir))
    phase_order = [p["name"] for p in raw_phases if p["name"] != "preamble"]
    tags = tag_events_by_phase(events, phase_order)

    # Per-phase cost: accurate per-message main cost (tagger fixed) + the nested
    # gather (Haiku) cost folded back in from the message log at its dispatch phase.
    attribution = phase_attribution(events, phase_order, tags)
    main_total = sum(b["cost"] for b in attribution.values())
    gather_by_phase, gather_total = gather_cost_by_phase(
        run_dir, events, tags, phase_order, main_total, result_total, messages
    )
    for ph in phase_order:
        attribution[ph]["gather_cost"] = gather_by_phase.get(ph, 0.0)
        attribution[ph]["cost"] += gather_by_phase.get(ph, 0.0)
    wall_times = phase_wall_times(events, tags, phase_order)

    msg_phase = msg_phase_map(events, tags)
    entries = build_transcript(messages, msg_phase, phase_order)
    tools = tool_usage(events, messages)
    health = run_health(run_dir, events, messages, phase_order, leads=leads, report=report)
    md = run_metadata(run_dir, events, messages)

    wall_ms = sum(e.get("duration_ms") or 0 for e in events if e.get("type") == "result")
    main_model = md["models"][0] if md["models"] else "main"
    by_model = {main_model: main_total}
    if gather_total > 0:
        by_model["haiku"] = gather_total
    # Headline total = main + gather, which by gather_cost_by_phase's contract
    # always equals the sum of the per-phase cost bars. With no phases there are
    # no bars to reconcile against, so fall back to the run's reported total
    # rather than the 0 an empty attribution would yield.
    totals = {
        "cost": (main_total + gather_total) if phase_order else result_total,
        "wall_ms": wall_ms,
        "by_model": by_model,
        "tool_calls": n_tool_calls,
    }

    investigation_html, phases = render_runtime_investigation(
        run_dir, attribution, wall_times, raw_phases
    )
    transcript_html, n_tx, tx_phases = render_runtime_transcript(entries, tools, phases)
    leads_html, n_leads = render_runtime_leads_queries(run_dir, leads)

    byline_parts = []
    if md["started"]:
        byline_parts.append(f'started {esc(md["started"][:19].replace("T", " "))}')
    if md["models"]:
        byline_parts.append(f'models {esc(", ".join(md["models"]))}')
    byline_parts.append(f'run_dir {esc(md["run_dir"])}')
    byline = _byline(byline_parts)

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>runtime — {esc(case_id)}</title>
<style>{CSS}</style></head><body id="top">
{render_header(case_id, active="runtime", byline=byline)}
{render_runtime_headline(run_dir, report, health, attribution, phase_order, wall_times, totals, leads)}
<div class="layout">
  {render_runtime_toc(phases, n_tx, n_leads, tx_phases)}
  <article class="content">
    {render_alert_block(run_dir, open_=False)}
    {investigation_html}
    {transcript_html}
    {leads_html}
  </article>
</div>
{render_footer(run_dir, case_id)}
<script>{RUNTIME_JS}</script>
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
    mirrored = render_and_mirror(run_dir)
    print(f"wrote {run_dir / JUDGE_FILENAME}")
    print(f"wrote {run_dir / RUNTIME_FILENAME}")
    for dest in mirrored:
        print(f"mirrored {dest.relative_to(_REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
