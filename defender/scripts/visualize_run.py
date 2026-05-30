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
        Optimized for inspecting the runtime agent: investigation.md is
        split per ``## PHASE`` header with cost/wall/tool-count stats,
        each phase has a collapsible inner-events expander, gather
        subagents pair with their gather_raw/ payloads, raw stream-json
        events sit collapsed at the bottom.

The two pages cross-link via a header tab strip and share their CSS.

Module layout (all in defender/scripts/, sibling imports thanks to
Python prepending the script's directory to sys.path):

    visualize_run.py        — this file: CLI, CSS, page composition,
                              header / headline / timing-cost block
    visualize_primitives.py — esc / block / pre helpers, load_*,
                              raw event renderers, shared content
                              fragments (alert, lead list, report card)
    visualize_data.py       — pricing, cost attribution, phase tagging,
                              wall times, merge helpers
    visualize_judge.py      — judge view sections + TOC
    visualize_runtime.py    — runtime view sections + TOC + footer

Usage:
    python3 defender/scripts/visualize_run.py <run_dir>
"""
from __future__ import annotations

import sys
from pathlib import Path

from visualize_data import (
    normalize_phase_names,
    phase_attribution,
    phase_color,
    phase_verb,
    phase_wall_times,
    scale_costs_to_reported,
    split_investigation_phases,
    tag_events_by_phase,
)
from visualize_judge import (
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
from visualize_primitives import (
    esc,
    fmt_duration,
    load_jsonl,
    load_judge_benign_findings,
    load_judge_findings,
    parse_report,
    render_alert_block,
)
from visualize_runtime import (
    render_footer,
    render_phase_inner_events,
    render_runtime_gather,
    render_runtime_investigation,
    render_runtime_lead_sequence,
    render_runtime_raw,
    render_runtime_report,
    render_runtime_toc,
)


JUDGE_FILENAME = "transcript.html"
RUNTIME_FILENAME = "runtime.html"


# ---------------------------------------------------------------------------
# Header + tabs (shared across views)
# ---------------------------------------------------------------------------


def render_header(case_id: str, n_events: int, n_tool_calls: int, cost: float, run_dir: Path, active: str) -> str:
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
  <div class="meta">events={n_events} · tool_calls={n_tool_calls} · cost=${cost:.4f} · run_dir={esc(str(run_dir))}</div>
</header>
"""


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


def render_runtime_headline(
    run_dir: Path,
    events: list[dict],
    attribution: dict[str, dict],
    phase_order: list[str],
    wall_times: dict[str, dict] | None = None,
) -> str:
    report = parse_report(run_dir)
    disposition = str(report.get("disposition", "?"))
    confidence = str(report.get("confidence", "?"))
    body = report.get("body", "").strip() or "(no report body)"
    return f"""
<section class="headline">
  <div class="headline-grid">
    <div class="tile tile-disp disp-{esc(disposition)}">
      <div class="tile-label">defender disposition</div>
      <div class="tile-value">{esc(disposition)}</div>
      <div class="tile-sub">confidence: {esc(confidence)}</div>
    </div>
    <div class="headline-body">
      <div class="hb-label">report.md</div>
      <div class="hb-text">{esc(body)}</div>
    </div>
  </div>
  {render_timing_cost_block(events, attribution, phase_order, wall_times)}
</section>
"""


# ---------------------------------------------------------------------------
# Top-of-page timing/cost block: summary + segmented cost & wall bars +
# methodology disclosure
# ---------------------------------------------------------------------------


def render_timing_cost_block(
    events: list[dict],
    attribution: dict[str, dict],
    phase_order: list[str],
    wall_times: dict[str, dict] | None = None,
) -> str:
    result_evs = [e for e in events if e.get("type") == "result"]
    duration_ms = sum(e.get("duration_ms") or 0 for e in result_evs)
    duration_api_ms = sum(e.get("duration_api_ms") or 0 for e in result_evs)
    total_cost_reported = sum(e.get("total_cost_usd") or 0 for e in result_evs)

    # Model-level usage from result events (main + subagents).
    sonnet_cost = 0.0
    haiku_cost = 0.0
    for ev in result_evs:
        mu = ev.get("modelUsage") or {}
        for k, v in mu.items():
            if not isinstance(v, dict):
                continue
            c = v.get("costUSD") or 0
            if "haiku" in k.lower():
                haiku_cost += c
            else:
                sonnet_cost += c

    # Per-phase cost summed from attribution (main agent + subagents
    # mapped via parent_tool_use_id). Used as the segment-bar denominator;
    # the bucket totals have already been rescaled to the reported total.
    attr_total = sum(b["cost"] for b in attribution.values())
    bar_total = attr_total if attr_total > 0 else (total_cost_reported or 0.001)

    segs: list[str] = []
    for ph in phase_order:
        b = attribution.get(ph)
        if not b or b["cost"] <= 0:
            continue
        pct = (b["cost"] / bar_total) * 100
        verb = phase_verb(ph)
        color = phase_color(verb)
        title = f"{ph} · ${b['cost']:.4f} · {pct:.1f}%"
        segs.append(
            f'<div class="cb-seg" style="width:{pct:.4f}%;background:{color}" '
            f'title="{esc(title)}"><span class="cb-label">{esc(verb)}</span>'
            f'<span class="cb-pct">${b["cost"]:.3f}</span></div>'
        )
    bar_html = "".join(segs) or '<div class="empty">(no per-phase cost attribution)</div>'

    # Wall-time bar: same phase order, widths proportional to seconds spent.
    wall_total = sum((w or {}).get("duration_sec", 0) for w in (wall_times or {}).values())
    wall_segs: list[str] = []
    if wall_total > 0:
        for ph in phase_order:
            w = (wall_times or {}).get(ph) or {}
            dur = w.get("duration_sec", 0)
            if dur <= 0:
                continue
            pct = (dur / wall_total) * 100
            verb = phase_verb(ph)
            color = phase_color(verb)
            title = f"{ph} · {fmt_duration(dur * 1000)} · {pct:.1f}%"
            wall_segs.append(
                f'<div class="cb-seg" style="width:{pct:.4f}%;background:{color}" '
                f'title="{esc(title)}"><span class="cb-label">{esc(verb)}</span>'
                f'<span class="cb-pct">{fmt_duration(dur * 1000)}</span></div>'
            )
    wall_bar_html = "".join(wall_segs) or '<div class="empty">(no per-phase wall-time attribution — tool_trace.jsonl has no user-event timestamps)</div>'

    summary = (
        f'<span class="tc-key">total cost</span> <span class="tc-val">${total_cost_reported:.4f}</span>'
        f'<span class="tc-sep">·</span>'
        f'<span class="tc-key">wall</span> <span class="tc-val">{fmt_duration(duration_ms)}</span>'
        f'<span class="tc-sep">·</span>'
        f'<span class="tc-key">api</span> <span class="tc-val">{fmt_duration(duration_api_ms)}</span>'
        f'<span class="tc-sep">·</span>'
        f'<span class="tc-key">sonnet</span> <span class="tc-val">${sonnet_cost:.4f}</span>'
        f'<span class="tc-sep">·</span>'
        f'<span class="tc-key">haiku</span> <span class="tc-val">${haiku_cost:.4f}</span>'
    )
    return f"""
<div class="timing-cost">
  <div class="tc-summary">{summary}</div>
  <div class="tc-bar-row">
    <div class="tc-bar-label">cost</div>
    <div class="cost-bar">{bar_html}</div>
  </div>
  <div class="tc-bar-row">
    <div class="tc-bar-label">wall</div>
    <div class="cost-bar">{wall_bar_html}</div>
  </div>
  <details class="tc-help">
    <summary>methodology</summary>
    <div class="tc-help-body">
      <p><strong>Scope.</strong> Totals describe the defender's <code>claude -p</code> session only — from the first tool_result (alert read) to the final assistant message. The learning loop runs in a separate process after the agent exits and is not reflected here. Wall time includes gather subagent calls (they share the agent's session) plus local tool / hook execution time, so it exceeds the API total.</p>
      <p><strong>Cost.</strong> Per-message cost = <code>input·$3 + output·$15 + cache_creation·$3.75 + cache_read·$0.30</code> per Mtok (sonnet-4-6 rates; haiku-4-5 = $1/$5/$1.25/$0.10). Main-agent messages are bucketed by the phase active when they were emitted (the cursor advances on <code>Write</code>/<code>Edit</code> writes to <code>investigation.md</code> that introduce a new <code>## PHASE</code> header with substantive body). Subagent messages are bucketed by the phase that issued their parent <code>Task</code>. Stream-json under-reports per-message <code>output_tokens</code>, so per-phase totals are rescaled to match the <code>result</code> event's <code>total_cost_usd</code>.</p>
      <p><strong>Wall time.</strong> Per-phase boundaries are drawn from timestamps on <code>user</code> events (tool_results) in <code>tool_trace.jsonl</code>. A phase ends at the first tool_result tagged to the next phase; if a phase had no tool_results, its slice is zero.</p>
    </div>
  </details>
</div>
"""


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

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>judge eval — {esc(case_id)}</title>
<style>{CSS}</style></head><body id="top">
{render_header(case_id, n_events, n_tool_calls, cost, run_dir, active="judge")}
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
    n_events, n_tool_calls, cost = _stats(events)
    raw_phases = normalize_phase_names(split_investigation_phases(run_dir))
    # Drop "preamble" from the attribution order — agent work before the
    # first ## header is functionally ORIENT-bucket work. The phase
    # itself still renders (as a header-less section) but doesn't get
    # cost/wall stats.
    phase_order = [p["name"] for p in raw_phases if p["name"] != "preamble"]
    attribution = phase_attribution(events, phase_order)
    scale_costs_to_reported(events, attribution, {})
    tags = tag_events_by_phase(events, phase_order)
    wall_times = phase_wall_times(events, tags, phase_order)
    inner_events_by_phase = {
        ph: render_phase_inner_events(events, tags, ph) for ph in phase_order
    }
    investigation_html, phases = render_runtime_investigation(
        run_dir, attribution, wall_times, inner_events_by_phase
    )
    gather_html, n_gather = render_runtime_gather(run_dir, events)

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>runtime — {esc(case_id)}</title>
<style>{CSS}</style></head><body id="top">
{render_header(case_id, n_events, n_tool_calls, cost, run_dir, active="runtime")}
{render_runtime_headline(run_dir, events, attribution, phase_order, wall_times)}
<div class="layout">
  {render_runtime_toc(phases, n_gather)}
  <article class="content">
    {render_alert_block(run_dir, open_=False)}
    {investigation_html}
    {gather_html}
    {render_runtime_lead_sequence(run_dir)}
    {render_runtime_report(run_dir)}
    {render_runtime_raw(events)}
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
    judge_out = run_dir / JUDGE_FILENAME
    runtime_out = run_dir / RUNTIME_FILENAME
    judge_out.write_text(render_judge_page(run_dir))
    runtime_out.write_text(render_runtime_page(run_dir))
    print(f"wrote {judge_out}")
    print(f"wrote {runtime_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
