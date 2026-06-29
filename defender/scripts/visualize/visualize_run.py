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

import re
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
    gather_cost_by_model,
    gather_cost_by_phase,
    gather_wall_by_phase,
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


def render_header(case_id: str, active: str, byline: str, stats_html: str = "") -> str:
    judge_active = " active" if active == "judge" else ""
    runtime_active = " active" if active == "runtime" else ""
    stats = f'<div class="top-stats">{stats_html}</div>' if stats_html else ""
    return f"""
<header class="top">
  <div class="top-row">
    <h1>defender run: {esc(case_id)}</h1>
    {stats}
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
    leads: list,
) -> str:
    """The top fold: a single full-width ANALYSIS card (disposition + execution
    health + report + lead summary) that owns the first screen. The run totals
    (cost / wall) sit in the header top bar; the per-phase bars + tool usage live
    in the § Metrics section below the fold (``render_runtime_metrics``)."""
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

    return f"""
<section class="headline headline-runtime">
  <div class="fold fold-single">
    <div class="fold-card card-analysis">
      <div class="an-top">
        <span class="disp-badge disp-{esc(disposition)}">{esc(disposition)}</span>
        <span class="an-conf">confidence: {esc(confidence)}</span>
      </div>
      <div class="an-health">{health_html}</div>
      <div class="an-cols">
        <div class="an-report">{esc(body)}</div>
        <div class="an-leads">{_lead_summary(leads)}</div>
      </div>
    </div>
  </div>
</section>
"""


def render_runtime_metrics(
    attribution: dict[str, dict],
    phase_order: list[str],
    wall_times: dict[str, dict],
    tools: list[dict],
    totals: dict,
    health: dict,
) -> str:
    """§ Metrics — the per-phase cost / wall bars + a tool-usage breakdown. Lives
    below the analysis fold; the headline numbers (total cost / wall) are in the
    header top bar."""
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

    if tools:
        max_n = max((t["count"] for t in tools), default=1) or 1
        rows: list[str] = []
        for t in tools:
            warn = f'<span class="tu-warn">⚠{t["retries"]}</span>' if t.get("retries") else ""
            pct = t["count"] / max_n * 100
            rows.append(
                f'<div class="tu-row"><span class="tu-name">{esc(t["tool"])}</span>'
                f'<span class="tu-track"><span class="tu-fill" style="width:{pct:.1f}%"></span></span>'
                f'<span class="tu-count">{t["count"]}{warn}</span></div>'
            )
        tools_html = f'<div class="tu-list">{"".join(rows)}</div>'
    else:
        tools_html = '<div class="empty">(no tool calls)</div>'

    return f"""
<section id="sec-metrics" class="stage stage-defender">
  <h2>Metrics <span class="stage-sub">— per-phase cost / wall + tool usage</span></h2>
  <div class="me-models">{model_bits}</div>
  <div class="me-bar-row"><span class="me-bar-label">cost</span><div class="cost-bar">{cost_bar}</div></div>
  <div class="me-bar-row"><span class="me-bar-label">wall</span><div class="cost-bar">{wall_bar}</div></div>
  <h3>tool usage</h3>
  {tools_html}
  <div class="me-foot">{esc(foot)}</div>
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
        # Slivers can't hold a label without clipping it to garble ("PLA $0.06" →
        # "LA $0.0"); show text only when the segment is wide enough, and drop the
        # value on the merely-narrow ones. Full detail stays in the hover title.
        if pct >= 9:
            inner = f'<span class="cb-label">{esc(verb[:3])}</span><span class="cb-pct">{esc(fmt(v))}</span>'
        elif pct >= 4.5:
            inner = f'<span class="cb-label">{esc(verb[:3])}</span>'
        else:
            inner = ""
        segs.append(
            f'<div class="cb-seg" style="width:{pct:.4f}%;background:{phase_color(verb)}" '
            f'title="{esc(title)}">{inner}</div>'
        )
    return "".join(segs)


def _lead_sort_key(jl) -> tuple[int, str]:
    """Numeric order over lead ids (``l-002`` before ``l-010``); falls back to the
    raw id when there's no number to parse (e.g. an orphan)."""
    m = re.search(r"\d+", jl.lead_id or "")
    return (int(m.group()) if m else 1 << 30, jl.lead_id or "")


def _lead_summary(leads: list) -> str:
    """The analysis card's compact lead list: id + goal + a ∅ marker for
    dead-ends. The goal is CSS-clamped to one line; clicking it expands the full
    text in place (the truncating ellipsis is the affordance). The full queries
    live in § Leads & queries below."""
    if not leads:
        return '<span class="empty">no leads</span>'
    rows: list[str] = []
    for jl in leads:
        dead = jl.orphan or not jl.queries
        goal = (jl.goal or ("orphan" if jl.orphan else "")).strip()
        mark = ' <span class="lead-dead">∅</span>' if dead else ""
        # Full goal in the DOM; CSS clamps it to one line. The JS marks it `.clip`
        # (and wires click-to-expand) only when it actually overflows.
        goal_html = f'<span class="lead-mini-goal">{esc(goal)}</span>' if goal else ""
        rows.append(
            f'<div class="lead-mini"><span class="lead-mini-id">{esc(jl.lead_id)}</span>'
            f'{goal_html}{mark}</div>'
        )
    return f'<div class="an-sublabel">leads</div><div class="lead-mini-list">{"".join(rows)}</div>'


# ---------------------------------------------------------------------------
# Page assets (#451): CSS shared by both pages + runtime JS (runtime page only).
# Authored under visualize/assets/*.{css,js} so they lint/highlight as real
# assets; read once at import and inlined into <style>/<script>, keeping each
# page self-contained.
# ---------------------------------------------------------------------------

_ASSETS = Path(__file__).resolve().parent / "assets"
CSS = (_ASSETS / "styles.css").read_text()


# ---------------------------------------------------------------------------
# Runtime-page interactivity: transcript search / filter + phase scroll-spy
# ---------------------------------------------------------------------------

RUNTIME_JS = (_ASSETS / "runtime.js").read_text()


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
    # joined() orders leads by execution order (its contract, shared with the
    # actor view); for the inspection page we want them in numeric lead-id order
    # (l-002 before l-010) across both the fold summary and the § Leads table.
    leads = sorted(lead_repository.joined(run_dir), key=_lead_sort_key)

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
    # Move gather's execution wall out of the PLAN window it was dispatched in and
    # into the GATHER bar, mirroring the cost reattribution above (else GATHER
    # renders as a zero-width sliver — the gather work is the bulk of the loop).
    g_wall_to, g_wall_from = gather_wall_by_phase(
        run_dir, events, tags, phase_order, messages
    )
    for ph in phase_order:
        d = wall_times.get(ph) or {"start": None, "end": None, "duration_sec": 0.0}
        base = d.get("duration_sec", 0.0) or 0.0
        moved = min(g_wall_from.get(ph, 0.0), base)
        d["duration_sec"] = base - moved + g_wall_to.get(ph, 0.0)
        wall_times[ph] = d

    msg_phase = msg_phase_map(events, tags)
    entries = build_transcript(messages, msg_phase, phase_order)
    tools = tool_usage(events, messages)
    health = run_health(run_dir, events, messages, phase_order, leads=leads, report=report)
    md = run_metadata(run_dir, events, messages)

    wall_ms = sum(e.get("duration_ms") or 0 for e in events if e.get("type") == "result")
    main_model = md["models"][0] if md["models"] else "main"
    by_model = {main_model: main_total}
    # Fold gather cost in under the model the gather agent actually ran on (read
    # from the log), not a hardcoded name — same-model gather merges into one line.
    for model, cost in gather_cost_by_model(run_dir, messages).items():
        by_model[model] = by_model.get(model, 0.0) + cost
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
    metrics_html = render_runtime_metrics(
        attribution, phase_order, wall_times, tools, totals, health
    )
    transcript_html, n_tx, tx_phases = render_runtime_transcript(entries, tools, phases)
    leads_html, n_leads = render_runtime_leads_queries(run_dir, leads)

    # Run totals now headline the top bar (was the metrics card); the bars moved
    # to § Metrics below the fold.
    stats_html = (
        f'<span class="ts-cost">${totals.get("cost", 0.0):.4f}</span>'
        f'<span class="ts-sep">·</span>'
        f'<span class="ts-wall">{fmt_duration(wall_ms)}</span>'
    )

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
{render_header(case_id, active="runtime", byline=byline, stats_html=stats_html)}
<div class="layout">
  {render_runtime_toc(phases, n_tx, n_leads, tx_phases, leads)}
  <article class="content content-runtime">
    {render_runtime_headline(run_dir, report, health, leads)}
    {metrics_html}
    {render_alert_block(run_dir, open_=False)}
    {investigation_html}
    {leads_html}
    {transcript_html}
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
