#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path
from typing import Any

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._io import read_jsonl_rows
from defender._report import ReportRead
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
    review_cost_by_lens,
    review_cost_by_model,
    run_health,
    run_metadata,
    split_investigation_phases,
    tag_events_by_phase,
    tool_usage,
)
from defender.scripts.visualize.visualize_judge import (
    DirectionView,
    active_views,
    judge_finding_count,
    render_judge_actor_section,
    render_judge_defender_summary,
    render_judge_judge_section,
    render_judge_raw_bundle,
    render_judge_toc,
)
from defender.scripts.visualize.visualize_primitives import (
    esc,
    esc_untrusted,
    fmt_duration,
    load_judge_doc,
    parse_report,
    render_alert_block,
    section,
)
from defender.scripts.visualize.visualize_runtime import (
    close_vocabulary,
    render_footer,
    render_review_gate,
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
    (run_dir / JUDGE_FILENAME).write_text(render_judge_page(run_dir), encoding="utf-8")
    (run_dir / RUNTIME_FILENAME).write_text(render_runtime_page(run_dir), encoding="utf-8")
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
    return '<span class="bl-sep">·</span>'.join(
        f'<span class="bl-item">{p}</span>' for p in parts if p
    )




def render_judge_headline(
    report: ReportRead, docs: list[tuple[DirectionView, dict | None]],
) -> str:
    disposition = report.disposition_or_unknown
    confidence = str(report.frontmatter.get("confidence", "?"))
    # First rendered direction that produced a doc supplies the outcome tile — the page
    # order, so adversarial still wins when both ran. The tile names its direction either
    # way; it used to say so for the benign direction only.
    graded = next(((v, d) for v, d in docs if d), None)
    if graded is not None:
        view, doc = graded
        outcome = str(doc.get("outcome", "—"))
        n_findings = judge_finding_count(doc)
        direction_sub = f"{n_findings} finding(s) · {view.direction.name} direction"
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


def _gate_badge_html(report: ReportRead) -> str:
    """The review gate's outcome, beside the disposition it produced.

    Read from report.md's own frontmatter — the gate WRITES `outcome`/`cause`/`failure_kind`
    there — rather than re-derived from the review records, so the headline cannot disagree
    with the file the learning loop and the judge both read. A `forced-inconclusive` says the
    headline disposition is the gate's and not the investigator's, which is the one thing a
    reader skimming this card would otherwise get wrong; § Review gate carries the rest.

    THE OUTCOME ALONE IS NOT THE BADGE. The gate's BYPASS arm writes `outcome: stands` too —
    `stands` is the close tool's word for "committed unchanged", not for "a review agreed" —
    so keying only on it painted a green "the review held" badge on every `inconclusive`
    close, contradicting § Review gate below, which reads the records and says "not reviewed".
    The CAUSE is what tells the two apart, and it is read from its owner rather than spelled
    here — see `visualize_runtime.close_vocabulary`.
    """
    outcome = str(report.frontmatter.get("outcome", "") or "")
    if not outcome:
        return ""
    vocab = close_vocabulary()
    kind = report.frontmatter.get("failure_kind")
    if kind:
        cls, label = "gate-fault", f"gate: {outcome} ({kind})"
    elif str(report.frontmatter.get("cause", "") or "") == vocab.not_reviewed_cause:
        cls, label = "gate-skip", "gate: not reviewed"
    else:
        cls = {vocab.stands: "gate-stands", vocab.forced: "gate-forced"}.get(outcome, "gate-other")
        label = f"gate: {outcome}"
    return f'<a class="gate-badge {cls}" href="#sec-review">{esc(label)}</a>'


def render_runtime_headline(
    run_dir: Path,
    report: ReportRead,
    health: dict,
    leads: list,
) -> str:
    disposition = report.disposition_or_unknown
    # `close_tool.render_report` renders the frontmatter from typed arguments and does NOT
    # write `confidence` — only pre-close-tool runs carry the key. Defaulting it to "?" put a
    # permanently-empty `confidence: ?` on every current run, beside the gate badge that
    # actually says something.
    confidence = report.frontmatter.get("confidence")
    conf_html = (
        f'<span class="an-conf">confidence: {esc(str(confidence))}</span>' if confidence else ""
    )
    body = report.body.strip() or "(no report body)"

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
        {conf_html}
        {_gate_badge_html(report)}
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

    body = f"""<div class="me-models">{model_bits}</div>
  <div class="me-bar-row"><span class="me-bar-label">cost</span><div class="cost-bar">{cost_bar}</div></div>
  <div class="me-bar-row"><span class="me-bar-label">wall</span><div class="cost-bar">{wall_bar}</div></div>
  <h3>tool usage</h3>
  {tools_html}
  <div class="me-foot">{esc(foot)}</div>"""
    return section("sec-metrics", "defender", "Metrics", "— per-phase cost / wall + tool usage", body)




def _phase_bar(values: dict[str, float], phase_order: list[str], fmt) -> str:
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
    m = re.search(r"\d+", jl.lead_id or "")
    return (int(m.group()) if m else 1 << 30, jl.lead_id or "")


def _lead_summary(leads: list) -> str:
    if not leads:
        return '<span class="empty">no leads</span>'
    rows: list[str] = []
    for jl in leads:
        dead = jl.orphan or not jl.queries
        goal = (jl.goal or ("orphan" if jl.orphan else "")).strip()
        mark = ' <span class="lead-dead">∅</span>' if dead else ""
        goal_html = f'<span class="lead-mini-goal">{esc(goal)}</span>' if goal else ""
        rows.append(
            f'<div class="lead-mini"><span class="lead-mini-id">{esc(jl.lead_id)}</span>'
            f'{goal_html}{mark}</div>'
        )
    return f'<div class="an-sublabel">leads</div><div class="lead-mini-list">{"".join(rows)}</div>'



_ASSETS = Path(__file__).resolve().parent / "assets"
CSS = (_ASSETS / "styles.css").read_text(encoding="utf-8")



RUNTIME_JS = (_ASSETS / "runtime.js").read_text(encoding="utf-8")




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


def _main_session_analysis(run_dir: Path) -> list[tuple[Any, str]]:
    """The store's own `analysis`-role read of this run's MAIN session, paired with each
    row's `actor`-role coordinate — resolved fresh from just `run_dir` (R4: the render
    path opens the store itself, it does not trust a stale on-disk projection), so a run
    dir whose store cannot be resolved fails this call rather than rendering
    silently-stale or empty pages."""
    from defender.runtime import session_store as ss

    store_path = ss.resolve_store_path(run_dir)
    store = ss.open_store_for_read(store_path)
    try:
        # The ROOT-OF-LINEAGE main session (FK-F) — `session_store.main_session_id` owns
        # the schema knowledge (`agent_id`/`parent_session_id`) this used to duplicate here
        # as inline SQL, alongside this same PR's other lineage readers (`branch_point`,
        # `displaced_tip`, `fold_history`).
        session_id = ss.main_session_id(store)
        messages = ss.hydrate(store, session_id, role="analysis")
        coords = ss.hydrate(store, session_id, role="actor")
        return list(zip(messages, [c["coord"] for c in coords], strict=True))
    finally:
        store.connection.close()


def render_store_transcript_section(run_dir: Path) -> str:
    """Model-authored text is attacker-influenced by construction (`session_store`'s own
    access table), so it is rendered through `esc_untrusted`, not `esc` — see that
    function's docstring."""
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart

    blocks: list[str] = []
    for message, coord in _main_session_analysis(run_dir):
        if not isinstance(message, ModelResponse):
            continue
        body: list[str] = []
        for part in message.parts:
            if isinstance(part, TextPart) and part.content.strip():
                body.append(f'<pre class="text">{esc_untrusted(part.content)}</pre>')
            elif isinstance(part, ToolCallPart):
                body.append(f'<div class="tx-call">→ {esc(part.tool_name)}</div>')
        if body:
            blocks.append(f'<div class="tx-entry" data-coord="{esc(coord)}">'
                          f'{"".join(body)}</div>')
    section_body = "".join(blocks) if blocks else '<div class="empty">no model transcript</div>'
    return section("sec-store-transcript", "defender", "Model transcript",
                    "— a preview of each response the store recorded for this run",
                    section_body)


def render_judge_page(run_dir: Path) -> str:
    case_id = run_dir.name
    events = read_jsonl_rows(run_dir / "tool_trace.jsonl")
    n_events, n_tool_calls, cost = _stats(events)

    # One pass over the directions this run selected or left artifacts for — the page no
    # longer enumerates them, so a third `Direction` lands here for free (#716).
    report = parse_report(run_dir)
    docs = [
        (v, load_judge_doc(case_id, v.direction))
        for v in active_views(case_id, report.disposition_or_unknown)
    ]
    toc_sections = [(v, judge_finding_count(d) if d else None) for v, d in docs]
    # Rendered once and handed to both the TOC and the page body: the bundle is empty when the
    # run left no raw artifacts, and the TOC linked it regardless (#748).
    raw_bundle = render_judge_raw_bundle(case_id)

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
{render_judge_headline(report, docs)}
<div class="layout">
  {render_judge_toc(toc_sections, raw_bundle=bool(raw_bundle))}
  <article class="content">
    {render_alert_block(run_dir, open_=True)}
    {render_judge_defender_summary(run_dir)}
    {"".join(
        render_judge_actor_section(case_id, v)
        + render_judge_judge_section(d, v)
        for v, d in docs
    )}
    {raw_bundle}
    {render_store_transcript_section(run_dir)}
  </article>
</div>
</body></html>
"""


def _render_policy_denials_section(run_dir: Path) -> str:
    """A denial is durable on disk (`observe.POLICY_DENIALS`) and unrelated to every other
    record kind this page already filters on — folding it into an existing filtered stream is
    exactly how a denial goes silently unrendered (#632, g9/g23). Rendered as its own section
    inside the document element, never a comment, so it survives `_visible_html`-shaped
    scraping as well as a human's eyes."""
    from defender.runtime import observe

    path = run_dir / observe.POLICY_DENIALS
    if not path.is_file():
        return ""
    rows = [r for r in read_jsonl_rows(path) if r.get("event_type") == observe.POLICY_DENIAL_EVENT_TYPE]
    if not rows:
        return ""
    items = "".join(
        f'<li class="denial-row">DENIED <code>{esc(str(r.get("system", "")))}.'
        f'{esc(str(r.get("verb", "")))}</code> — role {esc(str(r.get("role", "")))}, '
        f'{esc(str(r.get("ts", "")))}</li>'
        for r in rows
    )
    return section(
        "sec-policy-denials", "defender", "Policy denials",
        f"— {len(rows)} call(s) refused by the verb grant", f'<ul class="denial-list">{items}</ul>',
    )


def render_runtime_page(run_dir: Path) -> str:
    case_id = run_dir.name
    events = read_jsonl_rows(run_dir / "tool_trace.jsonl")
    messages = load_messages(run_dir)
    _, n_tool_calls, result_total = _stats(events)
    report = parse_report(run_dir)
    leads = sorted(lead_repository.joined(run_dir), key=_lead_sort_key)

    raw_phases = normalize_phase_names(split_investigation_phases(run_dir))
    phase_order = [p["name"] for p in raw_phases if p["name"] != "preamble"]
    tags = tag_events_by_phase(events, phase_order)

    attribution = phase_attribution(events, phase_order, tags)
    main_total = sum(b["cost"] for b in attribution.values())
    gather_by_phase, gather_total = gather_cost_by_phase(
        run_dir, events, tags, phase_order, main_total, result_total, messages
    )
    for ph in phase_order:
        attribution[ph]["gather_cost"] = gather_by_phase.get(ph, 0.0)
        attribution[ph]["cost"] += gather_by_phase.get(ph, 0.0)
    # The review's spend is totalled but deliberately NOT attributed to a phase. The gate is
    # a gate and not a loop phase — the investigator is never "in" it — so a per-phase share
    # would put its cost inside a bar that says where the agent was, which is the one thing
    # that is not true of it (`visualize_runtime.render_review_gate`).
    review_by_lens = review_cost_by_lens(run_dir, messages)
    review_total = sum(review_by_lens.values())
    wall_times = phase_wall_times(events, tags, phase_order)
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
    for by_model_costs in (
        gather_cost_by_model(run_dir, messages), review_cost_by_model(run_dir, messages),
    ):
        for model, cost in by_model_costs.items():
            by_model[model] = by_model.get(model, 0.0) + cost
    # `result_total` is the fallback for a run with no phases to attribute against, and it is
    # the MAIN SESSION's figure (`observe.write_trace` hydrates that session alone). The
    # subagent terms are added to it for the same reason they are added to the attributed
    # sum: they are calls this run made, and this is the run's total.
    totals = {
        "cost": (main_total + gather_total if phase_order else result_total) + review_total,
        "review_cost": review_total,
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
    review_html, n_reviewed = render_review_gate(run_dir, report, review_by_lens)

    # The review rides as a NAMED term inside the total, the way gather does on a phase's own
    # line. Folded silently it would be a number an operator cannot separate from the
    # investigation's; left out of the total it would be the defect #787 reported.
    review_note = (
        f'<span class="ts-review">(incl review ${totals["review_cost"]:.4f})</span>'
        if totals["review_cost"] else ""
    )
    stats_html = (
        f'<span class="ts-cost">${totals.get("cost", 0.0):.4f}</span>'
        f"{review_note}"
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
  {render_runtime_toc(phases, n_tx, n_leads, tx_phases, leads, n_reviewed)}
  <article class="content content-runtime">
    {render_runtime_headline(run_dir, report, health, leads)}
    {_render_policy_denials_section(run_dir)}
    {metrics_html}
    {render_alert_block(run_dir, open_=False)}
    {investigation_html}
    {review_html}
    {leads_html}
    {transcript_html}
    {render_store_transcript_section(run_dir)}
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
