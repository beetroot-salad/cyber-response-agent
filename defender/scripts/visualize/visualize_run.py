#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _env
from defender._io import load_json_artifact, read_guarded, read_jsonl_rows, read_text_utf8
from defender._report import ReportRead
from defender.run_repository import RunPaths
from defender.learning import lead_repository
from defender.scripts.visualize import _mirror_write
from defender.scripts.visualize._page_failed import VisualizeFailed
from defender.scripts.visualize.visualize_data import (
    build_transcript,
    gather_cost_by_model,
    gather_cost_by_phase,
    gather_wall_by_phase,
    load_messages,
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
    transcript_phase_map,
)
from defender.scripts.visualize.visualize_primitives import (
    ASSETS,
    CSS,
    esc,
    fmt_duration,
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


_DEFENDER_DIR = Path(__file__).resolve().parents[2]

#: The override for where run pages are mirrored. Read at call time so a test's `setenv`
#: reaches an already-imported module.
MIRROR_DIR_ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"
MIRROR_DIR_NAME = "run-visualizations"
_MIRROR_WRITER = Path(_mirror_write.__file__).resolve()

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from defender.run_repository import Run

#: What the dev-only copy did: landed, was not attempted (not a `dev` deployment), or failed.
CopyOutcome = Literal["copied", "skipped", "failed"]


class MirrorRootRefused(Exception):
    """Under pytest, the mirror root was about to resolve to a real checkout.

    The conftest sets the override for every test, so reaching the default means a test
    bypassed it and would write into the operator's real folder."""


def mirror_root(start: Path | None = None) -> Path:
    """Where run pages are mirrored: `<main checkout>/run-visualizations/`.

    Order: the `MIRROR_DIR_ENV` override; else the main checkout reached from `start` (by
    default this package's checkout), so a worktree's render lands in the one folder the
    operator opens; else `start` itself. Found by reading `.git` rather than running git, which
    as root in a user-owned repo depends on `safe.directory` and inherited `GIT_DIR`.
    """
    override = os.environ.get(MIRROR_DIR_ENV)
    if override:
        return Path(override)
    if start is None:
        if "PYTEST_CURRENT_TEST" in os.environ:
            raise MirrorRootRefused(
                f"{MIRROR_DIR_ENV} is unset under pytest; refusing the real checkout's "
                f"{MIRROR_DIR_NAME}/")
        start = _DEFENDER_DIR.parent
    return _main_checkout(start) / MIRROR_DIR_NAME


def _main_checkout(start: Path) -> Path:
    """`start`, or the main checkout its `.git` file points back to. A chain that cannot be
    followed, or that lands somewhere without `defender/`, falls back to `start` — loudly,
    since the page then lands where the operator is not looking."""
    dot_git = start / ".git"
    if dot_git.is_dir() or not dot_git.exists():
        return start
    try:
        pointer = read_text_utf8(dot_git).strip()
        if not pointer.startswith("gitdir:"):
            raise ValueError(f"{dot_git} is not a gitdir pointer")
        admin = (start / pointer[len("gitdir:"):].strip()).resolve()
        common = (admin / read_text_utf8(admin / "commondir").strip()).resolve()
        main = common.parent
        if not (main / "defender").is_dir():
            raise ValueError(f"{main} (from {dot_git}) holds no defender/")
    except (OSError, ValueError) as exc:
        _logger.warning("mirroring under %s: %s", start, exc)
        return start
    return main


def _mirror(page: bytes, dest: Path, root: Path) -> None:
    """Write the mirror copy as the owner of the folder holding the mirror root.

    Only root writing into a user's folder drops privileges: the copy then runs as that user,
    so a link they planted cannot take it anywhere they could not write. Otherwise it writes
    in-process."""
    try:
        owner = os.lstat(root.parent)
    except FileNotFoundError:
        owner = None
    if os.geteuid() != 0 or owner is None or owner.st_uid == 0:
        _mirror_write.write_page(dest, page)
        return
    proc = subprocess.run(  # noqa: S603 — fixed argv: this interpreter, the writer module
        [sys.executable, "-I", str(_MIRROR_WRITER), str(dest)],
        input=page, capture_output=True, cwd="/", check=False,
        user=owner.st_uid, group=owner.st_gid, extra_groups=[],
    )
    if proc.returncode != 0:
        raise OSError(
            f"mirror write as uid {owner.st_uid} failed (exit {proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}")


def render_page(run_dir: Path, *, update_ticket: bool = False) -> str:
    """This run's page, generated and returned — nothing is written, and nothing here knows
    where the page goes: the post-run step saves it as the run's record (#1110).
    `update_ticket` is `run.py`'s own `--update-ticket` (#1107 O6), handed through to the page.

    The store resolve is a precondition, not a data dependency: nothing on the page reads the
    session store, but a run dir copied without its store pointer would otherwise render a
    complete-looking page for a run whose record cannot be found. It fails before a page exists.
    """
    from defender.runtime import session_store as ss

    ss.open_store_for_read(ss.resolve_store_path(run_dir)).connection.close()
    return render_runtime_page(run_dir, update_ticket=update_ticket)


def publish_page(run: Run, *, update_ticket: bool = False) -> CopyOutcome:
    """The post-run step: render the run's page, save it as the run's `runtime_html` record
    through `run` — so whatever backend the handle sits on receives it like every other record —
    then hand it to the dev-only copy, and answer what the copy did (#1110).

    A failed render and a refused record save are each `VisualizeFailed`, saying which, with
    the cause chained: the caller's single "no record" signal. The copy never raises.
    """
    try:
        page = render_page(run.run_dir, update_ticket=update_ticket)
    except Exception as e:
        raise VisualizeFailed(f"the page for {run.run_dir} could not be rendered") from e
    record = run.observability.runtime_html
    try:
        record.write(page)
    except Exception as e:
        raise VisualizeFailed(f"the page record {record.path} could not be saved") from e
    _logger.info("saved the run page as %s", record.path)
    return mirror_page(page, run.run_dir.name)


def mirror_page(page: str, run_id: str) -> CopyOutcome:
    """The dev-only copy, whole: whether to copy, where, the write, and what to say about it.

    Copies the page to `<mirror root>/<run_id>/runtime.html`, written as the mirror folder's
    owner (#1084), only on a `dev` deployment (#1110) — the rule lives here, beside the write, so
    no caller can reach the copy without it. Best-effort, and never raises: everything after the
    deployment check sits in one `try`. A skipped copy is logged at INFO; a failed one at
    WARNING, naming the destination when one resolved and the error's reason.
    """
    deployment = _env.deployment()
    if deployment != "dev":
        _logger.info("page not copied: this deployment counts as %r, and only %s=dev copies",
                     deployment, _env.DEPLOYMENT_ENV)
        return "skipped"
    dest: Path | None = None
    try:
        root = mirror_root()
        dest = RunPaths(root / run_id).runtime_html
        _mirror(page.encode("utf-8"), dest, root)
    except Exception as e:
        # The reason alone: an OSError's `str()` repeats the path the message already names.
        reason = e.strerror if isinstance(e, OSError) and e.strerror else str(e)
        where = f" to {dest}" if dest is not None else ""
        _logger.warning("page not copied%s: %s: %s", where, type(e).__name__, reason)
        return "failed"
    _logger.info("page copied to %s", dest)
    return "copied"


def render_header(case_id: str, byline: str, stats_html: str = "") -> str:
    stats = f'<div class="top-stats">{stats_html}</div>' if stats_html else ""
    return f"""
<header class="top">
  <div class="top-row">
    <h1>defender run: {esc(case_id)}</h1>
    {stats}
  </div>
  <div class="byline">{byline}</div>
</header>
"""


def _byline(parts: list[str]) -> str:
    return '<span class="bl-sep">·</span>'.join(
        f'<span class="bl-item">{p}</span>' for p in parts if p
    )




_HEALTH_ICON = {"good": "✓", "warn": "⚠", "bad": "✗"}


def _gate_badge_html(report: ReportRead) -> str:
    """The review gate's outcome, beside the disposition it produced.

    Read from report.md's frontmatter (the gate writes `outcome`/`cause`/`failure_kind` there),
    so the headline agrees with what the learning loop and judge read.

    The outcome alone is not enough: the bypass arm also writes `outcome: stands` ("committed
    unchanged"), so the cause distinguishes a bypass from a review that held.
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
    # `close_tool.render_report` does not write `confidence`, so show it only when present.
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
    # The dict collapses repeated phase names into one bucket, in first-appearance order.
    cost_bar = _phase_bar(
        {ph: (attribution.get(ph) or {}).get("cost", 0.0) for ph in phase_order},
        lambda v: f"${v:.3f}",
    )
    wall_bar = _phase_bar(
        {ph: (wall_times.get(ph) or {}).get("duration_sec", 0.0) for ph in phase_order},
        lambda v: fmt_duration(v * 1000),
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




def _phase_bar(values: dict[str, float], fmt) -> str:
    total = sum(v for v in values.values() if v and v > 0)
    if total <= 0:
        return '<div class="empty">(no per-phase attribution)</div>'
    segs: list[str] = []
    # One segment per bucket (the dict's keys), so widths sum to 100%.
    for ph, v in values.items():
        v = v or 0.0
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
        dead = jl.orphan or not jl.rows  # "reached the table at all"
        goal = (jl.goal or ("orphan" if jl.orphan else "")).strip()
        mark = ' <span class="lead-dead">∅</span>' if dead else ""
        goal_html = f'<span class="lead-mini-goal">{esc(goal)}</span>' if goal else ""
        rows.append(
            f'<div class="lead-mini"><span class="lead-mini-id">{esc(jl.lead_id)}</span>'
            f'{goal_html}{mark}</div>'
        )
    return f'<div class="an-sublabel">leads</div><div class="lead-mini-list">{"".join(rows)}</div>'






RUNTIME_JS = read_text_utf8(ASSETS / "runtime.js")




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


def _render_policy_denials_section(run_dir: Path) -> str:
    """Policy denials in their own section: folding them into another filtered stream is how
    they go unrendered. A real section, not an HTML comment, so scrapers see it too."""
    from defender.runtime import observe

    path = RunPaths(run_dir).policy_denials
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


RECEIPT_UNREADABLE = "receipt unreadable"


def render_ticket_line(run_dir: Path) -> str:
    """The page's one line about the case-ticket write (#1107 O6): the key, status and reason the
    host's record step left in its receipt, or nothing when it left no receipt.

    The receipt is a sidecar beside the run dir (`ticket_writer.receipt_path`), out of the box's
    reach. It is still read defensively: only as a plain regular file (`read_guarded` — a link at
    that name is refused, never followed), decoded by the repo's one bounded loader
    (`load_json_artifact`, so the verdict never depends on stack depth), only if it is a JSON
    object whose fields have the types the writer gives them, and every field that reaches the
    page is escaped. Anything else renders `RECEIPT_UNREADABLE` in the receipt's place. The URL
    is shown as text, never as a link: nothing on the page sends the reader to an address a file
    named. The receipt's producer is the ticket writer's `_write_receipt`; this only reads what it
    wrote."""
    path = RunPaths(run_dir).ticket_write()  # = ticket_writer.receipt_path
    if not path.is_symlink() and not path.exists():
        return ""
    text, _refused = read_guarded(path)
    receipt: object = None
    if text is not None:
        receipt, _why = load_json_artifact(text)
    well_formed = (
        isinstance(receipt, dict)
        and isinstance(receipt.get("key"), str)
        and isinstance(receipt.get("status"), str)
        and isinstance(receipt.get("ok"), bool)
        and (receipt.get("url") is None or isinstance(receipt.get("url"), str))
        and (receipt.get("reason") is None or isinstance(receipt.get("reason"), str))
    )
    if not well_formed or not isinstance(receipt, dict):
        return f'<p class="ticket-line ticket-unreadable">ticket: {esc(RECEIPT_UNREADABLE)}</p>'
    cls = "ticket-ok" if receipt["ok"] else "ticket-error"
    parts = [f'ticket <code>{esc(receipt["key"])}</code>', esc(receipt["status"])]
    if receipt.get("url"):
        parts.append(f'<code>{esc(receipt["url"])}</code>')
    if receipt.get("reason"):
        parts.append(esc(receipt["reason"]))
    return f'<p class="ticket-line {cls}">{" — ".join(parts)}</p>'


def render_runtime_page(run_dir: Path, *, update_ticket: bool = False) -> str:
    """The run's page. `update_ticket` is run.py's own `--update-ticket`, handed in as an argument
    and read from no file in the run dir (the box can write every one of them): only a run that
    was started with it has a ticket line, so a receipt an earlier attempt left, or one the box
    planted, shows nothing on a run that never meant to write a ticket."""
    case_id = run_dir.name
    events = read_jsonl_rows(RunPaths(run_dir).tool_trace)
    messages = load_messages(run_dir)
    _, n_tool_calls, result_total = _stats(events)
    report = parse_report(run_dir)
    leads = sorted(lead_repository.joined(run_dir), key=_lead_sort_key)

    raw_phases = normalize_phase_names(split_investigation_phases(run_dir))
    # Two different lists. `phase_order` is the render order (one entry per `##` header, possibly
    # naming one bucket twice), which the tagger needs whole since it matches occurrences
    # positionally. `phase_keys` is the bucket set every per-phase dict is keyed on.
    phase_order = [p["name"] for p in raw_phases if p["name"] != "preamble"]
    phase_keys = list(dict.fromkeys(phase_order))
    tags = tag_events_by_phase(events, phase_order)

    attribution = phase_attribution(events, phase_order, tags)
    main_total = sum(b["cost"] for b in attribution.values())
    gather_by_phase, gather_total = gather_cost_by_phase(
        run_dir, events, tags, phase_order, main_total, result_total, messages
    )
    # `phase_keys`: iterating `phase_order` would add a repeated bucket's gather cost twice.
    for ph in phase_keys:
        attribution[ph]["gather_cost"] = gather_by_phase.get(ph, 0.0)
        attribution[ph]["cost"] += gather_by_phase.get(ph, 0.0)
    # Review spend is totalled but not attributed to a phase: the investigator is never in the
    # gate.
    review_by_lens = review_cost_by_lens(run_dir, messages)
    review_total = sum(review_by_lens.values())
    wall_times = phase_wall_times(events, tags, phase_order)
    g_wall_to, g_wall_from = gather_wall_by_phase(
        run_dir, events, tags, phase_order, messages
    )
    # Buckets again: a second visit would re-read the entry just written and compound the shift.
    for ph in phase_keys:
        d = wall_times.get(ph) or {"start": None, "end": None, "duration_sec": 0.0}
        base = d.get("duration_sec", 0.0) or 0.0
        moved = min(g_wall_from.get(ph, 0.0), base)
        d["duration_sec"] = base - moved + g_wall_to.get(ph, 0.0)
        wall_times[ph] = d

    # `transcript_phase_map`: the transcript walks wire-log ids, not trace coords.
    entries = build_transcript(
        messages, transcript_phase_map(events, tags, messages), phase_order)
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
    # `result_total` (main session only) is the fallback when there are no phases; subagent
    # and review costs are added either way.
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

    # The review is a named term inside the total, so an operator can separate it.
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
{render_header(case_id, byline=byline, stats_html=stats_html)}
<div class="layout">
  {render_runtime_toc(phases, n_tx, n_leads, tx_phases, leads, n_reviewed)}
  <article class="content content-runtime">
    {render_runtime_headline(run_dir, report, health, leads)}
    {render_ticket_line(run_dir) if update_ticket else ""}
    {_render_policy_denials_section(run_dir)}
    {metrics_html}
    {render_alert_block(run_dir, open_=False)}
    {investigation_html}
    {review_html}
    {leads_html}
    {transcript_html}
  </article>
</div>
{render_footer(run_dir, case_id)}
<script>{RUNTIME_JS}</script>
</body></html>
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    """`--tenant T [--episode ep] <run_id> [--update-ticket]` (#1105 declared change 7, J8):
    the tenant is required, with no default; the run is named by its id, in the tenant's own
    runs or, with `--episode`, as an arm of that episode."""
    p = argparse.ArgumentParser(prog="visualize_run.py", description=__doc__)
    p.add_argument("--tenant", required=True,
                   help="the tenant whose run is re-rendered; required, with no default")
    p.add_argument("--episode", default=None,
                   help="the episode the run is an arm of (its id); absent for a natural run")
    p.add_argument("--update-ticket", action="store_true")
    p.add_argument("run_id", help="the run, by its id")
    return p.parse_args(argv)


def _open_run(ns: argparse.Namespace, tenant: Any) -> Run:
    """The run the request names, opened by id through the request's tenant's repository —
    `runs.open` for a natural run, the episode view's `open` for an arm. Neither follows a link
    at the run's name, and an absent run is `RunAbsent`."""
    from defender.run_repository import RunId

    runs = tenant.runs_repository()
    run_id = RunId.parse(ns.run_id)
    if ns.episode is None:
        return runs.open(run_id)
    with runs.episode(ns.episode) as view:
        return view.open(run_id)


def main(argv: list[str]) -> int:
    """Re-render a finished run of the request's tenant (`--tenant`), opened by id through its
    repository, through the same step `run.py` takes, with every line stamped with the run and
    the REQUEST's tenant (never the tenant a box-writable stamp names). Exits 1 when the run
    cannot be opened, when the record was not saved, or when a `dev` copy failed — refreshing
    that copy is often why an operator re-renders."""
    from defender import _log, _tenant
    from defender._episode_handle import EpisodeRefused
    from defender._paths import process_defender_dir
    from defender.run_repository import RunRefused

    ns = parse_args(argv[1:])
    try:
        tenant = _tenant.accept_tenant(
            _tenant.resolve_data_root(), _tenant.requested_tenant_id(ns.tenant),
            defender_dir=process_defender_dir())
    except _tenant.TenantRefused as refused:
        print(f"this re-render's tenant cannot be used: {refused}", file=sys.stderr)
        return 1
    with _log.run_context(ns.run_id, str(tenant.id), logger=_logger):
        try:
            run = _open_run(ns, tenant)
        except (RunRefused, _tenant.TenantRefused, EpisodeRefused, OSError) as refused:
            _logger.error("the run cannot be opened: %s", refused)
            return 1
        try:
            copy = publish_page(run, update_ticket=ns.update_ticket)
        except VisualizeFailed:
            _logger.error("the re-render failed", exc_info=True)
            return 1
    return 1 if copy == "failed" else 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv))
