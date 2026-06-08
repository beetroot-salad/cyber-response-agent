"""Runtime view sections (runtime.html).

Mirrors the agent's working surface: investigation.md split per ``##
PHASE`` header with cost / wall / tool-count stats, a per-phase
inner-events expander that filters tool_trace.jsonl down to the
events tagged to that phase, gather subagent panels paired with
their gather_raw/ payloads, and the on-disk lead sequence + report
card. Raw stream-json events sit collapsed at the bottom. The footer
lists any concurrent lesson-author commits.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import subprocess
from pathlib import Path

from visualize_data import (
    extract_main_subagents,
    merge_assistant_events,
    normalize_phase_names,
    result_totals,
    split_investigation_phases,
    subagent_cost_by_task,
)
from visualize_primitives import (
    REPO_ROOT,
    block,
    esc,
    fmt_duration,
    pre_text,
    render_event,
    render_lead_sequence_compact,
    render_report_card,
)


# ---------------------------------------------------------------------------
# Investigation phase blocks
# ---------------------------------------------------------------------------


def render_runtime_investigation(
    run_dir: Path,
    attribution: dict[str, dict] | None = None,
    wall_times: dict[str, dict] | None = None,
    inner_events_by_phase: dict[str, str] | None = None,
) -> tuple[str, list[dict]]:
    phases = normalize_phase_names(split_investigation_phases(run_dir))
    if not phases:
        body = '<div class="empty">no investigation.md or empty</div>'
        return (
            f"""
<section id="sec-investigation" class="stage stage-defender">
  <h2>§ Investigation <span class="stage-sub">— investigation.md split by phase</span></h2>
  {body}
</section>
""",
            [],
        )
    blocks: list[str] = []
    for ph in phases:
        stats = (attribution or {}).get(ph["name"])
        wall = (wall_times or {}).get(ph["name"])
        stats_html = _phase_stats_html(stats, wall) if stats else ""
        inner_html = (inner_events_by_phase or {}).get(ph["name"], "")
        body_html = stats_html + f'<pre class="text invlang">{esc(ph["body"])}</pre>' + inner_html
        blocks.append(block("phase", ph["name"], body_html, open_=True, anchor=ph["anchor"]))
    return (
        f"""
<section id="sec-investigation" class="stage stage-defender">
  <h2>§ Investigation <span class="stage-sub">— investigation.md split by phase</span></h2>
  {"".join(blocks)}
</section>
""",
        phases,
    )


def _phase_stats_html(stats: dict, wall: dict | None = None) -> str:
    if not stats:
        return ""
    pieces = [
        f'<span class="ps-cost">${stats["cost"]:.4f}</span>',
    ]
    if wall and wall.get("duration_sec"):
        pieces += [
            '<span class="ps-sep">·</span>',
            f'<span class="ps-wall">{fmt_duration(wall["duration_sec"] * 1000)}</span>',
        ]
    pieces += [
        '<span class="ps-sep">·</span>',
        f'<span>{stats["turns"]} turn(s)</span>',
    ]
    tc = stats.get("tool_counts") or {}
    if tc:
        hist = " ".join(f'{name}×{count}' for name, count in sorted(tc.items(), key=lambda kv: -kv[1]))
        pieces += [
            '<span class="ps-sep">·</span>',
            f'<span class="ps-hist">{esc(hist)}</span>',
        ]
    else:
        pieces += [
            '<span class="ps-sep">·</span>',
            f'<span>{stats["tool_calls"]} tool call(s)</span>',
        ]
    if stats.get("subagent_calls"):
        pieces += [
            '<span class="ps-sep">·</span>',
            f'<span>{stats["subagent_calls"]} subagent(s)</span>',
        ]
    pieces += [
        '<span class="ps-sep">·</span>',
        f'<span class="ps-tok">in {stats["in"]:,} / out {stats["out"]:,}'
        f' / cache_r {stats["cache_r"]:,} / cache_w {stats["cache_w"]:,}</span>',
    ]
    return f'<div class="phase-stats">{"".join(pieces)}</div>'


def render_phase_inner_events(
    events: list[dict],
    tags: list[str | None],
    phase: str,
) -> str:
    """Collapsible per-phase event log: assistant turns + tool_results tagged to this phase.

    Assistant events are merged across stream-json deltas so a turn
    that issued three parallel ``Task`` calls renders as a single block
    containing all three. User events (tool_results) interleave in
    chronological order.

    A merged assistant message is bucketed by the *post-advance* phase
    of the message (the last per-event tag for its id), so a turn that
    writes "## ORIENT" lands in ORIENT rather than the prior phase.
    """
    msg_phase: dict[str, str] = {}
    for ev, ph in zip(events, tags):
        if ev.get("type") != "assistant" or ph is None:
            continue
        mid = ((ev.get("message") or {}).get("id")) or ev.get("uuid")
        if mid:
            msg_phase[mid] = ph

    merged_all = merge_assistant_events(events)
    merged_in_phase = {
        ((m.get("message") or {}).get("id") or m.get("uuid")): m
        for m in merged_all
        if msg_phase.get(((m.get("message") or {}).get("id") or m.get("uuid"))) == phase
    }
    if not merged_in_phase and not any(
        ev.get("type") == "user" and ph == phase for ev, ph in zip(events, tags)
    ):
        return ""

    out: list[dict] = []
    emitted: set[str] = set()
    for ev, ph in zip(events, tags):
        if ph != phase:
            continue
        t = ev.get("type")
        if t == "assistant":
            mid = ((ev.get("message") or {}).get("id")) or ev.get("uuid")
            if mid in emitted or mid not in merged_in_phase:
                continue
            out.append(merged_in_phase[mid])
            emitted.add(mid)
        elif t == "user":
            out.append(ev)

    if not out:
        return ""
    rendered = "\n".join(render_event(e) for e in out)
    return block(
        "phase-events",
        f"raw events ({len(out)} in this phase) — assistant turns + tool_results",
        rendered,
    )


# ---------------------------------------------------------------------------
# Gather subagent panel
# ---------------------------------------------------------------------------


def render_runtime_gather(run_dir: Path, events: list[dict]) -> tuple[str, int]:
    calls = extract_main_subagents(events)
    gather_dir = run_dir / "gather_raw"
    if not calls:
        body = '<div class="empty">(no Task/Agent calls)</div>'
        return (
            f"""
<section id="sec-gather" class="stage stage-defender">
  <h2>§ Gather subagents <span class="stage-sub">— prompt → query → raw payload</span></h2>
  {body}
</section>
""",
            0,
        )
    costs = subagent_cost_by_task(events)
    # Rescale per-call costs to match the reported haiku total (the
    # stream-json output-token undercount affects subagent traces too).
    haiku_reported = result_totals(events)["haiku"]
    sub_total = sum(costs.values())
    if sub_total > 0 and haiku_reported > 0:
        scale = haiku_reported / sub_total
        for k in list(costs.keys()):
            costs[k] *= scale
    blocks = [
        _render_gather_call(i, call, gather_dir, costs.get(call.get("id", ""), 0.0))
        for i, call in enumerate(calls)
    ]
    return (
        f"""
<section id="sec-gather" class="stage stage-defender">
  <h2>§ Gather subagents · {len(calls)} call(s) <span class="stage-sub">— each paired with its gather_raw/ payload</span></h2>
  {"".join(blocks)}
</section>
""",
        len(calls),
    )


def _render_gather_call(i: int, call: dict, gather_dir: Path, cost: float = 0.0) -> str:
    inp = call.get("input", {}) or {}
    description = inp.get("description") or "(no description)"
    subagent_type = inp.get("subagent_type") or "(default)"
    prompt = inp.get("prompt", "")
    result = call.get("result")
    err = " [error]" if call.get("is_error") else ""
    title = f"#{i} [{subagent_type}] {description}{err}"
    result_chars = len(result) if isinstance(result, str) else 0
    stats_html = (
        f'<div class="phase-stats">'
        f'<span class="ps-cost">${cost:.4f}</span>'
        f'<span class="ps-sep">·</span>'
        f'<span>prompt {len(prompt):,} char</span>'
        f'<span class="ps-sep">·</span>'
        f'<span>result {result_chars:,} char</span>'
        f'</div>'
    )
    inner = stats_html + block("subagent-input", "input prompt", pre_text(prompt))
    if result is not None:
        inner += block(
            "subagent-output",
            "subagent output (summary back to defender)",
            pre_text(result if isinstance(result, str) else json.dumps(result, indent=2)),
            open_=True,
        )
    else:
        inner += '<div class="empty">(no result captured)</div>'
    m = _LEAD_ID_RE.search(prompt)
    inner += _render_gather_raw_payloads(m.group(1) if m else None, gather_dir)
    return block("subcall gather", title, inner, anchor=f"gather-{i}")


# Pull the lead_id out of the (model-authored) dispatch YAML. Tolerate leading
# indentation: the dispatch block is free-form text, so the `lead_id:` key may
# be indented even though the canonical renderer emits it flush-left. The id
# body mirrors hooks/record_lead.py's LEAD_ID_RE — keep in sync.
_LEAD_ID_RE = re.compile(r"^[ \t]*lead_id:\s*(l-[A-Za-z0-9]+)", re.MULTILINE)


def _render_gather_raw_payloads(lead_id: str | None, gather_dir: Path) -> str:
    """Render the by-ref payloads for one dispatched lead.

    Payloads live under ``gather_raw/{lead_id}/{seq}.json`` — the FK subdir
    scopes a lead's outputs, so we list that lead's directory directly (no
    prefix-matching against a flat namespace).
    """
    if not lead_id:
        return ""
    lead_dir = gather_dir / lead_id
    if not lead_dir.is_dir():
        return ""
    out = ""
    for entry in sorted(lead_dir.iterdir()):
        if not entry.is_file() or entry.suffix not in (".json", ".txt"):
            continue
        try:
            raw = entry.read_text()
            if entry.suffix == ".json":
                raw = json.dumps(json.loads(raw), indent=2)
        except (OSError, json.JSONDecodeError):
            raw = "<unreadable>"
        out += block("gather-raw", f"gather_raw/{lead_id}/{entry.name}", pre_text(raw))
    return out


# ---------------------------------------------------------------------------
# Lead-sequence, report, raw, TOC
# ---------------------------------------------------------------------------


def render_runtime_lead_sequence(run_dir: Path) -> str:
    raw = ""
    p = run_dir / "executed_queries.jsonl"
    if p.is_file():
        raw = block("artifact", "executed_queries.jsonl (queries table)", pre_text(p.read_text()))
    return f"""
<section id="sec-lead-sequence" class="stage stage-defender">
  <h2>§ Lead sequence</h2>
  {render_lead_sequence_compact(run_dir)}
  {raw}
</section>
"""


def render_runtime_report(run_dir: Path) -> str:
    return f"""
<section id="sec-report" class="stage stage-defender">
  <h2>§ Report</h2>
  {render_report_card(run_dir)}
</section>
"""


def render_runtime_raw(events: list[dict]) -> str:
    inner = "\n".join(render_event(e) for e in events) or '<div class="empty">(no events)</div>'
    body = block("raw-stream", f"stream-json events ({len(events)})", inner)
    return f"""
<section id="sec-raw" class="stage stage-raw">
  <h2>§ Raw transcript <span class="stage-sub">— full stream-json, for debugging</span></h2>
  {body}
</section>
"""


def render_runtime_toc(phases: list[dict], n_gather: int) -> str:
    phase_links = "".join(
        f'<li class="item"><a href="#{esc(ph["anchor"])}">{esc(ph["name"])}</a></li>'
        for ph in phases
    )
    if not phases:
        phase_links = '<li class="item muted">(no phases)</li>'
    gather_links = "".join(
        f'<li class="item"><a href="#gather-{i}">gather #{i}</a></li>'
        for i in range(n_gather)
    )
    if n_gather == 0:
        gather_links = '<li class="item muted">(no calls)</li>'
    return f"""
<nav class="toc">
  <ul>
    <li class="section">Headline</li>
    <li class="item"><a href="#top">disposition + report</a></li>

    <li class="section">§ Alert</li>
    <li class="item"><a href="#sec-alert">alert.json</a></li>

    <li class="section">§ Investigation</li>
    {phase_links}

    <li class="section">§ Gather</li>
    {gather_links}

    <li class="section">§ Lead sequence</li>
    <li class="item"><a href="#sec-lead-sequence">leads</a></li>

    <li class="section">§ Report</li>
    <li class="item"><a href="#sec-report">report.md</a></li>

    <li class="section">§ Raw</li>
    <li class="item"><a href="#sec-raw">stream-json</a></li>

    <li class="section">Footer</li>
    <li class="item"><a href="#sec-footer">lesson commits</a></li>
  </ul>
</nav>
"""


# ---------------------------------------------------------------------------
# Footer: concurrent lesson commits
# ---------------------------------------------------------------------------


def _lesson_changes(run_dir: Path, run_id: str) -> dict:
    trace = run_dir / "tool_trace.jsonl"
    if not trace.is_file():
        return {"available": False, "reason": "no tool_trace.jsonl"}
    since_iso = (
        _dt.datetime.fromtimestamp(trace.stat().st_mtime, tz=_dt.UTC).isoformat()
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
    commits = _parse_git_log_records(log.stdout)
    for c in commits:
        c["diff"] = _git_show_lessons_diff(c["sha"])
    return {"available": True, "since": since_iso, "commits": commits, "run_id": run_id}


def _parse_git_log_records(stdout: str) -> list[dict]:
    commits: list[dict] = []
    cur: dict | None = None
    for line in stdout.splitlines():
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
    return commits


def _git_show_lessons_diff(sha: str) -> str:
    diff = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", sha,
         "--pretty=format:", "--", "defender/lessons/"],
        capture_output=True, text=True,
    )
    return diff.stdout if diff.returncode == 0 else ""


def render_footer(run_dir: Path, run_id: str) -> str:
    lc = _lesson_changes(run_dir, run_id)
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
    fold in findings from earlier runs.
  </div>
  {body}
</footer>
"""
