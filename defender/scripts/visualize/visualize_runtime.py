"""Runtime view sections (runtime.html).

The defender-run *inspection* page. Above the fold (composed in
``visualize_run.py``) sit the analysis + metrics cards; this module renders the
drill-down below it:

  - § Investigation — investigation.md split per ``## PHASE`` header, each with
    its corrected cost / wall / tool-count stats (the narrative reading).
  - § Transcript — a searchable, filterable, chronological main-agent transcript
    built from ``llm_requests.jsonl`` (turns, tool calls + their results, gate
    retries), with the tool-usage stats doubling as click-to-filter chips.
  - § Leads & queries — the two-table data trail, read from
    ``lead_repository.joined`` (NOT scraped from the lossy trace).

The footer lists any concurrent lesson-author commits. A sticky phase sidebar
(``render_runtime_toc``) navigates the chronological transcript.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import subprocess
from pathlib import Path

from defender.learning import lead_repository
from defender.scripts.visualize.visualize_data import (
    normalize_phase_names,
    phase_color,
    phase_verb,
    split_investigation_phases,
)
from defender.scripts.visualize.visualize_primitives import (
    REPO_ROOT,
    block,
    esc,
    fmt_duration,
    pre_text,
)


def _short_phase(name: str | None) -> str:
    """Compact gutter/sidebar tag: ``GATHER (loop 1)`` → ``G1``, ``ORIENT`` → ``OR``."""
    if not name:
        return ""
    verb = phase_verb(name)
    abbr = {"ORIENT": "OR", "PLAN": "P", "GATHER": "G", "ANALYZE": "A", "REPORT": "RP"}.get(
        verb, verb[:2].title()
    )
    m = re.search(r"loop (\d+)", name)
    return f"{abbr}{m.group(1)}" if m else abbr


# ---------------------------------------------------------------------------
# Investigation phase blocks (the narrative reading of investigation.md)
# ---------------------------------------------------------------------------


def render_runtime_investigation(
    run_dir: Path,
    attribution: dict[str, dict] | None = None,
    wall_times: dict[str, dict] | None = None,
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
        body_html = stats_html + f'<pre class="text invlang">{esc(ph["body"])}</pre>'
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
    pieces = [f'<span class="ps-cost">${stats["cost"]:.4f}</span>']
    if stats.get("gather_cost"):
        pieces.append(f'<span class="ps-gather">(incl gather ${stats["gather_cost"]:.4f})</span>')
    if wall and wall.get("duration_sec"):
        pieces += [
            '<span class="ps-sep">·</span>',
            f'<span class="ps-wall">{fmt_duration(wall["duration_sec"] * 1000)}</span>',
        ]
    pieces += ['<span class="ps-sep">·</span>', f'<span>{stats["turns"]} turn(s)</span>']
    tc = stats.get("tool_counts") or {}
    if tc:
        hist = " ".join(f"{name}×{count}" for name, count in sorted(tc.items(), key=lambda kv: -kv[1]))
        pieces += ['<span class="ps-sep">·</span>', f'<span class="ps-hist">{esc(hist)}</span>']
    else:
        pieces += ['<span class="ps-sep">·</span>', f'<span>{stats["tool_calls"]} tool call(s)</span>']
    pieces += [
        '<span class="ps-sep">·</span>',
        f'<span class="ps-tok">in {stats["in"]:,} / out {stats["out"]:,}'
        f' / cache_r {stats["cache_r"]:,} / cache_w {stats["cache_w"]:,}</span>',
    ]
    return f'<div class="phase-stats">{"".join(pieces)}</div>'


# ---------------------------------------------------------------------------
# Transcript: searchable, filterable, chronological (main agent)
# ---------------------------------------------------------------------------


def render_runtime_transcript(
    entries: list[dict],
    tools: list[dict],
    phases: list[dict],
) -> tuple[str, int]:
    """The § Transcript section: a filter toolbar, the tool-usage filter chips,
    and the chronological entry stream. Returns ``(html, n_entries)``."""
    phase_anchor = {ph["name"]: ph["anchor"] for ph in phases}

    chips: list[str] = []
    for t in tools:
        warn = f'<span class="chip-err">⚠{t["retries"]}</span>' if t.get("retries") else ""
        chips.append(
            f'<button type="button" class="tx-chip" data-tool="{esc(t["tool"])}">'
            f'{esc(t["tool"])}<span class="chip-n">×{t["count"]}</span>{warn}</button>'
        )
    chips_html = "".join(chips) or '<span class="empty">(no tool calls)</span>'

    if not entries:
        rows_html = (
            '<div class="empty">llm_requests.jsonl not found — transcript unavailable '
            '(older run, or the run is still in flight)</div>'
        )
    else:
        seen_phase: set[str] = set()
        rows: list[str] = []
        for e in entries:
            ph = e.get("phase")
            anchor_attr = ""
            if ph and ph not in seen_phase:
                seen_phase.add(ph)
                a = phase_anchor.get(ph)
                if a:
                    anchor_attr = f' id="tx-{esc(a)}"'
            rows.append(_render_tx_entry(e, anchor_attr))
        rows_html = "".join(rows)

    return (
        f"""
<section id="sec-transcript" class="stage stage-defender">
  <h2>§ Transcript <span class="stage-sub">— main-agent turns, tool calls + results (llm_requests.jsonl)</span></h2>
  <div class="tx-toolbar">
    <input type="search" class="tx-search" placeholder="search transcript…" aria-label="search transcript">
    <select class="tx-type" aria-label="filter by type">
      <option value="">all types</option>
      <option value="assistant">assistant turns</option>
      <option value="tool_result">tool results</option>
      <option value="retry">gate retries</option>
    </select>
    <label class="tx-errtoggle"><input type="checkbox" class="tx-errors"> errors only</label>
    <button type="button" class="tx-clear">clear</button>
  </div>
  <div class="tx-chips">{chips_html}</div>
  <div class="tx-stream">{rows_html}</div>
  <div class="tx-noresults empty" hidden>no entries match the current filter</div>
</section>
""",
        len(entries),
    )


def _render_tx_entry(e: dict, anchor_attr: str = "") -> str:
    kind = e["kind"]
    phase = e.get("phase") or ""
    verb = phase_verb(phase)
    tag = (
        f'<span class="tx-phasetag" style="color:{phase_color(verb)}">{esc(_short_phase(phase))}</span>'
    )
    data_tools = " ".join(e.get("tools") or [])

    if kind == "assistant":
        meta = f'{e["out_tokens"]:,} tok'
        if e.get("duration_ms"):
            meta += " · " + fmt_duration(e["duration_ms"])
        if e.get("model"):
            meta += " · " + esc(e["model"])
        body: list[str] = []
        for t in e.get("texts") or []:
            if t.strip():
                body.append(f'<div class="tx-text">{esc(t)}</div>')
        for th in e.get("thinks") or []:
            if th.strip():
                body.append(block("tx-think", "thinking", pre_text(th)))
        for c in e.get("calls") or []:
            body.append(
                f'<details class="block tx-call"><summary>→ {esc(c["tool"])}</summary>'
                f'<div class="body">{pre_text(c["args"])}</div></details>'
            )
        inner = "".join(body) or '<div class="empty">(no content)</div>'
        return (
            f'<div class="tx-entry tx-assistant"{anchor_attr} data-kind="assistant" '
            f'data-phase="{esc(phase)}" data-tools="{esc(data_tools)}">'
            f'<div class="tx-gutter"><span class="tx-turn">#{e.get("turn", "")}</span>{tag}</div>'
            f'<div class="tx-body"><div class="tx-head">'
            f'<span class="tx-role">assistant</span> <span class="tx-meta">{meta}</span></div>'
            f"{inner}</div></div>"
        )

    if kind == "tool_result":
        content = e.get("content") or ""
        head = f'<span class="tx-role">← {esc(e.get("tool", "?"))}</span> <span class="tx-meta">{len(content):,} chars</span>'
        inner = (
            block("tx-resultbody", "result", pre_text(content), open_=len(content) <= 400)
            if content
            else '<div class="empty">(empty result)</div>'
        )
        return (
            f'<div class="tx-entry tx-result" data-kind="tool_result" '
            f'data-phase="{esc(phase)}" data-tool="{esc(e.get("tool", ""))}" data-tools="{esc(data_tools)}">'
            f'<div class="tx-gutter">{tag}</div>'
            f'<div class="tx-body"><div class="tx-head">{head}</div>{inner}</div></div>'
        )

    # retry
    content = e.get("content") or ""
    tool = e.get("tool") or ""
    head = '<span class="tx-role">⟲ gate retry</span>' + (
        f' <span class="tx-meta">{esc(tool)}</span>' if tool else ""
    )
    return (
        f'<div class="tx-entry tx-retry" data-kind="retry" '
        f'data-phase="{esc(phase)}" data-tool="{esc(tool)}" data-tools="{esc(data_tools)}">'
        f'<div class="tx-gutter">{tag}</div>'
        f'<div class="tx-body"><div class="tx-head">{head}</div>{pre_text(content)}</div></div>'
    )


# ---------------------------------------------------------------------------
# Leads & queries: the two-table data trail (lead_repository.joined)
# ---------------------------------------------------------------------------


def render_runtime_leads_queries(run_dir: Path) -> tuple[str, int]:
    leads = lead_repository.joined(run_dir)
    if not leads:
        body = '<div class="empty">no leads recorded (monitor case — the agent ran no queries)</div>'
        return (
            f"""
<section id="sec-leads" class="stage stage-defender">
  <h2>§ Leads &amp; queries <span class="stage-sub">— the two-table data trail (lead_repository.joined)</span></h2>
  {body}
</section>
""",
            0,
        )
    rows: list[str] = []
    for jl in leads:
        goal = jl.goal or ("(orphan — query with no lead sidecar)" if jl.orphan else "")
        qs = jl.queries
        lead_cell = (
            f'<td class="lq-lead" rowspan="{max(1, len(qs))}">'
            f'<div class="lq-leadid">{esc(jl.lead_id)}</div>'
            f'<div class="lq-goal">{esc(goal)}</div></td>'
        )
        if not qs:
            rows.append(
                f'<tr class="lq-deadend">{lead_cell}'
                f'<td colspan="5" class="lq-empty">∅ no queries (dead-end lead)</td></tr>'
            )
            continue
        for i, q in enumerate(qs):
            params = json.dumps(q.params, ensure_ascii=False) if q.params else "—"
            exit_cls = "lq-ok" if q.exit_code == 0 else "lq-bad"
            payload = esc(q.payload_status or "")
            if q.raw_ref is not None:
                try:
                    rel = q.raw_ref.relative_to(run_dir)
                except ValueError:
                    rel = q.raw_ref.name
                payload = f"{payload} · {esc(str(rel))}" if payload else esc(str(rel))
            rows.append(
                f"<tr>{lead_cell if i == 0 else ''}"
                f'<td class="lq-qid">{esc(q.query_id or "?")}</td>'
                f'<td class="lq-sys">{esc(q.system or "")}</td>'
                f'<td class="lq-params">{esc(params)}</td>'
                f'<td class="lq-exit {exit_cls}">{q.exit_code}</td>'
                f'<td class="lq-payload">{payload or "—"}</td></tr>'
            )
    table = (
        '<table class="lq-table"><thead><tr>'
        "<th>lead</th><th>query_id</th><th>sys</th><th>params</th><th>exit</th><th>payload</th>"
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
    )
    return (
        f"""
<section id="sec-leads" class="stage stage-defender">
  <h2>§ Leads &amp; queries <span class="stage-sub">— the two-table data trail (lead_repository.joined)</span></h2>
  {table}
</section>
""",
        len(leads),
    )


# ---------------------------------------------------------------------------
# Sticky sidebar: phase navigation into the transcript + section jumps
# ---------------------------------------------------------------------------


def render_runtime_toc(phases: list[dict], n_tx: int, n_leads: int) -> str:
    def _phase_target(anchor: str) -> str:
        # Jump into the transcript when it exists; else fall back to the
        # investigation phase block.
        return f"#tx-{esc(anchor)}" if n_tx else f"#{esc(anchor)}"

    phase_links = "".join(
        f'<li class="item phase-nav"><a href="{_phase_target(ph["anchor"])}" '
        f'data-phase-link="{esc(ph["name"])}">'
        f'<span class="pn-tag" style="color:{phase_color(phase_verb(ph["name"]))}">'
        f'{esc(_short_phase(ph["name"]))}</span>{esc(ph["name"])}</a></li>'
        for ph in phases
    ) or '<li class="item muted">(no phases)</li>'
    return f"""
<nav class="toc">
  <ul>
    <li class="section">Phases <span class="toc-hint">→ transcript</span></li>
    {phase_links}
    <li class="section">Sections</li>
    <li class="item"><a href="#sec-alert">alert.json</a></li>
    <li class="item"><a href="#sec-investigation">investigation</a></li>
    <li class="item"><a href="#sec-transcript">transcript ({n_tx})</a></li>
    <li class="item"><a href="#sec-leads">leads &amp; queries ({n_leads})</a></li>
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
