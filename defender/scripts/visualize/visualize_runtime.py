from __future__ import annotations

import datetime as _dt
import functools
import json
import re
import subprocess
from pathlib import Path
from typing import NamedTuple

from defender import _git
from defender._report import ReportRead
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
    esc_untrusted,
    fmt_duration,
    pre_text_untrusted,
    section,
)


def _short_phase(name: str | None) -> str:
    if not name:
        return ""
    verb = phase_verb(name)
    abbr = {"ORIENT": "OR", "PLAN": "P", "GATHER": "G", "ANALYZE": "A", "REPORT": "RP"}.get(
        verb, verb[:2].title()
    )
    m = re.search(r"loop (\d+)", name)
    return f"{abbr}{m.group(1)}" if m else abbr




def render_runtime_investigation(
    run_dir: Path,
    attribution: dict[str, dict] | None = None,
    wall_times: dict[str, dict] | None = None,
    phases: list[dict] | None = None,
) -> tuple[str, list[dict]]:
    if phases is None:
        phases = normalize_phase_names(split_investigation_phases(run_dir))
    subtitle = "— investigation.md split by phase"
    if not phases:
        body = '<div class="empty">no investigation.md or empty</div>'
        return (section("sec-investigation", "defender", "Investigation", subtitle, body), [])
    blocks: list[str] = []
    for ph in phases:
        stats = (attribution or {}).get(ph["name"])
        wall = (wall_times or {}).get(ph["name"])
        stats_html = _phase_stats_html(stats, wall) if stats else ""
        body_html = stats_html + f'<pre class="text invlang">{esc(ph["body"])}</pre>'
        blocks.append(block("phase", ph["name"], body_html, open_=True, anchor=ph["anchor"]))
    return (section("sec-investigation", "defender", "Investigation", subtitle, "".join(blocks)), phases)


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




def render_runtime_transcript(
    entries: list[dict],
    tools: list[dict],
    phases: list[dict],
) -> tuple[str, int, set[str]]:
    phase_anchor = {ph["name"]: ph["anchor"] for ph in phases}
    anchored: set[str] = set()

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
        rows_html = _render_tx_groups(entries, phase_anchor, anchored)

    body = f"""<div class="tx-toolbar">
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
  <div class="tx-noresults empty" hidden>no entries match the current filter</div>"""
    return (
        section(
            "sec-transcript", "defender", "Transcript",
            "— main-agent turns, tool calls + results (llm_requests.jsonl)", body,
        ),
        len(entries),
        anchored,
    )


def _render_tx_groups(
    entries: list[dict], phase_anchor: dict[str, str], anchored: set[str]
) -> str:
    groups: list[tuple[str | None, list[dict]]] = []
    for e in entries:
        ph = e.get("phase")
        if groups and groups[-1][0] == ph:
            groups[-1][1].append(e)
        else:
            groups.append((ph, [e]))

    blocks: list[str] = []
    for ph, items in groups:
        inner = "".join(_render_tx_entry(e) for e in items)
        verb = phase_verb(ph or "")
        tag = (
            f'<span class="pn-tag" style="color:{phase_color(verb)}">{esc(_short_phase(ph))}</span>'
            if ph
            else ""
        )
        id_attr = ""
        if ph and ph not in anchored:
            a = phase_anchor.get(ph)
            if a:
                id_attr = f' id="tx-{esc(a)}"'
                anchored.add(ph)
        n = len(items)
        blocks.append(
            f'<details class="tx-group" open{id_attr} data-phase="{esc(ph or "")}">'
            f'<summary class="tx-group-head">{tag}'
            f'<span class="tx-group-name">{esc(ph or "(unphased)")}</span>'
            f'<span class="tx-group-n">{n} turn{"" if n == 1 else "s"}</span></summary>'
            f'<div class="tx-group-body">{inner}</div></details>'
        )
    return "".join(blocks)


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
            if t and t.strip():
                body.append(f'<div class="tx-text">{esc_untrusted(t)}</div>')
        for th in e.get("thinks") or []:
            if th and th.strip():
                # Thinking content and tool-call args are model-authored, exactly like
                # `texts` above — same attacker-influenced lane, same escape.
                body.append(block("tx-think", "thinking", pre_text_untrusted(th)))
        for c in e.get("calls") or []:
            body.append(
                f'<details class="block tx-call"><summary>→ {esc(c["tool"])}</summary>'
                f'<div class="body">{pre_text_untrusted(c["args"])}</div></details>'
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
            block("tx-resultbody", "result", pre_text_untrusted(content),
                  open_=len(content) <= 400)
            if content
            else '<div class="empty">(empty result)</div>'
        )
        return (
            f'<div class="tx-entry tx-result"{anchor_attr} data-kind="tool_result" '
            f'data-phase="{esc(phase)}" data-tool="{esc(e.get("tool", ""))}" data-tools="{esc(data_tools)}">'
            f'<div class="tx-gutter">{tag}</div>'
            f'<div class="tx-body"><div class="tx-head">{head}</div>{inner}</div></div>'
        )

    content = e.get("content") or ""
    tool = e.get("tool") or ""
    head = '<span class="tx-role">⟲ gate retry</span>' + (
        f' <span class="tx-meta">{esc(tool)}</span>' if tool else ""
    )
    return (
        f'<div class="tx-entry tx-retry"{anchor_attr} data-kind="retry" '
        f'data-phase="{esc(phase)}" data-tool="{esc(tool)}" data-tools="{esc(data_tools)}">'
        f'<div class="tx-gutter">{tag}</div>'
        f'<div class="tx-body"><div class="tx-head">{head}</div>'
        f'{pre_text_untrusted(content)}</div></div>'
    )




class _CloseVocabulary(NamedTuple):
    """The close tool's OWN published members, read once rather than restated as literals.

    Two viewer modules key on these — the per-attempt verdict badge here and the headline
    badge in `visualize_run` — and a member renamed at its home would otherwise fall through
    to the neutral grey on both with no test failing. Same reason this panel reads
    `REVIEW_ROLES` instead of listing the roles, and `review_trace_path` instead of spelling
    the filename."""

    stands: str
    challenged: str
    forced: str
    not_reviewed_cause: str


@functools.cache
def close_vocabulary() -> _CloseVocabulary:
    """`close_tool`'s outcome members and its not-reviewed cause.

    Imported lazily and cached: `close_tool` pulls the whole in-process runtime (pydantic-ai
    included) and `learning/frontend/build.py` imports this package at module scope, so the
    edge must not be paid by anything that only wants the page CSS."""
    from defender.runtime.close_tool import (
        CAUSE_NOT_REVIEWED,
        CHALLENGED,
        FORCED_INCONCLUSIVE,
        STANDS,
    )

    return _CloseVocabulary(STANDS, CHALLENGED, FORCED_INCONCLUSIVE, CAUSE_NOT_REVIEWED)


#: The one disposition `close_tool` commits WITHOUT a review (its bypass arm). Asked in ONE
#: place because two questions on this page turn on it — "is any attempt worth counting?" and
#: "does THIS attempt's verdict mean a review agreed?" — and the shipped shape asked only the
#: first, so a run challenged once and then closed `inconclusive` rendered its unreviewed
#: second attempt as `stands`, which reads as "a review ran and the disposition held".
UNREVIEWED_DISPOSITION = "inconclusive"

_BYPASS_NOTE = (
    '<div class="empty">the gate reviews confident closes only — an '
    "<code>inconclusive</code> disposition commits immediately</div>"
)


def _was_reviewed(rec: dict) -> bool:
    return rec.get("reviewed_disposition") != UNREVIEWED_DISPOSITION


def _review_records(run_dir: Path) -> list[tuple[int, dict]]:
    """Every close ATTEMPT's numbered review record, in attempt order.

    Numbered, not globbed-and-listed: a challenged close writes its record and commits
    nothing, so a run that was challenged once leaves `review_record.1.json` beside
    `review_record.2.json` and the two are different attempts at the same close — sorting
    them lexically would put attempt 10 before attempt 2 the first time a bound moves."""
    from defender._io import read_text_soft

    out: list[tuple[int, dict]] = []
    for p in run_dir.glob("review_record.*.json"):
        m = re.fullmatch(r"review_record\.(\d+)\.json", p.name)
        if m is None:
            continue
        # `read_text_soft` rather than a locally restated `(OSError, UnicodeDecodeError)`:
        # `_io` publishes that tuple as `TEXT_READ_ERRORS` precisely so a grep for the name
        # audits who guards a read correctly, and the degrading reader is what a view wants.
        text, _ = read_text_soft(p)
        if text is None:
            continue
        try:
            rec = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            out.append((int(m.group(1)), rec))
    return sorted(out, key=lambda kv: kv[0])


def _review_trace(path: Path) -> list[dict]:
    """One review role's trace: each metadata row, with the framed reply that follows it.

    Walked line by line rather than through `read_jsonl_rows`, and the split is decided by
    `parse_jsonl_row` — the WRITER's own predicate. `_write_trace_row` puts a stage's framed
    reply on its own physical line exactly when no reader could mistake it for a row, so the
    ordinary row reader skips it by design; using that reader here would silently drop the
    model's words this panel exists to show, and re-deriving the rule locally would drift
    from the writer the moment either side moved.

    A BLANK line inside a framed reply is part of the reply, not a separator: skipping it
    here (as the shipped shape did) silently reflowed every multi-paragraph reading into one
    run-on block, on the one surface whose whole job is to show the model's words."""
    from defender._io import parse_jsonl_row, read_text_soft

    entries: list[dict] = []
    text, _ = read_text_soft(path)
    if text is None:
        return entries
    for line in text.splitlines():
        row = parse_jsonl_row(line)
        if row is not None:
            entries.append({"row": row, "raw": []})
        elif entries:
            entries[-1]["raw"].append(line)
    return entries


def _review_reply_text(entry: dict) -> str:
    """The role's raw framed reply, from whichever of the two places the writer put it: its
    own physical line, or inside the row's `raw_reply` when the reply was itself row-shaped
    (a composer reply is a JSON object, and on its own line it would corrupt the trace)."""
    inline = entry["row"].get("raw_reply")
    if isinstance(inline, str) and inline.strip():
        return inline
    return "\n".join(entry["raw"])


def _verdict_class(value: str) -> str:
    """A verdict's CSS class, keyed on `close_tool`'s published members — see
    `close_vocabulary`. Anything else is the neutral grey."""
    v = close_vocabulary()
    return {v.stands: "rv-stands", v.challenged: "rv-challenged", v.forced: "rv-forced"}.get(
        value, "rv-skip"
    )


def _review_row_status(row: dict) -> tuple[str, str]:
    """One trace row's status label and class.

    `skipped` and `ok: false` are kept apart, and a `skipped` row is never read as an answer:
    the gate writes NO `ok` key for a lens it did not dispatch, precisely because every trace
    reader takes `ok: true` as "this stage answered". Collapsing the two here would reinstate
    that conflation one layer up, on the surface a human actually looks at."""
    if row.get("incomplete"):
        return "incomplete", "rr-bad"
    if "skipped" in row:
        return "skipped", "rr-skip"
    if row.get("ok") is True:
        return "ok", "rr-ok"
    if row.get("ok") is False:
        return "fault", "rr-bad"
    return "—", "rr-skip"


def _read_role_traces(run_dir: Path) -> list[tuple[str, list[dict]]]:
    """Every review role's trace, read ONCE per run rather than once per close attempt. The
    roster comes from `REVIEW_ROLES` rather than being restated here — the same reason the
    gate's own incomplete-marker walk reads it."""
    from defender.runtime.challenge_gate import REVIEW_ROLES, review_trace_path

    return [(role, _review_trace(review_trace_path(run_dir, role))) for role in REVIEW_ROLES]


def _review_role_html(traces: list[tuple[str, list[dict]]], attempt: int) -> str:
    """One close attempt's per-role calls.

    ATTEMPT N IS TRACE ROUND N-1, and the offset is real rather than a typo to tidy away.
    The gate stamps its trace rows with `state.turns` as it ENTERS the review (0 on the first
    close), while the record is numbered by the attempt it belongs to (`state.turns + 1` on a
    committing arm, and the already-incremented `state.turns` on a challenged one — which
    land on the same number). Filtering the traces on the record's own number is therefore an
    off-by-one that renders every role panel empty, with nothing to say it did."""
    round_no = attempt - 1

    cards: list[str] = []
    for role, entries in traces:
        for e in entries:
            row = e["row"]
            if row.get("round") != round_no:
                continue
            status, cls = _review_row_status(row)
            # `reason` (incomplete) and `skipped` are gate-authored or stage-derived text and
            # the reply is a model's own — all of it goes out through the untrusted escape.
            # `reason` rides FRAMED (real newlines), so it needs the pre-formatted lane too:
            # in a bare div the frame tags and the message collapse onto one line.
            note = row.get("reason") or row.get("skipped") or ""
            reply = _review_reply_text(e)
            inner = ""
            if note:
                inner += f'<div class="rr-note">{pre_text_untrusted(str(note))}</div>'
            if reply.strip():
                inner += pre_text_untrusted(reply)
            if not inner:
                inner = '<div class="empty">(no reply recorded)</div>'
            cards.append(
                f'<details class="block rr-card"><summary>'
                f'<span class="rr-role">{esc(role)}</span>'
                f'<span class="rr-status {cls}">{esc(status)}</span>'
                f'</summary><div class="body">{inner}</div></details>'
            )
    if not cards:
        return '<div class="empty">no role traces for this attempt</div>'
    return f'<div class="rr-list">{"".join(cards)}</div>'


def render_review_gate(run_dir: Path, report: ReportRead) -> tuple[str, int]:
    """§ Review gate — the write-time review every CONFIDENT close passes.

    Rendered as a gate and deliberately NOT as a phase: it has no `##` header in
    `investigation.md`, the investigator never occupies it, and it is kept out of
    `visualize_data`'s phase machinery (`_LOOP_VERBS`, `phase_color`) so no cost bar, wall
    bar or transcript group can imply the agent was ever "in" it. What it gets instead is
    its own section, keyed on the close ATTEMPT — which is the unit it actually has."""
    subtitle = "— the write-time gate on a confident close (not a phase)"
    records = _review_records(run_dir)
    if not records:
        body = (
            '<div class="empty">no review record — the run never reached a close '
            "(still in flight, or it failed before REPORT)</div>"
        )
        return (section("sec-review", "review", "Review gate", subtitle, body), 0)

    fm = report.frontmatter
    outcome = str(fm.get("outcome", "—"))
    cause = str(fm.get("cause", ""))
    failure_kind = fm.get("failure_kind")

    # An `inconclusive` close bypasses the gate entirely, so its record is the honest
    # "nothing was reviewed" and not a review that found nothing.
    reviewed = [(n, r) for n, r in records if _was_reviewed(r)]
    if not reviewed:
        body = (
            '<div class="rv-strip"><span class="rv-badge rv-skip">not reviewed</span>'
            f'<span class="rv-cause">{esc(cause)}</span></div>' + _BYPASS_NOTE
        )
        return (section("sec-review", "review", "Review gate", subtitle, body), 0)

    committed = report.disposition_or_unknown
    traces = _read_role_traces(run_dir)
    kind_html = (
        f'<span class="rv-badge rv-fault">failure_kind: {esc(str(failure_kind))}</span>'
        if failure_kind
        else ""
    )
    strip = (
        f'<div class="rv-strip"><span class="rv-badge {_verdict_class(outcome)}">'
        f"{esc(outcome)}</span>{kind_html}"
        f'<span class="rv-attempts">{len(records)} close attempt'
        f'{"" if len(records) == 1 else "s"}</span>'
        f'<span class="rv-cause">{esc(cause)}</span></div>'
    )
    if failure_kind:
        strip += (
            '<div class="rv-failnote">The review did not complete, so the close failed '
            "<strong>closed</strong> — this is the machinery breaking, not a finding about "
            "the case.</div>"
        )

    rows: list[str] = []
    for n, rec in records:
        verdict = str(rec.get("verdict", "—"))
        drafted = str(rec.get("reviewed_disposition", "—"))
        # An attempt that BYPASSED the gate carries `verdict: stands` — the close tool's word
        # for "committed unchanged", which on this page would read as "the review ran and the
        # disposition survived". It is labelled by what happened to it instead. The guard
        # above only covers a run whose EVERY attempt bypassed; a run challenged once and then
        # closed `inconclusive` reaches here with one of each.
        bypassed = not _was_reviewed(rec)
        badge_cls, badge_text = (
            ("rv-skip", "not reviewed") if bypassed else (_verdict_class(verdict), verdict)
        )
        moved = (
            f'<span class="rv-drafted">{esc(drafted)}</span>'
            f'<span class="rv-arrow">→</span>'
            f'<span class="rv-committed">{esc(committed)}</span>'
            if verdict == close_vocabulary().forced
            else f'<span class="rv-drafted">{esc(drafted)}</span>'
        )
        detail = str(rec.get("detail") or "")
        detail_html = (
            f'<div class="rv-detail">{pre_text_untrusted(detail)}</div>' if detail.strip() else ""
        )
        roles_html = _BYPASS_NOTE if bypassed else _review_role_html(traces, n)
        rows.append(
            f'<div class="rv-attempt">'
            f'<div class="rv-head"><span class="rv-n">attempt {n}</span>'
            f'<span class="rv-badge {badge_cls}">{esc(badge_text)}</span>'
            f'<span class="rv-disp">{moved}</span></div>'
            f"{detail_html}{roles_html}</div>"
        )
    return (
        section("sec-review", "review", "Review gate", subtitle, strip + "".join(rows)),
        len(reviewed),
    )


def render_runtime_leads_queries(run_dir: Path, leads: list | None = None) -> tuple[str, int]:
    if leads is None:
        leads = lead_repository.joined(run_dir)
    subtitle = "— the two-table data trail (lead_repository.joined)"
    if not leads:
        body = '<div class="empty">no leads recorded (monitor case — the agent ran no queries)</div>'
        return (section("sec-leads", "defender", "Leads &amp; queries", subtitle, body), 0)
    rows: list[str] = []
    for jl in leads:
        goal = jl.goal or ("(orphan — query with no lead sidecar)" if jl.orphan else "")
        qs = jl.queries
        lead_cell = (
            f'<td class="lq-lead" id="lead-{esc(jl.lead_id)}" rowspan="{max(1, len(qs))}">'
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
            exit_cls = {
                None: "lq-ok", "infra": "lq-infra", "agent-fixable": "lq-agent",
            }.get(q.error_class, "lq-bad")
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
    return (section("sec-leads", "defender", "Leads &amp; queries", subtitle, table), len(leads))




def _toc_dropdown(section_id: str, label: str, sublinks: str, open_: bool = True) -> str:
    if not sublinks:
        return f'<li class="item"><a href="#{section_id}">{label}</a></li>'
    open_attr = " open" if open_ else ""
    return (
        f'<li class="item toc-dd"><details class="toc-dd-d"{open_attr}>'
        f'<summary class="toc-dd-head"><a href="#{section_id}" class="toc-dd-link">{label}</a></summary>'
        f'<ul class="toc-sublist">{sublinks}</ul></details></li>'
    )


def _phase_nav_li(ph: dict, href: str, data_attr: str = "") -> str:
    return (
        f'<li class="item phase-nav"><a href="{href}"{data_attr}>'
        f'<span class="pn-tag" style="color:{phase_color(phase_verb(ph["name"]))}">'
        f'{esc(_short_phase(ph["name"]))}</span>{esc(ph["name"])}</a></li>'
    )


def render_runtime_toc(  # noqa: PLR0913 — one argument per section the nav links
    phases: list[dict],
    n_tx: int,
    n_leads: int,
    tx_phases: set[str] | None = None,
    leads: list | None = None,
    n_reviewed: int = 0,
) -> str:
    tx_phases = tx_phases or set()
    leads = leads or []

    def _tx_target(ph: dict) -> str:
        anchor = ph["anchor"]
        return f"#tx-{esc(anchor)}" if ph["name"] in tx_phases else f"#{esc(anchor)}"

    tx_links = "".join(
        _phase_nav_li(ph, _tx_target(ph), f' data-phase-link="{esc(ph["name"])}"') for ph in phases
    )
    inv_links = "".join(_phase_nav_li(ph, f'#{esc(ph["anchor"])}') for ph in phases)
    lead_links = "".join(
        f'<li class="item phase-nav lead-nav"><a href="#lead-{esc(jl.lead_id)}">'
        f'<span class="pn-tag pn-lead">{esc(jl.lead_id)}</span></a></li>'
        for jl in leads
    )

    investigation_item = _toc_dropdown("sec-investigation", "investigation", inv_links)
    # A flat link, never a phase entry in the dropdown above: the gate is not one of the
    # phases that nav enumerates, and giving it a `pn-tag` beside ORIENT/PLAN/… is exactly
    # the "sixth phase" reading the section exists to avoid.
    review_label = "review gate" + (f" ({n_reviewed})" if n_reviewed else "")
    review_item = f'<li class="item"><a href="#sec-review">{review_label}</a></li>'
    leads_item = _toc_dropdown("sec-leads", f"leads &amp; queries ({n_leads})", lead_links, open_=False)
    transcript_item = _toc_dropdown("sec-transcript", f"transcript ({n_tx})", tx_links, open_=False)
    return f"""
<nav class="toc">
  <ul>
    <li class="section">Sections</li>
    <li class="item"><a href="#top">↑ top</a></li>
    <li class="item"><a href="#sec-metrics">metrics</a></li>
    <li class="item"><a href="#sec-alert">alert.json</a></li>
    {investigation_item}
    {review_item}
    {leads_item}
    {transcript_item}
    <li class="item"><a href="#sec-footer">lesson commits</a></li>
  </ul>
</nav>
"""




def _lesson_changes(run_dir: Path, run_id: str) -> dict:
    trace = run_dir / "tool_trace.jsonl"
    if not trace.is_file():
        return {"available": False, "reason": "no tool_trace.jsonl"}
    since_iso = (
        _dt.datetime.fromtimestamp(trace.stat().st_mtime, tz=_dt.UTC).isoformat()
    )
    try:
        log_out = _git.git(
            [
                "log",
                f"--since={since_iso}",
                "--pretty=format:%H%x09%cI%x09%s",
                "--name-status",
                "--", "defender/lessons/",
            ],
            cwd=REPO_ROOT, timeout=10,
        )
    except _git.GitError as e:
        return {"available": False, "reason": e.stderr or "git log failed"}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"available": False, "reason": f"git unavailable: {e}"}
    commits = _parse_git_log_records(log_out)
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
    try:
        return _git.git(
            ["show", sha, "--pretty=format:", "--", "defender/lessons/"], cwd=REPO_ROOT
        )
    except _git.GitError:
        return ""


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
