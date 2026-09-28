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
from defender._vocab import CEILING_DISPOSITION, HOST_ONLY_DISPOSITION, normalized_disposition
from defender._run_paths import RUN_LAYOUT, RunPaths
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


def _wire_log_rel() -> str:
    """The wire log's run-dir-relative path, as an operator would look for it."""
    return str(RUN_LAYOUT.wire_log)


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
    subtitle = f"— {RUN_LAYOUT.investigation.name} split by phase"
    if not phases:
        body = f'<div class="empty">no {RUN_LAYOUT.investigation.name} or empty</div>'
        return (section("sec-investigation", "defender", "Investigation", subtitle, body), [])
    blocks: list[str] = []
    # Stats belong to the phase bucket, which may appear twice in `phases`; only the first
    # appearance carries them, so per-phase figures still sum to the headline.
    billed: set[str] = set()
    for ph in phases:
        stats = (attribution or {}).get(ph["name"])
        wall = (wall_times or {}).get(ph["name"])
        stats_html = _phase_stats_html(stats, wall) if stats and ph["name"] not in billed else ""
        billed.add(ph["name"])
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
    # First appearance wins: a repeated phase name is one transcript group with one `tx-`
    # anchor, and it must match the anchor the nav links.
    phase_anchor: dict[str, str] = {}
    for ph in phases:
        phase_anchor.setdefault(ph["name"], ph["anchor"])
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
            f'<div class="empty">{esc(_wire_log_rel())} not found — transcript unavailable '
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
            f"— main-agent turns, tool calls + results ({_wire_log_rel()})", body,
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


#: Sequences the HTML tokenizer honours inside `<script>`: `</script` ends the element, and
#: `<script` / `<!--` enter escaped states where the island's own closing tag stops working.
#: Case-insensitive because tag names are, and the content is a foreign tool's payload.
_SCRIPT_BREAKOUT_RE = re.compile(r"<(?=/?script|!--)", re.IGNORECASE)


def _render_original_json(original_json: str | None) -> str:
    """The original JSON a TOON-gate-substituted result replaced, rendered beside the view.

    A `<script type="application/json">` data island rather than an escaped `<pre>`, so the
    tool's JSON bytes stay searchable in the page. `<` is neutralized as `\\u003c`, a JSON
    escape, so parsing recovers the payload exactly."""
    if not original_json:
        return ""
    safe = _SCRIPT_BREAKOUT_RE.sub(lambda _: "\\u003c", original_json)
    return (
        '<details class="block tx-resultbody"><summary>original JSON '
        '(pre-TOON-gate)</summary><div class="body">'
        f'<script type="application/json" class="tx-original-json">{safe}</script>'
        "</div></details>"
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
            if t and t.strip():
                body.append(f'<div class="tx-text">{esc_untrusted(t)}</div>')
        for th in e.get("thinks") or []:
            if th and th.strip():
                # Model-authored, like `texts`: same untrusted escape.
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
        inner += _render_original_json(e.get("original_json"))
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
    """The close tool's published outcome members, read rather than restated as literals, so
    a rename at the source cannot silently turn both viewers' badges grey."""

    stands: str
    challenged: str
    forced: str
    not_reviewed_cause: str


@functools.cache
def close_vocabulary() -> _CloseVocabulary:
    """`close_tool`'s outcome members and its not-reviewed cause.

    Imported lazily: `close_tool` pulls in the whole runtime (pydantic-ai included), and
    `learning/frontend/build.py` imports this package just for the page CSS."""
    from defender.runtime.close_tool import CAUSE_NOT_REVIEWED, CHALLENGED, FORCED_INCONCLUSIVE, STANDS

    return _CloseVocabulary(STANDS, CHALLENGED, FORCED_INCONCLUSIVE, CAUSE_NOT_REVIEWED)


_BYPASS_NOTE = (
    '<div class="empty">the gate reviews every disposition but the host\'s own '
    "<code>unresolved</code>, which commits immediately</div>"
)

#: The note for a record predating the `reviewed` field, which must not describe today's
#: bypass set.
_PRE_RECORD_NOTE = (
    '<div class="empty">this record predates the close saying whether a review ran; by the '
    "bypass set of its day, none did</div>"
)


def _bypass_note(record: dict) -> str:
    """The note beside an attempt that bypassed the gate — one chooser for the run-level strip
    and the per-attempt row, so an old record is never shown with today's bypass set."""
    return _BYPASS_NOTE if isinstance(record.get("reviewed"), bool) else _PRE_RECORD_NOTE


#: The bypass set for records predating the `reviewed` field (the live set is
#: `close_tool.NO_REVIEW_DISPOSITIONS`, and records under it carry the field).
_UNREVIEWED_BEFORE_THE_RECORD_SAID = frozenset({CEILING_DISPOSITION, HOST_ONLY_DISPOSITION})


def _was_reviewed(record: dict) -> bool:
    """Did a review actually run for this attempt?

    One place, because an unreviewed attempt rendered as `stands` would read as "a review ran
    and the disposition held". Read off the record's own `reviewed` field, written by the close
    tool; inferring it is unreliable (a reviewed and a bypassed `inconclusive` look the same).
    The frozen fallback is only for records predating the field."""
    reviewed = record.get("reviewed")
    if isinstance(reviewed, bool):
        return reviewed
    # Through the vocabulary's normalizer: an unknown value is no evidence of a review.
    disposition = normalized_disposition(record.get("reviewed_disposition"))
    return disposition is not None and disposition not in _UNREVIEWED_BEFORE_THE_RECORD_SAID


def _review_records(run_dir: Path) -> list[tuple[int, dict]]:
    """Every close attempt's review record (`review_record.{n}.json`), sorted numerically so
    attempt 10 follows attempt 9."""
    from defender._io import read_text_soft

    out: list[tuple[int, dict]] = []
    # One specimen name drives both the glob and the turn-number regex.
    specimen = RUN_LAYOUT.review_record(0).name
    prefix, _, ext = specimen.partition("0")
    for p in run_dir.glob(f"{prefix}*{ext}"):
        m = re.fullmatch(rf"{re.escape(prefix)}(\d+){re.escape(ext)}", p.name)
        if m is None:
            continue
        # The degrading reader, which is what a view wants.
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

    Walked line by line using `parse_jsonl_row`, the writer's own predicate: the writer puts a
    framed reply on its own line exactly when it cannot be mistaken for a row, so
    `read_jsonl_rows` would skip the replies this panel shows. Blank lines belong to the
    reply."""
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
    """The role's raw framed reply: on its own line, or in the row's `raw_reply` when the
    reply is itself row-shaped (a composer's JSON object)."""
    inline = entry["row"].get("raw_reply")
    if isinstance(inline, str) and inline.strip():
        return inline
    return "\n".join(entry["raw"])


def _verdict_class(value: str) -> str:
    """A verdict's CSS class, keyed on `close_tool`'s members; anything else is neutral grey."""
    v = close_vocabulary()
    return {v.stands: "rv-stands", v.challenged: "rv-challenged", v.forced: "rv-forced"}.get(
        value, "rv-skip"
    )


def _review_row_status(row: dict) -> tuple[str, str]:
    """One trace row's status label and class.

    `skipped` and `ok: false` are distinct; a skipped lens has no `ok` key at all, since
    readers take `ok: true` as "this stage answered"."""
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
    """Every review role's trace (roster from `REVIEW_ROLES`), read once per run."""
    from defender._run_paths import RunPaths
    from defender.runtime.challenge_gate import REVIEW_ROLES

    owner = RunPaths(run_dir)
    return [(role, _review_trace(owner.review_trace(role))) for role in REVIEW_ROLES]


def _review_role_html(traces: list[tuple[str, list[dict]]], attempt: int) -> str:
    """One close attempt's per-role calls.

    Attempt N is trace round N-1: trace rows carry `state.turns` on entering the review (0 on
    the first close), while records are numbered by attempt."""
    round_no = attempt - 1

    cards: list[str] = []
    for role, entries in traces:
        for e in entries:
            row = e["row"]
            if row.get("round") != round_no:
                continue
            status, cls = _review_row_status(row)
            # Untrusted escape throughout. `reason` is framed with real newlines, so it needs
            # the pre-formatted lane.
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


def _review_cost_html(costs: dict[str, float] | None) -> str:
    """The gate's spend, totalled and split by lens.

    Empty when nothing priced (a replay's injected stages call no provider); `$0.0000` would
    claim the gate was free."""
    total = sum((costs or {}).values())
    if not total:
        return ""
    per_lens = " · ".join(
        f"{esc(lens)} ${cost:.4f}" for lens, cost in sorted((costs or {}).items())
    )
    return (
        f'<div class="rv-strip"><span class="rv-cost">review spend ${total:.4f}</span>'
        f'<span class="rv-cost-lenses">{per_lens}</span></div>'
    )


def render_review_gate(
    run_dir: Path, report: ReportRead, costs: dict[str, float] | None = None,
) -> tuple[str, int]:
    """§ Review gate — the write-time review every close but the host's own `unresolved`
    passes.

    Rendered as a gate, not a phase: it has no `##` header, the investigator is never in it,
    and it stays out of `visualize_data`'s phase machinery so no cost bar, wall bar or
    transcript group implies otherwise. Its unit is the close attempt. `costs` (per lens, from
    `visualize_messages.review_cost_by_lens`) is shown here for the same reason."""
    subtitle = "— the write-time gate on a close (not a phase)"
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

    # A bypassed close shows "nothing was reviewed", not a review that found nothing;
    # `_was_reviewed` reads that off the record.
    reviewed = [(n, r) for n, r in records if _was_reviewed(r)]
    if not reviewed:
        body = (
            '<div class="rv-strip"><span class="rv-badge rv-skip">not reviewed</span>'
            f'<span class="rv-cause">{esc(cause)}</span></div>'
            + _bypass_note(records[-1][1])
        )
        return (section("sec-review", "review", "Review gate", subtitle, body), 0)
    traces = _read_role_traces(run_dir)

    committed = report.disposition_or_unknown
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
        + _review_cost_html(costs)
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
        # A bypassed attempt carries `verdict: stands` ("committed unchanged"), which would
        # read as a review that held; label it by what happened. A run can mix reviewed and
        # bypassed attempts.
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
        roles_html = _bypass_note(rec) if bypassed else _review_role_html(traces, n)
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
        # `.rows`, including refusal and shim rows: this is the debugging view.
        qs = jl.rows
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
            # One entry per `error_class_for_exit` member, so a policy denial reads differently
            # from a broken adapter.
            exit_cls = {
                None: "lq-ok", "infra": "lq-infra", "agent-fixable": "lq-agent",
                "denied": "lq-denied",
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

    # One transcript entry per phase bucket (matching the transcript's single `tx-` anchor);
    # investigation links stay one per block.
    tx_phase_blocks: dict[str, dict] = {}
    for ph in phases:
        tx_phase_blocks.setdefault(ph["name"], ph)
    tx_links = "".join(
        _phase_nav_li(ph, _tx_target(ph), f' data-phase-link="{esc(ph["name"])}"')
        for ph in tx_phase_blocks.values()
    )
    inv_links = "".join(_phase_nav_li(ph, f'#{esc(ph["anchor"])}') for ph in phases)
    lead_links = "".join(
        f'<li class="item phase-nav lead-nav"><a href="#lead-{esc(jl.lead_id)}">'
        f'<span class="pn-tag pn-lead">{esc(jl.lead_id)}</span></a></li>'
        for jl in leads
    )

    investigation_item = _toc_dropdown("sec-investigation", "investigation", inv_links)
    # A flat link, not a phase entry: the review gate is not a phase.
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
    <li class="item"><a href="#sec-alert">{RUN_LAYOUT.alert.name}</a></li>
    {investigation_item}
    {review_item}
    {leads_item}
    {transcript_item}
    <li class="item"><a href="#sec-footer">lesson commits</a></li>
  </ul>
</nav>
"""




def _lesson_changes(run_dir: Path, run_id: str) -> dict:
    trace = RunPaths(run_dir).tool_trace
    if not trace.is_file():
        return {"available": False, "reason": f"no {trace.name}"}
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
