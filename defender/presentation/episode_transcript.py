"""Episode stage, cost, and transcript rendering."""
from __future__ import annotations



import math




from typing import Any






from defender.records._run_id import is_valid_run_id







from defender.learning.branch.steps import STEPS, Step

from defender.learning.judge import (
    recorded_draws,
)








from defender.presentation.visualize_primitives import (
    EVENT_HANDLER_RE,
    esc,
    fmt_duration,
)

from defender.presentation.episode_models import _Episode as _Episode, _RoleCost as _RoleCost, _Trace as _Trace, _duration as _duration, _items as _items, _mapping as _mapping, _priced as _priced



#: The family's own draw documents live under this pseudo-label beside the worlds.
_FAMILY_LABEL = "family"




# =========================================================================================
# Small escaping / id-safety primitives
# =========================================================================================


def _safe_id(raw: str) -> str | None:
    """`raw` if it may become an html id/href/class component (the run-id alphabet), else
    `None`: the caller renders an "unnameable entry" line instead."""
    return raw if isinstance(raw, str) and is_valid_run_id(raw) else None




def _uv(x: Any) -> str:
    """A scalar rendered as text through the untrusted escape — the only spelling, since nearly
    every string here is a record field from a box-reachable tree; `esc()` alone is for the
    page's own literals and ids.

    Splits event-handler names with a `<wbr>` element rather than `esc_untrusted`'s zero-width
    character: both defeat a raw "onerror=" scan, but `<wbr>` contributes no text, so the page's
    text reader round-trips the original word (several adversarial tests assert this)."""
    if x is None:
        return "—"
    if isinstance(x, bool):
        return "True" if x else "False"
    escaped = esc(x if isinstance(x, str) else str(x))
    return EVENT_HANDLER_RE.sub(lambda m: m.group(0) + "<wbr>", escaped)




def _unnameable(raw: str, *, what: str) -> str:
    return f'<div class="unnameable">unnameable entry ({esc(what)}): {_uv(raw)}</div>'




def _money(cost: float) -> str:
    """Gated at print time too: a sum of finite rows can still be `inf`."""
    return f"${cost:.4f}" if math.isfinite(cost) else "—"





def _count(x: Any) -> int | None:
    """A non-negative integer field, or `None` for anything else (a bool is not a count)."""
    return x if isinstance(x, int) and not isinstance(x, bool) and x >= 0 else None




def _page_section(anchor: str, title: str, body: str) -> str:
    return f'<section id="{esc(anchor)}"><h2>{esc(title)}</h2>{body}</section>'




# =========================================================================================
# Stages section
# =========================================================================================


def _render_stages(ep: _Episode) -> str:  # noqa: C901, PLR0912, PLR0915 — the stage table, the two clocks and every trace block are one section
    timing = ep.timing
    rows_by_step = timing.rows_by_step
    review_total, review_calls = ep.review_cost, ep.review_calls

    table_rows = []
    for step in STEPS:
        entries_for_step = rows_by_step.get(str(step), [])
        if timing.error:
            wall_text = ""
        elif entries_for_step:
            # Trusted (non-inverted) pairs only.
            step_wall = timing.step_wall_ms(str(step))
            wall_text = fmt_duration(step_wall) if step_wall is not None else "—"
            if len(entries_for_step) > 1:
                wall_text += f" ({len(entries_for_step)} entries)"
        else:
            wall_text = "not on the record"
        if str(step) in ep.role_costs:
            cost_text = _role_cost_text(ep.role_costs[str(step)])
        elif str(step) == "runs":
            # The runs step row carries only its wall; its cost is on the per-run sub-rows.
            cost_text = ""
        else:
            cost_text = "no model calls"
        table_rows.append(f'<div class="st-row">{esc(str(step))} {esc(wall_text)} '
                         f'{esc(cost_text)}</div>')

    # The caption is `_Timing`'s decision, shared with the header line and the verdict tile.
    if timing.error:
        table = f'<div class="st-error">{_uv(timing.error)}</div>' + "".join(table_rows)
    elif timing.caption is not None:
        table = f'<div class="st-caption">{esc(timing.caption)}</div>' + "".join(table_rows)
    else:
        table = "".join(table_rows)

    # `ep.total_cost` already includes the questioner and judge traces.
    grand_total = ep.total_cost + review_total
    # No total line when nothing priced; `ep.costed` rather than truthiness, since an
    # all-$0.0000 episode is still priced.
    if ep.costed or review_calls:
        table += (f'<div class="st-total">{_money(grand_total)} — excludes gather subagents</div>')

    runs_rows = []
    runs_total = 0.0
    for w in ep.entries.values():
        result = w.result
        if result is None:
            continue
        if result.cost is not None and result.costed:
            runs_total += result.cost
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} {_money(result.cost)} '
                            f'{fmt_duration(result.wall_ms) if result.wall_ms else ""} '
                            f'<span class="rn-launcher">result event</span></div>')
        else:
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} {esc(result.text)}</div>')
    runs_wall = timing.step_wall_ms("runs")
    if runs_wall is not None:
        runs_rows.insert(0, f'<div class="rn-launcher-wall">{fmt_duration(runs_wall)} launcher</div>')
    if ep.runs_costed:
        runs_rows.append(f'<div class="rn-total">{_money(runs_total)}</div>')

    # Only these steps get an id; the rest render inline.
    stages_id_map = {"questioner": "stage-questioner", "runs": "stage-runs",
                     Step.JUDGE: "stage-judge"}
    judge_scopes, unattributed = _classify_judge_traces(ep)
    stage_blocks = []
    for step in STEPS:
        content = table_rows[list(STEPS).index(step)]
        extra = "".join(runs_rows) if str(step) == "runs" else ""
        anchor = stages_id_map.get(str(step))
        id_attr = f' id="{esc(anchor)}"' if anchor else ""
        stage_blocks.append(f'<div{id_attr} class="stage-block">{content}{extra}'
                           f'{_transcript_blocks_for_step(ep, str(step), judge_scopes)}'
                           f'</div>')

    timing_block = f'<div id="stage-timing" class="stage-timing">{table}</div>'
    unattributed_html = ""
    if unattributed:
        unattributed_html = (f'<div class="st-unattributed">unattributed traces: '
                            f'{", ".join(esc(n) for n in unattributed)}</div>')

    if not timing.measured:
        header_line = f'<div class="hd-lower-bound">{esc(ep.lower_bound)}</div>'
    else:
        header_wall_text = fmt_duration(timing.launcher_wall_ms or 0.0)
        header_line = (f'<div class="hd-wall">{esc(header_wall_text)} — the launcher\'s wall '
                      f'from the first step\'s start to the last step\'s end; excludes '
                      f'preflight and the prime, includes the gaps between steps</div>')

    body = f'{header_line}{timing_block}{"".join(stage_blocks)}{unattributed_html}'
    return _page_section("sec-stages", f"Stages ({len(STEPS)})", body)




def _role_cost_text(role: _RoleCost) -> str:
    if not role.calls:
        return "no cost recorded"
    if role.priced < role.calls:
        return (f"{_money(role.cost)} · {role.calls} traces · {fmt_duration(role.wall_ms)} · "
                f"partial — {role.priced} of {role.calls} calls priced")
    return f"{_money(role.cost)} · {role.calls} traces · {fmt_duration(role.wall_ms)}"




def _classify_judge_traces(ep: _Episode) -> tuple[dict[str, list[str]], list[str]]:
    """Partition every judge trace by a declared UUID or family scope, before draw filtering."""
    scoped: dict[str, list[str]] = {_FAMILY_LABEL: []}
    for label, entry in ep.entries.items():
        if entry.nameable:
            scoped[ep.world_id(label)] = []
    unmatched: list[str] = []
    for stem in sorted(ep.wire.stems_for(Step.JUDGE)):
        for scope_id, stems in scoped.items():
            if _stem_names_scope(stem, scope_id):
                stems.append(stem)
                break
        else:
            unmatched.append(stem)
    return scoped, unmatched


def _transcript_blocks_for_step(  # noqa: C901 — one discovery pass per role, family-first ordering included
        ep: _Episode, step: str, judge_scopes: dict[str, list[str]]) -> str:
    if step not in ("questioner", Step.JUDGE, "review") or not ep.wire.present:
        return ""
    blocks = []
    if step == "questioner":
        for stem in sorted(ep.wire.stems_for("questioner")):
            blocks.append(_transcript_block(ep.wire.traces[stem]))
    elif step == Step.JUDGE:
        # Family first, then each world in numeric draw order. Stems include framed-only
        # twins, which is all some judge calls write. Only the draws judge.yaml records (A6):
        # a call log a stopped or wider earlier pass left is never shown as this record's.
        family_drawn = recorded_draws(ep.grade, _FAMILY_LABEL)
        family_stems = sorted((s for s in judge_scopes[_FAMILY_LABEL]
                               if _draw_key_stem(s, _FAMILY_LABEL) in family_drawn),
                              key=lambda s: _draw_key_stem(s, _FAMILY_LABEL))
        for stem in family_stems:
            blocks.append(_transcript_block(ep.wire.traces[stem]))
        for label in sorted(ep.entries):
            if not ep.entries[label].nameable:
                continue
            # Grade rows use labels; the shared classifier has already bound trace UUIDs.
            drawn = recorded_draws(ep.grade, label)
            world_id = ep.world_id(label)
            label_stems = sorted((s for s in judge_scopes[world_id]
                                  if _draw_key_stem(s, world_id) in drawn),
                                 key=lambda s: _draw_key_stem(s, world_id))
            for stem in label_stems:
                blocks.append(_transcript_block(ep.wire.traces[stem]))
    elif step == "review":
        for stem in ep.wire.plain_stems(agent_prefix="comparator_"):
            trace = ep.wire.traces[stem]
            if trace.plain != "ok":
                continue
            if trace.rows:
                blocks.append(_transcript_block(trace))
            else:
                # An empty comparator trace is listed by stem rather than rendered.
                blocks.append(f'<div class="tx-note">{esc(stem)}: 0 rows</div>')
    return "".join(blocks)




def _stem_names_scope(stem: str, scope_id: str) -> bool:
    """Match a world UUID or the family scope and its exact numeric draw suffix."""
    prefix = f"judge_{scope_id}_"
    if not stem.startswith(prefix):
        return False
    remainder = stem[len(prefix):-len("_trace")]
    # ASCII digits only, matching `draws_on_disk_report` (`str.isdigit` admits other scripts).
    return remainder.isascii() and remainder.isdigit()




def _draw_key_stem(stem: str, scope_id: str) -> int:
    prefix = f"judge_{scope_id}_"
    if not stem.startswith(prefix):
        return 0
    try:
        return int(stem[len(prefix):-len("_trace")])
    except ValueError:
        return 0




def _message_parts(row: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
    """A wire row's `message` mapping and `parts` list, each empty when absent."""
    msg = _mapping(row.get("message"))
    return msg, _items(msg.get("parts"))




def _no_response_html(trace: _Trace) -> str:
    """The line for a call with no response. A refused plain trace (link, FIFO, unreadable)
    says so, rather than reading like a benign empty call."""
    if trace.plain == "refused":
        return '<div class="tx-refused">trace refused — not a plain readable file at its name</div>'
    return '<div class="tx-entry">no response recorded</div>'




def _transcript_block(trace: _Trace) -> str:  # noqa: C901, PLR0912 — one call's request/response rendering, every response field independently absent
    rows = trace.rows
    framed = trace.framed

    agent_id = None
    if isinstance(framed, dict) and isinstance(framed.get("agent_id"), str):
        agent_id = framed["agent_id"]
    else:
        for row in rows:
            if isinstance(row.get("agent_id"), str):
                agent_id = row["agent_id"]
                break
    entries_html = [f'<div class="tx-label">{_uv(agent_id)}</div>'] if agent_id else []
    has_plain_response = any(r.get("kind") == "response" for r in rows)
    # The request (framed prompt, or the plain trace's request row) is its own element, not a
    # `tx-entry`.
    if framed is not None:
        prompt = framed.get("prompt")
        failure = framed.get("failure")
        reply = framed.get("reply")
        entries_html.append(f'<div class="tx-request">{_uv(prompt)}</div>')
        if failure:
            entries_html.append(f'<div class="tx-failure">{_uv(failure)}</div>')
        elif reply and not has_plain_response:
            # Framed-only calls render the bare reply. When the plain trace has a response
            # row, that row (with model/usage/duration) is rendered below instead.
            entries_html.append(f'<div class="tx-entry">{_uv(reply)}</div>')
    else:
        request = next((r for r in rows if r.get("kind") == "request"), None)
        if request is not None:
            msg, parts = _message_parts(request)
            instructions = msg.get("instructions")
            prompt_text = ""
            for part in parts:
                if isinstance(part, dict) and part.get("part_kind") == "user-prompt":
                    prompt_text = part.get("content") or ""
            entries_html.append(f'<div class="tx-request">{_uv(prompt_text)}'
                               f'<details><summary>instructions</summary>'
                               f'{_uv(instructions)}</details></div>')

    for row in rows:
        if row.get("kind") != "response":
            continue
        model = row.get("model")
        usage = row.get("usage")
        duration = _duration(row.get("duration_ms"))
        _msg, parts = _message_parts(row)
        text = next((p.get("content") for p in parts if isinstance(p, dict)
                    and p.get("part_kind") == "text"), "")
        priced = _priced(model, usage)
        line_bits = [f'<div class="tx-entry">{_uv(text)}']
        if model:
            line_bits.append(f'<span class="tx-model">{_uv(model)}</span>')
        input_tokens = _count(usage.get("input_tokens", 0)) if isinstance(usage, dict) else None
        if input_tokens is not None:
            line_bits.append(f'<span class="tx-usage">{input_tokens:,}</span>')
        else:
            line_bits.append('<span class="tx-usage">unpriced</span>')
        if priced is not None:
            line_bits.append(f'<span class="tx-cost">{_money(priced)}</span>')
        elif isinstance(usage, dict):
            line_bits.append('<span class="tx-cost">unpriced</span>')
        if duration is not None:
            line_bits.append(f'<span class="tx-wall">{fmt_duration(duration)}</span>')
        line_bits.append('</div>')
        entries_html.append("".join(line_bits))
    framed_has_response = framed is not None and (framed.get("failure") or framed.get("reply"))
    if not framed_has_response and not has_plain_response:
        entries_html.append(_no_response_html(trace))

    unreadable_html = (f'<div class="tx-unreadable">{trace.unreadable} unreadable rows</div>'
                       if trace.unreadable else "")
    # The id embeds a filename stem, so it is grammar-gated, not merely escaped.
    safe = _safe_id(trace.stem)
    if safe is None:
        return _unnameable(trace.stem, what="wire log")
    return (f'<div id="tx-{esc(safe)}" class="tx-stream">'
          f'<div class="tx-search"></div>'
          f'{"".join(entries_html)}{unreadable_html}</div>')
