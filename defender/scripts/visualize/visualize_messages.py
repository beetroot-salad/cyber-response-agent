"""Message-stream projection layer for the visualizer: llm_requests.jsonl readers.

``tool_trace.jsonl`` is a lossy projection: its user events carry tool_results
with only a tool_name (no content, no is_error, no tool_use_id), and it omits
the nested gather agents entirely (observe._main_messages filters them out).
So the searchable transcript, the tool-usage stats, the exact per-phase cost
(gather included), and the run-health signals read the source of truth —
llm_requests.jsonl — which carries every message (main + gather) with full
content, per-message usage / model / duration, and retry-prompt parts. This
is the "write another projection over RequestLogger.messages" path that
runtime/observe.py documents.

Shared helpers imported here:
  ``phase_verb``          — from ``visualize_data`` (phase-name verb accessor)
  ``usage_cost``          — from ``defender.scripts.pricing``
  ``load_jsonl``, ``parse_report`` — from ``visualize_primitives``
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from defender.scripts.pricing import usage_cost
from defender.scripts.visualize.visualize_data import phase_verb
from defender.scripts.visualize.visualize_primitives import load_jsonl, parse_report


LLM_REQUESTS = "llm_requests.jsonl"


def load_messages(run_dir: Path) -> list[dict]:
    """Read llm_requests.jsonl → the per-message records. Missing file → []."""
    return load_jsonl(run_dir / LLM_REQUESTS)


def _pretty_model(name: str) -> str:
    """``anthropic:claude-sonnet-4-6`` / ``claude-haiku-4-5`` → ``sonnet-4-6``."""
    n = (name or "").split(":")[-1]
    return n.removeprefix("claude-") or (name or "?")


def run_metadata(
    run_dir: Path, events: list[dict], messages: list[dict] | None = None
) -> dict:
    """Stable 'where / when / with-what' for the header byline.

    ``started`` is the earliest event timestamp (ISO strings compare in order
    within one run's timezone); ``models`` are the distinct model names that
    appeared (the main agent from the trace, the nested gather agents from the
    message log so the byline isn't missing the Haiku the metrics card prices),
    prettified.
    """
    started = None
    models: list[str] = []

    def _note_model(m) -> None:
        if m and m not in models:
            models.append(m)

    for ev in events:
        ts = ev.get("timestamp")
        if ts and (started is None or ts < started):
            started = ts
        if ev.get("type") == "assistant":
            _note_model((ev.get("message") or {}).get("model"))
    for rec in messages or []:
        if rec.get("kind") == "response":
            _note_model(rec.get("model"))
    return {
        "run_dir": str(run_dir),
        "started": started,
        "models": [_pretty_model(m) for m in models],
    }


def msg_phase_map(events: list[dict], tags: list[str | None]) -> dict[str, str]:
    """main message id -> phase (last per-id tag wins, so a message whose final
    delta wrote "## ORIENT" lands in ORIENT). Shared by cost + transcript."""
    out: dict[str, str] = {}
    for ev, ph in zip(events, tags, strict=False):
        if ev.get("type") != "assistant" or ph is None:
            continue
        mid = ((ev.get("message") or {}).get("id")) or ev.get("uuid")
        if mid:
            out[mid] = ph
    return out


def _iter_gather_tool_uses(events: list[dict], tags: list[str | None]):
    """Yield ``(phase, input_dict)`` for each main-agent ``gather`` tool_use,
    tagged by the phase it was dispatched in."""
    for ev, ph in zip(events, tags, strict=False):
        if ev.get("type") != "assistant":
            continue
        for blk in (ev.get("message") or {}).get("content") or []:
            if (
                isinstance(blk, dict)
                and blk.get("type") == "tool_use"
                and blk.get("name") == "gather"
            ):
                # tool-call args reach the trace as whatever observe.py copied
                # from the part (a dict, or a JSON string — see compaction.py);
                # only a dict carries lead_id, so coerce anything else to {}.
                inp = blk.get("input")
                yield ph, (inp if isinstance(inp, dict) else {})


def gather_dispatch_phase(events: list[dict], tags: list[str | None]) -> dict[str, str]:
    """lead_id -> the phase whose turn dispatched that lead's ``gather`` call."""
    out: dict[str, str] = {}
    for ph, inp in _iter_gather_tool_uses(events, tags):
        lead = str(inp.get("lead_id") or "")
        if lead and ph is not None:
            out.setdefault(lead, ph)
    return out


def gather_calls_by_phase(
    events: list[dict], tags: list[str | None], phase_order: list[str]
) -> dict[str, int]:
    out = {ph: 0 for ph in phase_order}
    for ph, _inp in _iter_gather_tool_uses(events, tags):
        if ph in out:
            out[ph] += 1
    return out


def _iter_gather_responses(run_dir: Path, messages: list[dict] | None):
    """Yield ``(lead_id, record)`` for each gather subagent *response* message in
    the log — the single filter shared by the three gather-message aggregations
    (cost-by-phase, wall-by-phase, cost-by-model)."""
    for rec in (load_messages(run_dir) if messages is None else messages):
        if rec.get("kind") != "response":
            continue
        aid = rec.get("agent_id", "main")
        if not aid.startswith("gather:"):
            continue
        yield aid.split(":", 1)[1], rec


def _gather_phase_for(dispatch_phase: str | None, phase_order: list[str]) -> str | None:
    """The GATHER phase that semantically owns a gather call dispatched in
    ``dispatch_phase``.

    The main agent issues the ``gather`` tool-call (and awaits its result) during
    the PLAN turn — *before* it writes the ``## GATHER`` header — so by raw
    tagging the gather cost and wall pile into PLAN and the GATHER bar renders
    empty. Route them to the GATHER phase of the same loop instead; fall back to
    the first GATHER phase, then to the dispatch phase itself."""
    if dispatch_phase and phase_verb(dispatch_phase) == "GATHER":
        return dispatch_phase
    m = re.search(r"loop (\d+)", dispatch_phase or "")
    if m:
        n = m.group(1)
        for p in phase_order:
            if phase_verb(p) == "GATHER" and re.search(rf"loop {n}\b", p):
                return p
    for p in phase_order:
        if phase_verb(p) == "GATHER":
            return p
    return dispatch_phase


def gather_cost_by_phase(
    run_dir: Path,
    events: list[dict],
    tags: list[str | None],
    phase_order: list[str],
    main_total: float,
    result_total: float,
    messages: list[dict] | None = None,
) -> tuple[dict[str, float], float]:
    """Per-phase Haiku (gather) cost, attributed to each lead's dispatch phase.

    Exact when llm_requests.jsonl is present: sum each gather instance's
    per-message cost and land it in the phase that dispatched its lead. Falls
    back to spreading the ``result - main`` residual across phases by
    gather-call count when the source log is absent (older runs).

    Returns ``(by_phase, total)`` where ``total`` is always ``sum(by_phase)`` —
    not the raw per-lead/residual sum — so the headline (``main + total``) always
    equals the sum of the per-phase cost bars. Cost we cannot place in a bar
    (e.g. a legacy ``Task``/``Agent`` run whose residual maps to no ``gather``
    call) is reported as 0 rather than fabricated into the headline.

    ``messages`` may be passed by a caller that already loaded the log, to avoid
    re-reading the largest file in the run dir; ``None`` reads it here.
    """
    out = {ph: 0.0 for ph in phase_order}
    per_lead: dict[str, float] = {}
    for lead, rec in _iter_gather_responses(run_dir, messages):
        per_lead[lead] = per_lead.get(lead, 0.0) + usage_cost(
            rec.get("model") or "", rec.get("usage") or {}
        )
    if per_lead:
        gphase = gather_dispatch_phase(events, tags)
        # When a lead's dispatch phase is untagged (gphase miss) *and* the run has
        # no GATHER phase, _gather_phase_for can't place the cost — land it in the
        # first phase rather than dropping it, so gather_total stays equal to the
        # full gather cost (the per-model breakdown reads that same sum).
        fallback = phase_order[0] if phase_order else None
        for lead, c in per_lead.items():
            ph = _gather_phase_for(gphase.get(lead), phase_order) or fallback
            if ph in out:
                out[ph] += c
        return out, sum(out.values())
    residual = max(0.0, (result_total or 0.0) - (main_total or 0.0))
    counts = gather_calls_by_phase(events, tags, phase_order)
    tot = sum(counts.values())
    if residual > 0 and tot > 0:
        for ph, n in counts.items():
            tph = _gather_phase_for(ph, phase_order)
            if tph in out:
                out[tph] += residual * n / tot
    return out, sum(out.values())


def gather_wall_by_phase(
    run_dir: Path,
    events: list[dict],
    tags: list[str | None],
    phase_order: list[str],
    messages: list[dict] | None = None,
) -> tuple[dict[str, float], dict[str, float]]:
    """Per-lead gather subagent wall (seconds), grouped two ways.

    Returns ``(to_gather, from_dispatch)``: ``to_gather`` lands each lead's gather
    wall in the GATHER phase that owns it (``_gather_phase_for``); ``from_dispatch``
    records the same seconds against the phase that actually dispatched the call
    (PLAN). The gather run executes *inside* the dispatch turn's wall window, so
    the caller moves these seconds out of the dispatch bar and into the GATHER bar.

    Wall is summed from each gather message's ``duration_ms`` (the model-request
    time). That undercounts true gather wall — the adapter/ES|QL calls between
    model turns aren't timed here — so the move is conservative and never drives a
    phase negative."""
    per_lead_ms: dict[str, float] = {}
    for lead, rec in _iter_gather_responses(run_dir, messages):
        per_lead_ms[lead] = per_lead_ms.get(lead, 0.0) + (rec.get("duration_ms") or 0.0)

    gphase = gather_dispatch_phase(events, tags)
    to_gather = {ph: 0.0 for ph in phase_order}
    from_dispatch = {ph: 0.0 for ph in phase_order}
    for lead, ms in per_lead_ms.items():
        disp = gphase.get(lead)
        gph = _gather_phase_for(disp, phase_order)
        sec = ms / 1000.0
        if gph in to_gather:
            to_gather[gph] += sec
        if disp in from_dispatch:
            from_dispatch[disp] += sec
    return to_gather, from_dispatch


def gather_cost_by_model(
    run_dir: Path, messages: list[dict] | None = None
) -> dict[str, float]:
    """Gather subagent cost grouped by its (prettified) model name.

    The metrics card's per-model breakdown reads this so the gather line carries
    the model the gather agent *actually* ran on (Sonnet, today) rather than a
    hardcoded guess. Empty when llm_requests.jsonl is absent (older runs)."""
    out: dict[str, float] = {}
    for _lead, rec in _iter_gather_responses(run_dir, messages):
        raw = rec.get("model") or ""
        pretty = _pretty_model(raw)
        out[pretty] = out.get(pretty, 0.0) + usage_cost(raw, rec.get("usage") or {})
    return out


def tool_usage(events: list[dict], messages: list[dict] | None = None) -> list[dict]:
    """Per-tool call counts (from the trace) + retry counts (from the message
    log, when present). Ordered by descending count. Drives the transcript's
    tool-filter chips."""
    counts: dict[str, int] = {}
    for ev in events:
        if ev.get("type") != "assistant":
            continue
        for blk in (ev.get("message") or {}).get("content") or []:
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                name = blk.get("name", "?")
                counts[name] = counts.get(name, 0) + 1
    retries: dict[str, int] = {}
    for rec in messages or []:
        # Count MAIN-agent retries only: these chips sit over the main-only
        # transcript, so folding nested gather-agent retries in here would pin
        # gather friction onto main tool chips.
        if rec.get("kind") != "request" or rec.get("agent_id", "main") != "main":
            continue
        for part in (rec.get("message") or {}).get("parts", []):
            if part.get("part_kind") == "retry-prompt":
                name = part.get("tool_name") or "?"
                retries[name] = retries.get(name, 0) + 1
    return [
        {"tool": name, "count": counts[name], "retries": retries.get(name, 0)}
        for name in sorted(counts, key=lambda n: (-counts[n], n))
    ]


def _count_retries(messages: list[dict]) -> int:
    """MAIN-agent gate retries (the process page's friction signal); nested
    gather-agent retries are that subagent's concern, not the main loop's."""
    return sum(
        1
        for rec in messages or []
        if rec.get("kind") == "request" and rec.get("agent_id", "main") == "main"
        for part in (rec.get("message") or {}).get("parts", [])
        if part.get("part_kind") == "retry-prompt"
    )


def _is_dead_end(jl) -> bool:
    """A lead that ran no query, or references a lead_id with no sidecar — a
    planning/tooling gap. The single definition shared by the health count, the
    fold's ∅ markers, and the leads table."""
    return jl.orphan or not jl.queries


def _safe_joined(run_dir: Path) -> list:
    """``lead_repository.joined`` with a never-raise guard, for the standalone
    callers (run_health) that don't get the already-joined list passed in."""
    try:
        from defender.learning import lead_repository

        return lead_repository.joined(run_dir)
    except Exception:
        return []


def _dead_end_count(leads: list) -> int:
    """How many of ``leads`` are dead-ends (see ``_is_dead_end``)."""
    return sum(1 for jl in leads if _is_dead_end(jl))


def _turn_count(events: list[dict]) -> int:
    for ev in events:
        if ev.get("type") == "result" and ev.get("num_turns"):
            return int(ev["num_turns"])
    return sum(1 for ev in events if ev.get("type") == "assistant")


def run_health(
    run_dir: Path,
    events: list[dict],
    messages: list[dict],
    phase_order: list[str],
    leads: list | None = None,
    report: dict | None = None,
) -> dict:
    """Execution-quality signals for the top fold: did the run finish cleanly,
    how much gate friction (retries), and any structural dead-ends.

    ``runtime.html`` is the *process* page, so its headline quality signal is
    execution health (the *outcome* — was the disposition right — is the judge
    page's job, and needs ground truth this page does not have).

    ``leads`` / ``report`` may be passed by a caller that already loaded them so
    the joined tables and report.md aren't re-read; ``None`` reads them here.
    """
    retries = _count_retries(messages)
    dead_ends = _dead_end_count(_safe_joined(run_dir) if leads is None else leads)
    loops = sum(1 for p in phase_order if phase_verb(p) == "PLAN")
    turns = _turn_count(events)
    completed = bool((parse_report(run_dir) if report is None else report).get("disposition"))

    if not completed:
        level, label = "bad", "incomplete"
    elif retries:
        level, label = "warn", "completed"
    else:
        level, label = "good", "completed"
    details: list[str] = []
    if retries:
        details.append(f"{retries} gate retr{'y' if retries == 1 else 'ies'}")
    if dead_ends:
        details.append(f"{dead_ends} dead-end lead{'' if dead_ends == 1 else 's'}")
    return {
        "level": level,
        "label": label,
        "details": details,
        "retries": retries,
        "dead_ends": dead_ends,
        "loops": loops,
        "turns": turns,
        "completed": completed,
    }


def _part_text(part: dict) -> str:
    """Plaintext of a message part's content / args, for search + display."""
    c = part.get("content")
    if isinstance(c, str):
        return c
    if c is None:
        args = part.get("args")
        if args is None:
            return ""
        return args if isinstance(args, str) else json.dumps(args, indent=2, default=str)
    return json.dumps(c, indent=2, default=str)


def _response_entry(rec: dict, phase: str | None, turn: int) -> dict:
    texts, thinks, calls = [], [], []
    for p in (rec.get("message") or {}).get("parts") or []:
        pk = p.get("part_kind")
        if pk == "text":
            texts.append(p.get("content") or "")
        elif pk == "thinking":
            thinks.append(p.get("content") or "")
        elif pk == "tool-call":
            calls.append({"tool": p.get("tool_name", "?"), "args": _part_text(p)})
    usage = rec.get("usage") or {}
    return {
        "kind": "assistant",
        "turn": turn,
        "phase": phase,
        "model": _pretty_model(rec.get("model") or ""),
        "out_tokens": int(usage.get("output_tokens", 0) or 0),
        "duration_ms": rec.get("duration_ms"),
        "texts": texts,
        "thinks": thinks,
        "calls": calls,
        "tools": sorted({c["tool"] for c in calls}),
    }


def _request_entries(rec: dict, phase: str | None, turn: int) -> list[dict]:
    """The prior turn's tool-returns + any gate retries, as transcript entries."""
    out: list[dict] = []
    for p in (rec.get("message") or {}).get("parts") or []:
        pk = p.get("part_kind")
        if pk not in ("tool-return", "retry-prompt"):
            continue
        name = p.get("tool_name") or ("?" if pk == "tool-return" else "")
        out.append({
            "kind": "tool_result" if pk == "tool-return" else "retry",
            "turn": turn,
            "phase": phase,
            "tool": name,
            "is_error": pk == "retry-prompt",
            "content": _part_text(p),
            "tools": [name] if name else [],
        })
    return out


def build_transcript(
    messages: list[dict],
    msg_phase: dict[str, str],
    phase_order: list[str],
) -> list[dict]:
    """Chronological MAIN-agent transcript entries from llm_requests.jsonl.

    One entry per assistant response (its text / thinking / tool-calls) and one
    per tool-return / retry in the intervening request messages. Each entry is
    independently filterable: it carries its phase, a coarse ``kind``, and the
    tool name(s) it touches. Nested gather-agent turns are not inlined — the
    dispatch + returned summary already show as the main agent's ``gather``
    tool-call / return; the per-lead detail lives in § Leads & queries.
    """
    entries: list[dict] = []
    cur_phase: str | None = phase_order[0] if phase_order else None
    turn = 0
    for rec in messages:
        if rec.get("agent_id", "main") != "main":
            continue
        if rec.get("kind") == "response":
            turn += 1
            cur_phase = msg_phase.get(rec.get("id") or "", cur_phase)
            entries.append(_response_entry(rec, cur_phase, turn))
        else:  # request — the prior turn's tool-returns + any gate retries
            entries.extend(_request_entries(rec, cur_phase, turn))
    return entries
