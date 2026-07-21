from __future__ import annotations

import json
import re
from pathlib import Path

from defender._io import read_jsonl_rows
from defender.scripts.pricing import usage_cost
from defender.scripts.visualize.visualize_data import phase_verb
from defender.scripts.visualize.visualize_primitives import parse_report


LLM_REQUESTS = "llm_requests.jsonl"


def load_messages(run_dir: Path) -> list[dict]:
    return read_jsonl_rows(run_dir / LLM_REQUESTS)


def _pretty_model(name: str) -> str:
    n = (name or "").split(":")[-1].rsplit("/", 1)[-1]
    return n.removeprefix("claude-") or (name or "?")


def run_metadata(
    run_dir: Path, events: list[dict], messages: list[dict] | None = None
) -> dict:
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
    out: dict[str, str] = {}
    for ev, ph in zip(events, tags, strict=False):
        if ev.get("type") != "assistant" or ph is None:
            continue
        mid = ((ev.get("message") or {}).get("id")) or ev.get("uuid")
        if mid:
            out[mid] = ph
    return out


def _iter_gather_tool_uses(events: list[dict], tags: list[str | None]):
    for ev, ph in zip(events, tags, strict=False):
        if ev.get("type") != "assistant":
            continue
        for blk in (ev.get("message") or {}).get("content") or []:
            if (
                isinstance(blk, dict)
                and blk.get("type") == "tool_use"
                and blk.get("name") == "gather"
            ):
                inp = blk.get("input")
                yield ph, (inp if isinstance(inp, dict) else {})


def gather_dispatch_phase(events: list[dict], tags: list[str | None]) -> dict[str, str]:
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
    for rec in (load_messages(run_dir) if messages is None else messages):
        if rec.get("kind") != "response":
            continue
        aid = rec.get("agent_id", "main")
        if not aid.startswith("gather:"):
            continue
        yield aid.split(":", 1)[1], rec


def _gather_phase_for(dispatch_phase: str | None, phase_order: list[str]) -> str | None:
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
    out = {ph: 0.0 for ph in phase_order}
    per_lead: dict[str, float] = {}
    for lead, rec in _iter_gather_responses(run_dir, messages):
        per_lead[lead] = per_lead.get(lead, 0.0) + usage_cost(
            rec.get("model") or "", rec.get("usage") or {}
        )
    if per_lead:
        gphase = gather_dispatch_phase(events, tags)
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
    out: dict[str, float] = {}
    for _lead, rec in _iter_gather_responses(run_dir, messages):
        raw = rec.get("model") or ""
        pretty = _pretty_model(raw)
        out[pretty] = out.get(pretty, 0.0) + usage_cost(raw, rec.get("usage") or {})
    return out


def tool_usage(events: list[dict], messages: list[dict] | None = None) -> list[dict]:
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
    return sum(
        1
        for rec in messages or []
        if rec.get("kind") == "request" and rec.get("agent_id", "main") == "main"
        for part in (rec.get("message") or {}).get("parts", [])
        if part.get("part_kind") == "retry-prompt"
    )


def _is_dead_end(jl) -> bool:
    return jl.orphan or not jl.queries


def _safe_joined(run_dir: Path) -> list:
    try:
        from defender.learning import lead_repository

        return lead_repository.joined(run_dir)
    except Exception:
        return []


def _dead_end_count(leads: list) -> int:
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
        else:
            entries.extend(_request_entries(rec, cur_phase, turn))
    return entries
