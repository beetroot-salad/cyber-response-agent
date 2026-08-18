from __future__ import annotations

import json
import re
from pathlib import Path

from defender._io import read_jsonl_rows
from defender._report import ReportRead
from defender._run_paths import GATE_METADATA_KEY, WIRE_LOG, RunPaths
# `agent_role` and NOT `review_roles`, though the latter re-exports the same constant:
# `review_roles` pulls `runtime.tools` and with it the whole in-process runtime (pydantic-ai
# included), and `learning/frontend/build.py` imports this package at module scope for the
# page CSS alone. Same rule `visualize_runtime.close_vocabulary` states for `close_tool`.
from defender.runtime.agent_role import GATHER_AGENT_ID_PREFIX, REVIEW_AGENT_ID_PREFIX
from defender.scripts.pricing import usage_cost
from defender.scripts.visualize.visualize_data import phase_verb
from defender.scripts.visualize.visualize_primitives import parse_report


#: The wire log's PRE-`wire_logs/` run-root location, named for that rather than for the file:
#: its one live use is `load_messages`' fallback below. Named this way because `run_dir / X` on
#: a constant that reads as "the wire log" silently resolves to a path no current run writes —
#: a consumer that wants the live wire log asks `RunPaths.wire_log`.
LEGACY_WIRE_LOG = WIRE_LOG


def load_messages(run_dir: Path) -> list[dict]:
    """The run's wire-log records, or `[]` when the run has none.

    Falls back to the pre-`wire_logs/` run-root path so an older run dir still renders a
    transcript. A READER fallback only: the `wire_logs/` location is a read-GATE fact
    (`_run_paths.WIRE_LOG_DIR`) and this is host code, outside the gate entirely."""
    current = RunPaths(run_dir).wire_log
    return read_jsonl_rows(current if current.is_file() else run_dir / LEGACY_WIRE_LOG)


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


def _iter_tool_uses(events: list[dict], tags: list[str | None]):
    """Every `tool_use` block an assistant trace event carries, as `(phase, block)`.

    The module's one "walk the trace's assistant turns alongside their phase tags" loop."""
    for ev, ph in zip(events, tags, strict=False):
        if ev.get("type") != "assistant":
            continue
        for blk in (ev.get("message") or {}).get("content") or []:
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                yield ph, blk


def msg_phase_map(events: list[dict], tags: list[str | None]) -> dict[str, str]:
    """Phase by TRACE id — the session-store coord `{session_id}/{agent_id}#{seq}`.

    This is `visualize_data._attribute_main_agent`'s key space, and it reads trace events,
    so it holds coords too. A reader that walks the WIRE LOG instead holds
    `{agent_id}#{seq}` and cannot use this map — see `transcript_phase_map`."""
    out: dict[str, str] = {}
    for ev, ph in zip(events, tags, strict=False):
        if ev.get("type") != "assistant" or ph is None:
            continue
        mid = ((ev.get("message") or {}).get("id")) or ev.get("uuid")
        if mid:
            out[mid] = ph
    return out


def transcript_phase_map(
    events: list[dict], tags: list[str | None], messages: list[dict],
) -> dict[str, str]:
    """Phase by WIRE-LOG record id — the key space `build_transcript` actually holds.

    `tool_trace.jsonl` and the wire log name the same assistant turn in two id spaces that
    cannot be compared. The trace carries the session-store coord
    (`{session_id}/{agent_id}#{seq}`, seq counting store ROWS — `session_store._actor_row`),
    the wire log its own `{agent_id}#{seq}` (seq counting every emitted RECORD, requests
    included — `observe.RequestLogger._emit`). Hand `build_transcript` the coord-keyed map and
    its `.get` misses on every turn, so `cur_phase` never leaves its `phase_order[0]` seed and
    the whole transcript renders as ORIENT.

    Neither WRITER can mint the other's key: the store row for a response is appended a round
    later by `selection.ingest`, so the coord does not exist when the logger runs — and making
    the trace carry a wire id would break the invariant that the projection is built from the
    store alone. The visualizer is the first frame holding BOTH files.

    The join key is the TOOL-CALL ID, which is neither side's invention: both files copy it
    off the same `ModelResponse.parts[].tool_call_id` — the trace as a `tool_use` block's `id`
    (`observe._assistant_event`), the wire log as a `tool-call` part's `tool_call_id`. A
    POSITIONAL pairing cannot stand in for it, because the two sequences differ in length once
    a fold has fired: a fold re-parents the frontier onto the LINEAGE ROOT, so the trace holds
    only the turns SINCE the last fold while the append-only wire log still holds every turn
    from the first. Keying on the id leaves the folded-away turns unmapped instead, and
    `build_transcript` carries the previous phase forward as it does for any untagged turn.

    A response with no tool call at all is likewise unmapped. That is only ever the run's
    terminal turn — a text-only `ModelResponse` ends the agent run — so it inherits the phase
    of the turn before it, which is the phase it is in.
    """
    by_call: dict[str, str] = {}
    for ph, blk in _iter_tool_uses(events, tags):
        call_id = blk.get("id")
        if call_id and ph is not None:
            by_call.setdefault(str(call_id), ph)

    out: dict[str, str] = {}
    for rec in messages:
        wid = rec.get("id")
        if rec.get("kind") != "response" or rec.get("agent_id", "main") != "main" or not wid:
            continue
        for part in (rec.get("message") or {}).get("parts") or []:
            ph = by_call.get(str(part.get("tool_call_id") or ""))
            if ph is not None:
                out[wid] = ph
                break
    return out


def _iter_gather_tool_uses(events: list[dict], tags: list[str | None]):
    for ph, blk in _iter_tool_uses(events, tags):
        if blk.get("name") == "gather":
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


def _iter_agent_responses(run_dir: Path, messages: list[dict] | None, prefix: str):
    """Every wire response a subagent namespace wrote, as `(suffix, record)`.

    Parameterised on the prefix rather than copied per namespace: the main agent, the gather
    subagents and the review stages all write through ONE `RequestLogger` into one wire log
    and are told apart only by `agent_id`."""
    for rec in (load_messages(run_dir) if messages is None else messages):
        if rec.get("kind") != "response":
            continue
        aid = rec.get("agent_id", "main")
        if not aid.startswith(prefix):
            continue
        yield aid[len(prefix):], rec


def _iter_gather_responses(run_dir: Path, messages: list[dict] | None):
    return _iter_agent_responses(run_dir, messages, GATHER_AGENT_ID_PREFIX)


def _iter_review_responses(run_dir: Path, messages: list[dict] | None):
    return _iter_agent_responses(run_dir, messages, REVIEW_AGENT_ID_PREFIX)


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
    per_lead = _cost_by(_iter_gather_responses(run_dir, messages), lambda lead, _raw: lead)
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


def _cost_by(pairs, key) -> dict[str, float]:
    """Price a namespace's wire responses and total them under whatever `key` names."""
    out: dict[str, float] = {}
    for suffix, rec in pairs:
        raw = rec.get("model") or ""
        k = key(suffix, raw)
        out[k] = out.get(k, 0.0) + usage_cost(raw, rec.get("usage") or {})
    return out


def gather_cost_by_model(
    run_dir: Path, messages: list[dict] | None = None
) -> dict[str, float]:
    return _cost_by(_iter_gather_responses(run_dir, messages), lambda _s, raw: _pretty_model(raw))


def review_cost_by_lens(
    run_dir: Path, messages: list[dict] | None = None
) -> dict[str, float]:
    """The write-time review gate's spend, split by LENS — support / ablation / composer.

    Per lens and not per close ATTEMPT, though the attempt is the unit the gate's own record
    is keyed on: the wire record carries no round, and the ordinal cannot stand in for one
    because the ablation lens is skipped on a pass with no load-bearing edge to withhold, so
    its n-th call is not its n-th round. The lens is also the decomposition this gate has
    actually made roster decisions on (`runtime/challenge_gate.py`)."""
    return _cost_by(_iter_review_responses(run_dir, messages), lambda lens, _raw: lens)


def review_cost_by_model(
    run_dir: Path, messages: list[dict] | None = None
) -> dict[str, float]:
    """The same spend keyed by MODEL, for the run's by-model breakdown. The review runs on its
    own pinned default (`review_roles.DEFAULT_REVIEW_MODEL`), so this is usually a row of its
    own — and correctly merges with main's when an operator points both at one model."""
    return _cost_by(_iter_review_responses(run_dir, messages), lambda _s, raw: _pretty_model(raw))


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
    for rec in deduped_main_records(messages or []):
        if rec.get("kind") != "request":
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
        for rec in deduped_main_records(messages or [])
        if rec.get("kind") == "request"
        for part in (rec.get("message") or {}).get("parts", [])
        if part.get("part_kind") == "retry-prompt"
    )


def _is_dead_end(jl) -> bool:
    return jl.orphan or not jl.rows  # "reached the table at all"


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
    report: ReportRead | None = None,
) -> dict:
    retries = _count_retries(messages)
    dead_ends = _dead_end_count(_safe_joined(run_dir) if leads is None else leads)
    loops = sum(1 for p in phase_order if phase_verb(p) == "PLAN")
    turns = _turn_count(events)
    # "Completed" asks whether the run reached REPORT at all, so it keys off the frontmatter
    # HAVING a `disposition` key, not off that value being valid. A run that closed on a
    # disposition the enum rejects still ran to the end; saying otherwise would send an
    # operator hunting a truncated run instead of a malformed headline.
    read = parse_report(run_dir) if report is None else report
    completed = bool(read.frontmatter.get("disposition"))

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


def _gate_original_json(part: dict) -> str | None:
    """The tool's own JSON, carried alongside a TOON-gate-substituted view under
    `GATE_METADATA_KEY` on the part's `metadata`. `load_messages` returns `metadata` verbatim,
    so the entry built here is the only place the field can be lost between wire log and page.

    The key is read from `defender._run_paths`, NOT from the `defender.runtime.toon_gate` that
    writes it: that module imports pydantic-ai, a `runtime`-extra-only dependency, so an
    import here would raise `ModuleNotFoundError` while rendering the first tool return of any
    transcript on a learning-loop/CI install — the same edge this module's
    `agent_role`-not-`review_roles` import already refuses to pay."""
    meta = part.get("metadata")
    if not isinstance(meta, dict) or GATE_METADATA_KEY not in meta:
        return None
    return json.dumps(meta[GATE_METADATA_KEY], default=str)


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
            "original_json": _gate_original_json(p) if pk == "tool-return" else None,
            "tools": [name] if name else [],
        })
    return out


def _message_key(rec: dict) -> str:
    return json.dumps(rec.get("message") or {}, sort_keys=True, default=str)


def _new_suffix(prev: list[str], current: list[str]) -> int:
    """Index past the longest common prefix of two turns' request digests."""
    i = 0
    while i < len(prev) and i < len(current) and prev[i] == current[i]:
        i += 1
    return i


def deduped_main_records(messages: list[dict]) -> list[dict]:
    """Main-agent wire records with the verbatim log's repeated history removed.

    `RequestLogger.log` records the FULL request list on every call — there is deliberately no
    write-time delta encoding, since a cursor never logs a rewrite that fails to shrink the
    list below it. The cost is that every consumer must de-duplicate at READ time or count
    each turn's history again on the next turn.

    The key is wire POSITION, not content identity: each turn's request records are matched
    against the previous turn's and only the suffix past their longest common prefix is new.
    Two genuinely identical tool results therefore both survive (different positions), while a
    fold — which rewrites the list from the front — correctly re-emits the frontier and
    everything after it.
    """
    out: list[dict] = []
    prev: list[str] = []
    pending: list[dict] = []

    def flush() -> None:
        nonlocal prev, pending
        digests = [_message_key(r) for r in pending]
        out.extend(pending[_new_suffix(prev, digests):])
        prev, pending = digests, []

    for rec in messages:
        if rec.get("agent_id", "main") != "main":
            continue
        if rec.get("kind") == "response":
            flush()
            out.append(rec)
        else:
            pending.append(rec)
    flush()
    return out


def build_transcript(
    messages: list[dict],
    msg_phase: dict[str, str],
    phase_order: list[str],
) -> list[dict]:
    entries: list[dict] = []
    cur_phase: str | None = phase_order[0] if phase_order else None
    turn = 0
    for rec in deduped_main_records(messages):
        if rec.get("kind") == "response":
            turn += 1
            cur_phase = msg_phase.get(rec.get("id") or "", cur_phase)
            entries.append(_response_entry(rec, cur_phase, turn))
        else:
            entries.extend(_request_entries(rec, cur_phase, turn))
    return entries
