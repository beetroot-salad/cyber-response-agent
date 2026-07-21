from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from defender._run_paths import RunPaths
from defender.scripts.pricing import PRICING, usage_cost  # noqa: F401  (re-exported for this module's consumers)
from defender.scripts.visualize.visualize_primitives import slugify




_LOOP_VERBS = ("PLAN", "GATHER", "ANALYZE")
_LOOP_VERB_RE = re.compile(
    r"^(?P<verb>PLAN|GATHER|ANALYZE)\b\s*(?:\((?:loop\s+)?(?P<n>\d+)\))?\s*(?P<rest>.*)$",
    re.IGNORECASE,
)


def normalize_phase_names(phases: list[dict]) -> list[dict]:
    loop = 0
    for ph in phases:
        m = _LOOP_VERB_RE.match(ph["name"])
        if not m:
            continue
        verb = m.group("verb").upper()
        n = m.group("n")
        rest = (m.group("rest") or "").strip()
        if n is not None:
            loop = int(n)
        else:
            if verb == "PLAN":
                loop += 1
            elif loop == 0:
                loop = 1
        suffix = f" — {rest}" if rest else ""
        ph["name"] = f"{verb} (loop {loop}){suffix}"
    return phases


def phase_color(verb: str) -> str:
    return {
        "ORIENT":  "#58a6ff",
        "PLAN":    "#a371f7",
        "GATHER":  "#3fb950",
        "ANALYZE": "#d29922",
        "REPORT":  "#f0883e",
    }.get(verb.upper(), "#8b949e")


def phase_verb(name: str) -> str:
    return name.split(" ", 1)[0].upper() if name else ""


def split_investigation_phases(run_dir: Path) -> list[dict]:
    p = RunPaths(run_dir).investigation
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8")
    parts = re.split(r"(?m)^(## .*)$", text)
    out: list[dict] = []
    pre = parts[0].strip()
    if pre:
        out.append({"name": "preamble", "anchor": "phase-preamble", "body": pre})
    used_anchors: set[str] = set()
    for i in range(1, len(parts), 2):
        header_line = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""
        name = header_line[3:].strip() or f"phase-{i}"
        slug = slugify(name)
        anchor = f"phase-{slug}"
        n = 2
        while anchor in used_anchors:
            anchor = f"phase-{slug}-{n}"
            n += 1
        used_anchors.add(anchor)
        out.append({"name": name, "anchor": anchor, "body": body.strip()})
    return out




_BODY_RE_CACHE: dict[str, re.Pattern] = {}


def _header_has_body(text: str, header: str) -> bool:
    pat = _BODY_RE_CACHE.get(header)
    if pat is None:
        pat = re.compile(
            r"^## " + re.escape(header) + r"\s*\n+(?P<body>.*?)(?=^## |\Z)",
            re.MULTILINE | re.DOTALL,
        )
        _BODY_RE_CACHE[header] = pat
    m = pat.search(text)
    if not m:
        return False
    body = (m.group("body") or "").strip()
    return len(body) >= 10


def _introduced_headers(new_text: str, seen_headers: set[str], header_re) -> list[str]:
    introduced: list[str] = []
    for m in header_re.finditer(new_text):
        h = m.group(1).strip()
        if h in seen_headers:
            continue
        if _header_has_body(new_text, h):
            introduced.append(h)
            seen_headers.add(h)
    return introduced


def _match_loop_verb(
    verb: str, expected_loop_verbs: list[str], seen_loop_idx: int
) -> tuple[str | None, int]:
    while seen_loop_idx < len(expected_loop_verbs):
        cand = expected_loop_verbs[seen_loop_idx]
        seen_loop_idx += 1
        if phase_verb(cand) == verb:
            return cand, seen_loop_idx
    return None, seen_loop_idx


def _match_non_loop_verb(verb: str, expected_non_loop: list[str]) -> str | None:
    for cand in expected_non_loop:
        if phase_verb(cand) == verb:
            return cand
    return None


class _PhaseTagger:

    def __init__(self, phase_order: list[str]) -> None:
        self.current = phase_order[0]
        self.expected_loop_verbs = [p for p in phase_order if phase_verb(p) in _LOOP_VERBS]
        self.expected_non_loop = [p for p in phase_order if phase_verb(p) not in _LOOP_VERBS]
        self.seen_loop_idx = 0
        self.consumed_tool_use_ids: set[str] = set()
        self.seen_headers: set[str] = set()
        self.header_re = re.compile(r"^## (.+?)\s*$", re.MULTILINE)

    def _advance(self, raw_header: str) -> None:
        verb = raw_header.upper().split(" ", 1)[0]
        if verb in _LOOP_VERBS:
            target, self.seen_loop_idx = _match_loop_verb(
                verb, self.expected_loop_verbs, self.seen_loop_idx
            )
        else:
            target = _match_non_loop_verb(verb, self.expected_non_loop)
        if target is not None:
            self.current = target

    def _process_block(self, blk) -> None:
        if not isinstance(blk, dict) or blk.get("type") != "tool_use":
            return
        if blk.get("name") not in ("Write", "Edit", "write_file", "edit_file"):
            return
        tu_id = blk.get("id") or ""
        if tu_id and tu_id in self.consumed_tool_use_ids:
            return
        inp = blk.get("input", {}) or {}
        fp = str(inp.get("file_path") or inp.get("path") or "")
        if not fp.endswith("investigation.md"):
            return
        if tu_id:
            self.consumed_tool_use_ids.add(tu_id)
        new_text = inp.get("content") or inp.get("new_string") or ""
        for raw in _introduced_headers(new_text, self.seen_headers, self.header_re):
            self._advance(raw)

    def tag(self, events: list[dict]) -> list[str | None]:
        tags: list[str | None] = []
        for ev in events:
            if ev.get("type") == "assistant":
                for blk in (ev.get("message") or {}).get("content") or []:
                    self._process_block(blk)
            tags.append(self.current)
        return tags


def tag_events_by_phase(events: list[dict], phase_order: list[str]) -> list[str | None]:
    if not phase_order:
        return [None] * len(events)
    return _PhaseTagger(phase_order).tag(events)




def merge_assistant_events(events: list[dict]) -> list[dict]:
    by_id: dict[str, dict] = {}
    order: list[str] = []
    for ev in events:
        if ev.get("type") != "assistant":
            continue
        msg = ev.get("message") or {}
        mid = msg.get("id") or ev.get("uuid") or ""
        if mid not in by_id:
            order.append(mid)
            by_id[mid] = {
                "type": "assistant",
                "parent_tool_use_id": ev.get("parent_tool_use_id"),
                "uuid": ev.get("uuid"),
                "message": {
                    "id": mid,
                    "model": msg.get("model", ""),
                    "usage": msg.get("usage") or {},
                    "content": [],
                },
            }
        entry = by_id[mid]
        for blk in msg.get("content") or []:
            if isinstance(blk, dict):
                entry["message"]["content"].append(blk)
    return [by_id[mid] for mid in order]




def _accumulate_usage(b: dict, msg: dict) -> None:
    usage = msg.get("usage") or {}
    model = msg.get("model", "")
    b["turns"] += 1
    b["in"] += usage.get("input_tokens", 0)
    b["out"] += usage.get("output_tokens", 0)
    b["cache_r"] += usage.get("cache_read_input_tokens", 0)
    b["cache_w"] += usage.get("cache_creation_input_tokens", 0)
    b["cost"] += usage_cost(model, usage)


def _attribute_main_agent(
    deduped: list[dict],
    buckets: dict[str, dict],
    msg_phase: dict[str, str],
    phase_order: list[str],
) -> dict[str, str]:
    task_phase: dict[str, str] = {}
    for ev in deduped:
        if ev.get("parent_tool_use_id"):
            continue
        mid = ((ev.get("message") or {}).get("id")) or ev.get("uuid", "")
        ph = msg_phase.get(mid, phase_order[0])
        b = buckets.get(ph)
        if b is None:
            continue
        msg = ev.get("message") or {}
        _accumulate_usage(b, msg)
        for blk in (msg.get("content") or []):
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                name = blk.get("name", "?")
                b["tool_calls"] += 1
                b["tool_counts"][name] = b["tool_counts"].get(name, 0) + 1
                if name in ("Task", "Agent"):
                    b["subagent_calls"] += 1
                    task_phase[blk.get("id", "")] = ph
    return task_phase


def _attribute_subagents(
    deduped: list[dict],
    buckets: dict[str, dict],
    task_phase: dict[str, str],
) -> None:
    for ev in deduped:
        pid = ev.get("parent_tool_use_id")
        if not pid:
            continue
        ph = task_phase.get(pid)
        if ph is None:
            continue
        msg = ev.get("message") or {}
        b = buckets[ph]
        _accumulate_usage(b, msg)
        for blk in (msg.get("content") or []):
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                name = blk.get("name", "?")
                b["tool_calls"] += 1
                b["tool_counts"][name] = b["tool_counts"].get(name, 0) + 1


def phase_attribution(
    events: list[dict],
    phase_order: list[str],
    tags: list[str | None] | None = None,
) -> dict[str, dict]:
    buckets: dict[str, dict] = {
        ph: {
            "turns": 0, "tool_calls": 0, "subagent_calls": 0,
            "tool_counts": {},
            "in": 0, "out": 0, "cache_r": 0, "cache_w": 0, "cost": 0.0,
        }
        for ph in phase_order
    }
    if not phase_order:
        return buckets

    if tags is None:
        tags = tag_events_by_phase(events, phase_order)
    deduped = merge_assistant_events(events)

    msg_phase = msg_phase_map(events, tags)
    task_phase = _attribute_main_agent(deduped, buckets, msg_phase, phase_order)
    _attribute_subagents(deduped, buckets, task_phase)

    return buckets


def _parse_timestamped_user_events(
    events: list[dict], tags: list[str | None]
) -> list[tuple]:

    def _parse(ts: str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None

    parsed: list[tuple] = []
    for ev, ph in zip(events, tags, strict=False):
        if ev.get("type") != "user":
            continue
        ts = ev.get("timestamp")
        if not ts or ph is None:
            continue
        dt = _parse(ts)
        if dt is None:
            continue
        parsed.append((dt, ph))
    return parsed


def _tile_phase_boundaries(
    parsed: list[tuple], phase_order: list[str]
) -> dict[str, dict]:
    parsed.sort(key=lambda x: x[0])
    run_start = parsed[0][0]
    run_end = parsed[-1][0]

    first_in_phase: dict[str, datetime] = {}
    for dt, ph in parsed:
        if ph not in first_in_phase:
            first_in_phase[ph] = dt

    next_phase_first: list[datetime | None] = []
    for i, _ph in enumerate(phase_order):
        nxt = None
        for j in range(i + 1, len(phase_order)):
            if phase_order[j] in first_in_phase:
                nxt = first_in_phase[phase_order[j]]
                break
        next_phase_first.append(nxt)

    out: dict[str, dict] = {}
    cursor = run_start
    for i, ph in enumerate(phase_order):
        start = cursor
        nxt = next_phase_first[i]
        end = nxt if nxt is not None else run_end
        if end < start:
            end = start
        out[ph] = {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "duration_sec": (end - start).total_seconds(),
        }
        cursor = end
    return out


def phase_wall_times(
    events: list[dict],
    tags: list[str | None],
    phase_order: list[str],
) -> dict[str, dict]:
    parsed = _parse_timestamped_user_events(events, tags)

    out: dict[str, dict] = {ph: {"start": None, "end": None, "duration_sec": 0.0} for ph in phase_order}
    if not parsed:
        return out
    out.update(_tile_phase_boundaries(parsed, phase_order))
    return out


from defender.scripts.visualize.visualize_messages import (  # noqa: F401
    LLM_REQUESTS,
    build_transcript,
    gather_calls_by_phase,
    gather_cost_by_model,
    gather_cost_by_phase,
    gather_dispatch_phase,
    gather_wall_by_phase,
    load_messages,
    msg_phase_map,
    run_health,
    run_metadata,
    tool_usage,
)
