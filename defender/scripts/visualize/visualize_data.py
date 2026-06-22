"""Data layer for the visualizer: pricing, phases, attribution, wall times.

Everything in this module is a pure function over the
``tool_trace.jsonl`` event stream (plus a few file reads for
``investigation.md``). The render layer treats these outputs as
opaque dicts.

Key concepts:

- *Per-message cost*  — computed from each merged assistant message's
  ``usage`` block using ``PRICING``. Stream-json under-reports
  per-message ``output_tokens`` (only the first content-block delta
  survives in the usage block), so per-phase totals are rescaled to
  match the final ``result`` event in ``scale_costs_to_reported``.

- *Phase tagging* — ``tag_events_by_phase`` walks the trace and assigns
  every event a phase based on which ``## PHASE`` header the agent has
  most recently committed body content under in ``investigation.md``.
  Headers introduced as pure scaffolding (e.g. "## ORIENT\\n\\n##
  PLAN" with no body between) don't trigger an advance.

- *Phase attribution* — ``phase_attribution`` buckets each merged
  message's usage and tool-use count into its phase. Subagent
  messages (those with ``parent_tool_use_id`` set) are attributed
  to the phase that issued their parent ``Task``.

- *Wall times* — ``phase_wall_times`` derives per-phase durations from
  ISO timestamps on ``user`` events (tool_results). A phase ends at
  the first tool_result tagged to the next phase.
"""
from __future__ import annotations

import re
from pathlib import Path

from defender.scripts.pricing import PRICING, usage_cost  # noqa: F401  (re-exported for this module's consumers)
from defender.scripts.visualize.visualize_primitives import slugify


# ---------------------------------------------------------------------------
# Phase parsing
# ---------------------------------------------------------------------------


_LOOP_VERBS = ("PLAN", "GATHER", "ANALYZE")
_LOOP_VERB_RE = re.compile(
    r"^(?P<verb>PLAN|GATHER|ANALYZE)\b\s*(?:\((?:loop\s+)?(?P<n>\d+)\))?\s*(?P<rest>.*)$",
    re.IGNORECASE,
)


def normalize_phase_names(phases: list[dict]) -> list[dict]:
    """Stamp every PLAN/GATHER/ANALYZE block with an explicit ``(loop N)``.

    investigation.md is inconsistent in source: some runs label only
    GATHER/ANALYZE with a loop counter, leaving PLAN bare ("## PLAN").
    For the runtime view's TOC and phase summaries we want the loop
    number on every loop-scoped phase. We infer it from the position
    in the phase sequence — a new PLAN starts a new loop; explicit
    annotations override.

    Mutates and returns the same list.
    """
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
    """Cost/wall bar color for a phase verb. Neutral fallback for unknowns."""
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
    """Split investigation.md on ``## `` headers into ordered phase blocks.

    Returns ``[{name, anchor, body}, ...]`` in source order. The text
    before the first ``## `` (preamble / frontmatter) is included as a
    leading entry named "preamble" if non-empty.
    """
    p = run_dir / "investigation.md"
    if not p.is_file():
        return []
    text = p.read_text()
    parts = re.split(r"(?m)^(## .*)$", text)
    # re.split with one capturing group yields: [pre, header1, body1, header2, body2, ...]
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


# ---------------------------------------------------------------------------
# Phase tagging
# ---------------------------------------------------------------------------


_BODY_RE_CACHE: dict[str, re.Pattern] = {}


def _header_has_body(text: str, header: str) -> bool:
    """Return True if ``## {header}`` is followed by non-empty content before the next ``## `` header.

    Used to distinguish scaffolding writes ("## ORIENT\\n\\n## PLAN") from
    real phase transitions where the agent commits substantive content
    under a header. We treat <10 chars of non-whitespace under a header
    as scaffolding — the agent placed the marker but hasn't started
    filling it in.
    """
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


def tag_events_by_phase(events: list[dict], phase_order: list[str]) -> list[str | None]:
    """Walk the raw event stream and tag each event with the phase active when it was emitted.

    The cursor advances when an assistant turn issues a ``Write`` or
    ``Edit`` on ``investigation.md`` whose new content introduces a
    previously-unseen ``## PHASE`` header *and* that header has
    substantive body underneath (else it's scaffolding). Returns a list
    parallel to ``events``; entries are ``None`` only when
    ``phase_order`` is empty.

    Tags are assigned *after* any advance triggered by the event's own
    writes, so the turn that writes "## ORIENT" lands in ORIENT rather
    than in the prior phase.
    """
    if not phase_order:
        return [None] * len(events)

    expected_loop_verbs = [p for p in phase_order if phase_verb(p) in _LOOP_VERBS]
    expected_non_loop = [p for p in phase_order if phase_verb(p) not in _LOOP_VERBS]
    seen_loop_idx = 0
    current = phase_order[0]
    header_re = re.compile(r"^## (.+?)\s*$", re.MULTILINE)

    # Stream-json emits the same tool_use block id repeatedly across the
    # streamed deltas of one message; dedupe so each Write/Edit only
    # advances the phase once.
    consumed_tool_use_ids: set[str] = set()
    # Track every "## PHASE" header we've ever seen in investigation.md
    # writes. Subsequent Edits often fill in those phases without
    # re-introducing the headers; we ask "is this header new to the
    # trace?" rather than "is it absent from this specific Edit's
    # old_string?" to detect real transitions.
    seen_headers: set[str] = set()

    tags: list[str | None] = []
    for ev in events:
        if ev.get("type") != "assistant":
            tags.append(current)
            continue
        msg = ev.get("message") or {}
        for blk in msg.get("content") or []:
            if not isinstance(blk, dict) or blk.get("type") != "tool_use":
                continue
            if blk.get("name") not in ("Write", "Edit"):
                continue
            tu_id = blk.get("id") or ""
            if tu_id and tu_id in consumed_tool_use_ids:
                continue
            inp = blk.get("input", {}) or {}
            fp = str(inp.get("file_path", ""))
            if not fp.endswith("investigation.md"):
                continue
            if tu_id:
                consumed_tool_use_ids.add(tu_id)
            new_text = inp.get("content") or inp.get("new_string") or ""
            new_headers = [m.group(1).strip() for m in header_re.finditer(new_text)]
            introduced: list[str] = []
            for h in new_headers:
                if h in seen_headers:
                    continue
                if _header_has_body(new_text, h):
                    introduced.append(h)
                    seen_headers.add(h)
            for raw in introduced:
                verb = raw.upper().split(" ", 1)[0]
                target = None
                if verb in _LOOP_VERBS:
                    while seen_loop_idx < len(expected_loop_verbs):
                        cand = expected_loop_verbs[seen_loop_idx]
                        if phase_verb(cand) == verb:
                            target = cand
                            seen_loop_idx += 1
                            break
                        seen_loop_idx += 1
                else:
                    for cand in expected_non_loop:
                        if phase_verb(cand) == verb:
                            target = cand
                            break
                if target is not None:
                    current = target
        tags.append(current)
    return tags


# ---------------------------------------------------------------------------
# Assistant message merging
# ---------------------------------------------------------------------------


def merge_assistant_events(events: list[dict]) -> list[dict]:
    """Merge streamed deltas of the same assistant message into one event.

    Stream-json emits each content block (thinking / text / tool_use)
    as its own event for a given ``message.id``. Each event carries the
    same ``usage`` block but a *single* content block. To attribute
    cost correctly (one charge per message) and to see every tool_use a
    message issued, we union the content blocks across events of the
    same id while keeping the first ``usage`` we saw.
    """
    by_id: dict[str, dict] = {}
    order: list[str] = []
    for ev in events:
        if ev.get("type") != "assistant":
            continue
        msg = ev.get("message") or {}
        mid = msg.get("id") or ev.get("uuid")
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


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


def phase_attribution(
    events: list[dict],
    phase_order: list[str],
) -> dict[str, dict]:
    """Bucket per-message usage, cost, and tool calls into phases.

    Builds a ``msg.id -> phase`` map from ``tag_events_by_phase`` using
    last-tag-wins (so a message whose final delta wrote "## ORIENT"
    lands in ORIENT, not the prior phase). Main-agent merged messages
    are bucketed by that map; subagent merged messages (those with
    ``parent_tool_use_id``) are bucketed by whichever phase issued
    their parent ``Task`` tool_use.

    Bucket shape: ``{turns, tool_calls, subagent_calls, tool_counts,
    in, out, cache_r, cache_w, cost}``.
    """
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

    tags = tag_events_by_phase(events, phase_order)
    deduped = merge_assistant_events(events)

    # Build msg.id -> phase map from the *last* tag we saw for each id.
    msg_phase: dict[str, str] = {}
    for ev, ph in zip(events, tags, strict=False):
        if ev.get("type") != "assistant" or ph is None:
            continue
        mid = ((ev.get("message") or {}).get("id")) or ev.get("uuid")
        if mid:
            msg_phase[mid] = ph

    # First pass: main-agent messages.
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
        usage = msg.get("usage") or {}
        model = msg.get("model", "")
        b["turns"] += 1
        b["in"] += usage.get("input_tokens", 0)
        b["out"] += usage.get("output_tokens", 0)
        b["cache_r"] += usage.get("cache_read_input_tokens", 0)
        b["cache_w"] += usage.get("cache_creation_input_tokens", 0)
        b["cost"] += usage_cost(model, usage)
        for blk in (msg.get("content") or []):
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                name = blk.get("name", "?")
                b["tool_calls"] += 1
                b["tool_counts"][name] = b["tool_counts"].get(name, 0) + 1
                if name in ("Task", "Agent"):
                    b["subagent_calls"] += 1
                    task_phase[blk.get("id", "")] = ph

    # Second pass: subagent messages, attributed by parent_tool_use_id.
    for ev in deduped:
        pid = ev.get("parent_tool_use_id")
        if not pid:
            continue
        ph = task_phase.get(pid)
        if ph is None:
            continue
        msg = ev.get("message") or {}
        usage = msg.get("usage") or {}
        model = msg.get("model", "")
        b = buckets[ph]
        b["turns"] += 1
        b["in"] += usage.get("input_tokens", 0)
        b["out"] += usage.get("output_tokens", 0)
        b["cache_r"] += usage.get("cache_read_input_tokens", 0)
        b["cache_w"] += usage.get("cache_creation_input_tokens", 0)
        b["cost"] += usage_cost(model, usage)
        for blk in (msg.get("content") or []):
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                name = blk.get("name", "?")
                b["tool_calls"] += 1
                b["tool_counts"][name] = b["tool_counts"].get(name, 0) + 1

    return buckets


def phase_wall_times(
    events: list[dict],
    tags: list[str | None],
    phase_order: list[str],
) -> dict[str, dict]:
    """Compute per-phase [start, end) durations from ``user`` event timestamps.

    The trace only carries ISO timestamps on ``user`` events
    (tool_results); we tile the run wall-clock by treating
    *first-timestamp-in-a-phase* as the phase's end boundary for the
    preceding phase. Returns ``{phase: {start, end, duration_sec}}``;
    phases with no timestamped events get a zero-duration entry.
    """
    from datetime import datetime

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

    out: dict[str, dict] = {ph: {"start": None, "end": None, "duration_sec": 0.0} for ph in phase_order}
    if not parsed:
        return out
    parsed.sort(key=lambda x: x[0])
    run_start = parsed[0][0]
    run_end = parsed[-1][0]

    first_in_phase: dict[str, object] = {}
    for dt, ph in parsed:
        if ph not in first_in_phase:
            first_in_phase[ph] = dt

    next_phase_first = []
    for i, _ph in enumerate(phase_order):
        nxt = None
        for j in range(i + 1, len(phase_order)):
            if phase_order[j] in first_in_phase:
                nxt = first_in_phase[phase_order[j]]
                break
        next_phase_first.append(nxt)

    cursor = run_start
    for i, ph in enumerate(phase_order):
        start = cursor
        end = next_phase_first[i] if next_phase_first[i] is not None else run_end
        if end < start:
            end = start
        out[ph] = {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "duration_sec": (end - start).total_seconds(),
        }
        cursor = end
    return out


# ---------------------------------------------------------------------------
# Result totals + scaling
# ---------------------------------------------------------------------------


def result_totals(events: list[dict]) -> dict[str, float]:
    """Reliable totals from the run's final ``result`` event."""
    total_cost = 0.0
    sonnet_cost = 0.0
    haiku_cost = 0.0
    for ev in events:
        if ev.get("type") != "result":
            continue
        total_cost += ev.get("total_cost_usd") or 0
        for k, v in (ev.get("modelUsage") or {}).items():
            if not isinstance(v, dict):
                continue
            c = v.get("costUSD") or 0
            if "haiku" in k.lower():
                haiku_cost += c
            else:
                sonnet_cost += c
    return {"total": total_cost, "sonnet": sonnet_cost, "haiku": haiku_cost}


def scale_costs_to_reported(
    events: list[dict],
    attribution: dict[str, dict],
    subagent_costs: dict[str, float],
) -> None:
    """Rescale per-phase + per-subagent cost so totals match the result event.

    Stream-json under-reports ``output_tokens`` per message (only the
    first chunk's count survives in the per-event usage block), so cost
    computed message-by-message is short by 15–25%. The *shape* of the
    per-phase distribution is still informative because
    ``cache_read_input_tokens`` — the dominant cost driver in cached
    sessions — is accurate per message.
    """
    totals = result_totals(events)
    total_reported = totals["total"]
    haiku_reported = totals["haiku"]

    attr_total = sum(b["cost"] for b in attribution.values())
    if attr_total > 0 and total_reported > 0:
        scale = total_reported / attr_total
        for b in attribution.values():
            b["cost"] *= scale

    sub_total = sum(subagent_costs.values())
    if sub_total > 0 and haiku_reported > 0:
        scale = haiku_reported / sub_total
        for k in list(subagent_costs.keys()):
            subagent_costs[k] *= scale


def subagent_cost_by_task(events: list[dict]) -> dict[str, float]:
    """Per-Task subagent cost, keyed by the parent Task tool_use id."""
    out: dict[str, float] = {}
    for ev in merge_assistant_events(events):
        pid = ev.get("parent_tool_use_id")
        if not pid:
            continue
        msg = ev.get("message") or {}
        out[pid] = out.get(pid, 0.0) + usage_cost(msg.get("model", ""), msg.get("usage") or {})
    return out


def extract_main_subagents(events: list[dict]) -> list[dict]:
    """Pair each main-agent ``Task``/``Agent`` tool_use with its tool_result.

    Walks the raw stream (not the merged events) so a single message
    that fired three parallel ``Task`` calls yields three entries. Each
    entry: ``{id, name, input, result, is_error}``. The order matches
    dispatch order — same order the runtime view's § Gather panel
    renders, which pairs each call with its lead's ``gather_raw/{lead_id}/``
    payloads.
    """
    from defender.scripts.visualize.visualize_primitives import flatten_tool_result_content

    calls: dict[str, dict] = {}
    order: list[str] = []
    for ev in events:
        if ev.get("type") == "assistant":
            for blk in (ev.get("message") or {}).get("content", []):
                if (
                    isinstance(blk, dict)
                    and blk.get("type") == "tool_use"
                    and blk.get("name") in ("Task", "Agent")
                ):
                    calls[blk["id"]] = {
                        "id": blk["id"],
                        "name": blk["name"],
                        "input": blk.get("input", {}),
                        "result": None,
                        "is_error": False,
                    }
                    order.append(blk["id"])
        elif ev.get("type") == "user":
            c = (ev.get("message") or {}).get("content", [])
            if not isinstance(c, list):
                continue
            for blk in c:
                if not isinstance(blk, dict) or blk.get("type") != "tool_result":
                    continue
                tid = blk.get("tool_use_id")
                if tid in calls:
                    calls[tid]["result"] = flatten_tool_result_content(blk.get("content", ""))
                    calls[tid]["is_error"] = blk.get("is_error", False)
    return [calls[i] for i in order]
