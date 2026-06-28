"""Data layer for the visualizer: pricing, phases, attribution, wall times.

Most functions are pure over the ``tool_trace.jsonl`` event stream (plus a few
file reads for ``investigation.md``). The render layer treats these outputs as
opaque dicts. The message-stream readers (transcript, tool-usage stats, gather
cost/wall, run-health) live in ``visualize_messages.py`` and are re-exported
here for backward compatibility.

Key concepts:

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
from datetime import datetime
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


def _introduced_headers(new_text: str, seen_headers: set[str], header_re) -> list[str]:
    """New ``## PHASE`` headers in ``new_text`` that carry substantive body (not
    scaffolding) and haven't been seen before in the trace. Mutates ``seen_headers``
    so a header introduced once isn't re-counted by a later Edit that re-states it."""
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
    """Advance the loop-verb cursor to the next phase whose verb matches ``verb``.
    Returns (target phase or None, the advanced cursor). The cursor only moves
    forward — skipped candidates are consumed too, so each loop phase matches once."""
    while seen_loop_idx < len(expected_loop_verbs):
        cand = expected_loop_verbs[seen_loop_idx]
        seen_loop_idx += 1
        if phase_verb(cand) == verb:
            return cand, seen_loop_idx
    return None, seen_loop_idx


def _match_non_loop_verb(verb: str, expected_non_loop: list[str]) -> str | None:
    """The non-loop phase (ORIENT/REPORT/…) whose verb matches ``verb``, or None."""
    for cand in expected_non_loop:
        if phase_verb(cand) == verb:
            return cand
    return None


class _PhaseTagger:
    """The cursor state for ``tag_events_by_phase``: the current phase plus the
    bookkeeping (loop cursor, consumed tool_use ids, seen headers) the original
    walk threaded as locals — made explicit so the per-event dispatch stays under
    the complexity gate."""

    def __init__(self, phase_order: list[str]) -> None:
        self.current = phase_order[0]
        self.expected_loop_verbs = [p for p in phase_order if phase_verb(p) in _LOOP_VERBS]
        self.expected_non_loop = [p for p in phase_order if phase_verb(p) not in _LOOP_VERBS]
        self.seen_loop_idx = 0
        # Stream-json emits the same tool_use block id repeatedly across the
        # streamed deltas of one message; dedupe so each Write/Edit only advances
        # the phase once.
        self.consumed_tool_use_ids: set[str] = set()
        # Every "## PHASE" header ever seen in investigation.md writes. Subsequent
        # Edits often fill in those phases without re-introducing the headers; we
        # ask "is this header new to the trace?" rather than "absent from this
        # Edit's old_string?" to detect real transitions.
        self.seen_headers: set[str] = set()
        self.header_re = re.compile(r"^## (.+?)\s*$", re.MULTILINE)

    def _advance(self, raw_header: str) -> None:
        """Move ``current`` to the phase an introduced header names, if any."""
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
        """One content block: if it's a new-phase-introducing Write/Edit on
        investigation.md, advance the cursor (deduping repeated stream deltas)."""
        if not isinstance(blk, dict) or blk.get("type") != "tool_use":
            return
        # The PydanticAI runtime exposes the run-dir writers as `write_file` /
        # `edit_file` (arg `path`); the legacy `claude -p` engine used `Write` /
        # `Edit` (arg `file_path`). Match both so phase tagging works on either
        # trace shape — the runtime migration renamed the tools, and a tagger
        # that only knew the old names tagged every event into the first phase.
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
        """Tag each event with the phase active when emitted — after any advance the
        event's own writes trigger (so the turn writing "## ORIENT" lands in ORIENT)."""
        tags: list[str | None] = []
        for ev in events:
            if ev.get("type") == "assistant":
                for blk in (ev.get("message") or {}).get("content") or []:
                    self._process_block(blk)
            tags.append(self.current)
        return tags


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
    return _PhaseTagger(phase_order).tag(events)


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


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


def _accumulate_usage(b: dict, msg: dict) -> None:
    """Fold one merged message's usage + cost into bucket ``b`` (shared by both
    attribution passes)."""
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
    """First pass: bucket main-agent messages by ``msg_phase``. Returns the
    ``task_tool_use_id -> phase`` map so the second pass can attribute subagent
    messages to the phase that issued their parent ``Task``."""
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
    """Second pass: subagent messages, attributed by ``parent_tool_use_id`` to the
    phase that issued the parent ``Task``."""
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
    """Bucket per-message usage, cost, and tool calls into phases.

    Builds a ``msg.id -> phase`` map from ``tag_events_by_phase`` using
    last-tag-wins (so a message whose final delta wrote "## ORIENT"
    lands in ORIENT, not the prior phase). Main-agent merged messages
    are bucketed by that map; subagent merged messages (those with
    ``parent_tool_use_id``) are bucketed by whichever phase issued
    their parent ``Task`` tool_use.

    ``tags`` may be passed by a caller that already tagged the events (the same
    ``tag_events_by_phase(events, phase_order)`` walk), to avoid re-walking the
    whole stream; ``None`` computes it here.

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
    """Pull (datetime, phase) pairs from the ``user`` events that carry a parseable
    ISO timestamp + a phase tag (the only events the trace timestamps)."""

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
    """Tile the run wall-clock into per-phase [start, end) windows: each phase ends
    at the *first* timestamp seen in a later phase (or the run end if none follows).
    Returns ``{phase: {start, end, duration_sec}}``."""
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
    """Compute per-phase [start, end) durations from ``user`` event timestamps.

    The trace only carries ISO timestamps on ``user`` events
    (tool_results); we tile the run wall-clock by treating
    *first-timestamp-in-a-phase* as the phase's end boundary for the
    preceding phase. Returns ``{phase: {start, end, duration_sec}}``;
    phases with no timestamped events get a zero-duration entry.
    """
    parsed = _parse_timestamped_user_events(events, tags)

    out: dict[str, dict] = {ph: {"start": None, "end": None, "duration_sec": 0.0} for ph in phase_order}
    if not parsed:
        return out
    out.update(_tile_phase_boundaries(parsed, phase_order))
    return out


# ---------------------------------------------------------------------------
# Re-exports from visualize_messages (backward-compat public API)
# ---------------------------------------------------------------------------
# These names moved to visualize_messages.py. They are re-exported here so
# existing importers (visualize_run.py, tests/test_visualize_runtime.py) need
# no changes. The import is deferred to the bottom of this module so that
# visualize_messages can import phase_verb from here without a load-time cycle
# (phase_verb is defined above; by the time this line runs, it is available).
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
