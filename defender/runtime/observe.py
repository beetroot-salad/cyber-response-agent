"""Observability for the PydanticAI runtime: one streaming log, projected views.

**Single source of truth.** Every model API request is logged at the request
boundary (the driver's `wrap_model_request` hook → `RequestLogger.log`) to
`llm_requests.jsonl`, written *live* (flushed) so a crash mid-run still leaves a
complete audit. The log is **delta/streaming**: each conversation MESSAGE is
written exactly once, the first request that carries it (`event_type:"message"`,
one line per message), rather than re-dumping the whole growing history on every
request. A long run therefore costs O(n) on disk and in memory, not O(n²).

Each message line carries `agent_id` ("main" / "gather:{lead_id}") and a stable
per-instance `id` (`{agent_id}#{seq}`) — the identity downstream views key on,
so interleaved nested-agent messages never collide. Response messages also carry
their own `model` + `usage` (so cost is exact and per-model).

Everything else is a **projection** of those messages — same data, re-tagged:

  - `tool_trace.jsonl` — the consumer contract `run_stats.py` / `visualize_run.py`
    read (`assistant`/`user`/`result` events). Built post-mortem by replaying the
    main instance's messages; the trailing `result` event's `total_cost_usd` is
    summed **per response message at its own model's rate** via `scripts/pricing.py`
    (the first-party API does not return a cost the way `claude -p` did), so a run
    that dispatched gather mixes Sonnet + Haiku correctly.

To add another view (a tool-only audit, a cost-by-phase rollup), write another
projection over `RequestLogger.messages` — don't add another logging site.

Note (Phase A): the streaming cursor assumes the per-agent message history is
append-only (it is — the driver passes history through unmodified). Phase B
message-level compaction would rewrite history and must reset the cursors.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from pydantic_ai.messages import ModelMessagesTypeAdapter

# scripts/ holds the shared price table; mirror permission.py's path bootstrap
# (defender/runtime → defender/scripts) rather than couple to an install layout.
_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
from pricing import usage_cost  # noqa: E402  (sys.path set above)


# --- the single instrumentation point -------------------------------------

def _max_chars() -> int:
    """Per-string cap for logged message content; 0 (default) = full fidelity.
    A single oversized message (e.g. a huge tool-return) can still bloat the
    on-disk log; set DEFENDER_LLM_LOG_MAX_CHARS to bound that when debugging."""
    try:
        return int(os.environ.get("DEFENDER_LLM_LOG_MAX_CHARS", "0"))
    except ValueError:
        return 0


def _trim(obj: Any, cap: int) -> Any:
    """Recursively truncate long string leaves (content/args) to `cap` chars."""
    if cap <= 0:
        return obj
    if isinstance(obj, str):
        return obj if len(obj) <= cap else obj[:cap] + f"…[+{len(obj) - cap} chars]"
    if isinstance(obj, list):
        return [_trim(x, cap) for x in obj]
    if isinstance(obj, dict):
        return {k: _trim(v, cap) for k, v in obj.items()}
    return obj


def _usage_dict(usage: Any) -> dict[str, int]:
    """RequestUsage → the `tool_trace.jsonl` usage key shape (the names
    run_stats.py and pricing.usage_cost read).

    PydanticAI reports `input_tokens` as the TOTAL input — cache reads + cache
    writes + the genuinely-uncached remainder (verified: per response,
    input_tokens == cache_read + cache_write + ~1). But the trace contract (and
    `pricing.usage_cost`, shared with the legacy `claude -p` path) treats
    `input_tokens` as the UNCACHED count, pricing cache reads/writes separately.
    So we subtract the cache fields here — otherwise the ~cached tokens are billed
    at the full input rate AND again at the cache rate (a ~4-5x cost overcount).
    Normalize at this projection boundary so `pricing` stays correct for both
    engines and the on-disk `input_tokens` means the same thing everywhere."""
    g = lambda n: int(getattr(usage, n, 0) or 0)  # noqa: E731
    cache_r = g("cache_read_tokens")
    cache_w = g("cache_write_tokens")
    return {
        "input_tokens": max(0, g("input_tokens") - cache_r - cache_w),
        "output_tokens": g("output_tokens"),
        "cache_read_input_tokens": cache_r,
        "cache_creation_input_tokens": cache_w,
    }


class RequestLogger:
    """Streams conversation messages to `llm_requests.jsonl`, one line per message,
    live and flushed, and keeps them in memory for post-run projection. Open one
    per run (shared by the main and nested gather agents); the driver's
    `wrap_model_request` hook calls `log` around each API call.

    Streaming, not snapshotting: each request's input is the whole growing
    history, so logging it verbatim every time is O(n²). Instead we track a
    per-agent cursor and emit only the messages new since that agent's previous
    request, plus the new response — each message lands exactly once.
    """

    def __init__(self, path: Path):
        self.path = path
        self._fh = path.open("w")
        self.messages: list[dict] = []   # the message stream (all instances)
        self._seen: dict[str, int] = {}  # agent_id → history messages already emitted
        self._seq: dict[str, int] = {}   # agent_id → next per-instance message index
        self.n_requests = 0

    def _emit(
        self, agent_id: str, kind: str, message: dict, cap: int, **extra: Any
    ) -> None:
        seq = self._seq.get(agent_id, 0)
        self._seq[agent_id] = seq + 1
        rec = {
            "event_type": "message",
            "agent_id": agent_id,
            "seq": seq,
            "id": f"{agent_id}#{seq}",  # stable identity for the projection's merge
            "kind": kind,
            **extra,
            "message": message,
        }
        self.messages.append(rec)
        # The cap bounds only the ON-DISK copy (a giant tool-return line); the
        # in-memory record stays full so the projection isn't corrupted.
        disk = {**rec, "message": _trim(message, cap)} if cap > 0 else rec
        self._fh.write(json.dumps(disk, default=str) + "\n")
        self._fh.flush()

    def log(
        self, *, request_messages: list[Any], response: Any, run_step: int = 0,
        duration_ms: float = 0.0, agent_id: str = "main",
    ) -> None:
        cap = _max_chars()
        # Delta of the request history: everything appended since this agent's
        # previous request (its prior response — already emitted — is skipped by
        # the +1 below, so this is the new request message(s), typically the
        # tool-returns). Dump only the slice, never the whole history.
        seen = self._seen.get(agent_id, 0)
        for dumped in ModelMessagesTypeAdapter.dump_python(
            request_messages[seen:], mode="json"
        ):
            self._emit(agent_id, dumped.get("kind", "request"), dumped, cap)
        self._seen[agent_id] = len(request_messages)
        # The new response is not yet in request_messages; emit it with its own
        # model + usage + timing, then advance the cursor past it so the next
        # request's delta doesn't re-log it.
        resp_dump = ModelMessagesTypeAdapter.dump_python([response], mode="json")[0]
        self._emit(
            agent_id, "response", resp_dump, cap,
            model=getattr(response, "model_name", None),
            usage=_usage_dict(getattr(response, "usage", None)),
            duration_ms=round(duration_ms, 1),
            run_step=run_step,
        )
        self._seen[agent_id] += 1
        self.n_requests += 1

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:  # noqa: BLE001 — logging must never break the run
            pass


# --- projection: tool_trace.jsonl (the run_stats / visualize contract) ----

def _main_messages(messages: list[dict]) -> list[dict]:
    """Messages from the orchestrator instance only, in conversation order.
    Nested gather agents stream to the same list (their own conversations); the
    trace is the MAIN conversation, so its projection must exclude them — else an
    interleaved gather message would land in the reconstructed main transcript."""
    return [m for m in messages if m.get("agent_id", "main") == "main"]


def _assistant_event(rec: dict) -> dict:
    """A `response` message record → an `assistant` trace event (text / tool_use /
    thinking), carrying the per-instance id + model + usage the visualizer keys on."""
    msg = rec.get("message") or {}
    content: list[dict] = []
    for part in msg.get("parts", []):
        pk = part.get("part_kind")
        if pk == "text":
            content.append({"type": "text", "text": part.get("content", "")})
        elif pk == "tool-call":
            content.append({
                "type": "tool_use",
                "name": part.get("tool_name", ""),
                "id": part.get("tool_call_id", ""),
                "input": part.get("args"),
            })
        elif pk == "thinking":
            content.append({"type": "thinking"})
    ev = {
        "type": "assistant",
        "message": {
            "id": rec.get("id"),
            "model": rec.get("model") or "",
            "usage": rec.get("usage") or {},
            "content": content,
        },
    }
    if msg.get("timestamp"):
        ev["timestamp"] = msg["timestamp"]
    return ev


def _user_event(rec: dict) -> dict | None:
    """A `request` message record → a `user` trace event carrying its tool_results,
    or None if it has none. The tool-return timestamp anchors visualize_run.py's
    per-phase wall-time bars."""
    msg = rec.get("message") or {}
    returns = [p for p in msg.get("parts", []) if p.get("part_kind") == "tool-return"]
    if not returns:
        return None
    ev = {
        "type": "user",
        "message": {"content": [{"type": "tool_result", "tool_name": p.get("tool_name", "")} for p in returns]},
    }
    ts = next((p.get("timestamp") for p in returns if p.get("timestamp")), None)
    if ts:
        ev["timestamp"] = ts
    return ev


def _trace_events(messages: list[dict]) -> list[dict]:
    """Project the main instance's message stream into the assistant/user events."""
    events: list[dict] = []
    for rec in _main_messages(messages):
        if rec.get("kind") == "response":
            events.append(_assistant_event(rec))
        else:
            user = _user_event(rec)
            if user:
                events.append(user)
    return events


def _usage_totals(messages: list[dict]) -> dict[str, int]:
    keys = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
    return {
        k: sum(int((r.get("usage") or {}).get(k, 0) or 0)
               for r in messages if r.get("kind") == "response")
        for k in keys
    }


def write_trace(run_dir: Path, messages: list[dict], *, wall_ms: float) -> None:
    """Project the message stream → `tool_trace.jsonl`. Post-mortem; cost is
    summed per response message at its own model's rate via scripts/pricing.py."""
    events = _trace_events(messages)
    totals = _usage_totals(messages)  # aggregate token counts across all instances
    # Price each response at ITS OWN model's rate, then sum: a run that dispatched
    # gather mixes Sonnet (main) and Haiku (gather), and Haiku is ~3x cheaper —
    # pricing the combined totals at one model's rate would over-report.
    total_cost = sum(
        usage_cost(r.get("model"), r.get("usage") or {})
        for r in messages if r.get("kind") == "response"
    )
    main_responses = sum(1 for r in _main_messages(messages) if r.get("kind") == "response")
    events.append({
        "type": "result",
        "duration_ms": round(wall_ms),
        "duration_api_ms": round(wall_ms),  # no separate API timing from the SDK
        "total_cost_usd": round(total_cost, 6),
        "num_turns": main_responses,  # matches the emitted main assistant events
        "usage": totals,
    })
    (run_dir / "tool_trace.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
