"""Observability for the PydanticAI runtime: one boundary log, projected views.

**Single source of truth.** Every model API request is logged at the request
boundary (the driver's `wrap_model_request` hook → `RequestLogger.log`) to
`llm_requests.jsonl` — full request input, response output, usage, and timing,
written *live* (flushed per request) so a crash mid-run still leaves a complete
audit of every request that finished. This is the debugging log:
`event_type:"model_request"`, one line per API call.

Everything else is a **projection** of those records — same data, re-tagged:

  - `tool_trace.jsonl` — the consumer contract `run_stats.py` / `visualize_run.py`
    read (`assistant`/`user`/`result` events). Built post-mortem by replaying the
    logged records; the trailing `result` event's `total_cost_usd` is computed
    from the exact token counts via `scripts/pricing.py` (the first-party API does
    not return a cost the way `claude -p` did).

To add another view (a tool-only audit, a cost-by-phase rollup), write another
projection over `RequestLogger.records` — don't add another logging site.
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
    """Per-string cap for logged request *input*; 0 (default) = full fidelity.
    The full conversation is replayed on every request, so a long run logs it
    O(n²) times; set DEFENDER_LLM_LOG_MAX_CHARS to bound that when debugging."""
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
    """RequestUsage/RunUsage → the `tool_trace.jsonl` usage key shape (the names
    run_stats.py and pricing.usage_cost read)."""
    g = lambda n: int(getattr(usage, n, 0) or 0)  # noqa: E731
    return {
        "input_tokens": g("input_tokens"),
        "output_tokens": g("output_tokens"),
        "cache_read_input_tokens": g("cache_read_tokens"),
        "cache_creation_input_tokens": g("cache_write_tokens"),
    }


class RequestLogger:
    """Appends one record per model API request to `llm_requests.jsonl`, live and
    flushed, and keeps the records in memory for post-run projection. Open one per
    run; the driver's `wrap_model_request` hook calls `log` around each call."""

    def __init__(self, path: Path):
        self.path = path
        self._fh = path.open("w")
        self.records: list[dict] = []

    def log(
        self, *, request_messages: list[Any], response: Any, run_step: int, duration_ms: float
    ) -> None:
        cap = _max_chars()
        record = {
            "event_type": "model_request",
            "run_step": run_step,
            "model": getattr(response, "model_name", None),
            "duration_ms": round(duration_ms, 1),
            "usage": _usage_dict(getattr(response, "usage", None)),
            # full fidelity via the message type adapter (the exact shape the
            # projections below read back); input is the whole growing history.
            "input": _trim(ModelMessagesTypeAdapter.dump_python(request_messages, mode="json"), cap),
            "output": ModelMessagesTypeAdapter.dump_python([response], mode="json")[0],
        }
        self.records.append(record)
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:  # noqa: BLE001 — logging must never break the run
            pass


# --- projection: tool_trace.jsonl (the run_stats / visualize contract) ----

def _assistant_event(msg: dict) -> dict:
    """A `response` message → an `assistant` trace event (text / tool_use / thinking)."""
    content: list[dict] = []
    for part in msg.get("parts", []):
        pk = part.get("part_kind")
        if pk == "text":
            content.append({"type": "text", "text": part.get("content", "")})
        elif pk == "tool-call":
            content.append({
                "type": "tool_use",
                "name": part.get("tool_name", ""),
                "input": part.get("args"),
            })
        elif pk == "thinking":
            content.append({"type": "thinking"})
    ev = {"type": "assistant", "message": {"content": content}}
    if msg.get("timestamp"):
        ev["timestamp"] = msg["timestamp"]
    return ev


def _user_event(msg: dict) -> dict | None:
    """A `request` message → a `user` trace event carrying its tool_results, or
    None if it has none. The tool-return timestamp anchors visualize_run.py's
    per-phase wall-time bars."""
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


def _full_messages(records: list[dict]) -> list[dict]:
    """The complete conversation = the last request's input (all prior history)
    plus its response — equivalent to `run.all_messages()`. A tool-return produced
    *after* the final model request rides in no request's input, so it is omitted;
    runs almost always end on the final assistant message, so this is negligible."""
    if not records:
        return []
    last = records[-1]
    return list(last.get("input", [])) + [last["output"]]


def _trace_events(records: list[dict]) -> list[dict]:
    """Project the boundary records into the assistant/user event stream."""
    events: list[dict] = []
    for msg in _full_messages(records):
        if msg.get("kind") == "response":
            events.append(_assistant_event(msg))
        else:
            user = _user_event(msg)
            if user:
                events.append(user)
    return events


def _usage_totals(records: list[dict]) -> dict[str, int]:
    keys = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
    return {k: sum(int(r.get("usage", {}).get(k, 0) or 0) for r in records) for k in keys}


def write_trace(run_dir: Path, records: list[dict], *, model: str, wall_ms: float) -> None:
    """Project `llm_requests.jsonl` records → `tool_trace.jsonl`. Post-mortem;
    cost is computed from the exact token totals via scripts/pricing.py."""
    events = _trace_events(records)
    totals = _usage_totals(records)
    events.append({
        "type": "result",
        "duration_ms": round(wall_ms),
        "duration_api_ms": round(wall_ms),  # no separate API timing from the SDK
        "total_cost_usd": round(usage_cost(model, totals), 6),
        "num_turns": len(records),
        "usage": totals,
    })
    (run_dir / "tool_trace.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
