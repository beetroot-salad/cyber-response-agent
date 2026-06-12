"""Observability: the captured message stream → tool_trace.jsonl + a full dump.

Observability here is *code-level* — the PydanticAI message stream we already
own — not a hook. After a run we have `result.all_messages()` (every model
request/response, tool call, tool return) and `result.usage()` (exact token
counts). We serialize:

  - `tool_trace.jsonl` — `assistant`/`user` events + a trailing `result` event,
    the shape `scripts/run_stats.py` and `scripts/visualize_run.py` read. Both
    consume it with `.get(...)` defaults, so partial fidelity degrades, never
    crashes. Stream-json parity is intentionally partial.
  - `pai_messages.json` — the full structured message list, for rich debugging.

Token counts are exact; `total_cost_usd` is *computed* (the first-party API does
not return cost like `claude -p` did), so treat absolute cost as approximate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Approximate Anthropic list prices, USD per 1M tokens. Token counts are exact;
# this only affects the computed cost column. Update from anthropic.com/pricing.
_PRICES: dict[str, dict[str, float]] = {
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0, "cache_write": 3.75, "cache_read": 0.30},
    "claude-haiku-4-5": {"input": 1.0, "output": 5.0, "cache_write": 1.25, "cache_read": 0.10},
}
_DEFAULT_PRICE = _PRICES["claude-sonnet-4-6"]


def _usage_dict(usage: Any) -> dict[str, int]:
    """RunUsage → the tool_trace `usage` shape run_stats.py reads."""
    g = lambda n: int(getattr(usage, n, 0) or 0)  # noqa: E731
    return {
        "input_tokens": g("input_tokens"),
        "output_tokens": g("output_tokens"),
        "cache_read_input_tokens": g("cache_read_tokens"),
        "cache_creation_input_tokens": g("cache_write_tokens"),
    }


def _estimate_cost(u: dict[str, int], model: str) -> float:
    p = _PRICES.get(model, _DEFAULT_PRICE)
    return round(
        u["input_tokens"] / 1e6 * p["input"]
        + u["output_tokens"] / 1e6 * p["output"]
        + u["cache_creation_input_tokens"] / 1e6 * p["cache_write"]
        + u["cache_read_input_tokens"] / 1e6 * p["cache_read"],
        6,
    )


def _events_from_messages(messages: list[Any]) -> list[dict]:
    """Reconstruct assistant/user trace events from the message list, duck-typed
    on `part_kind` so we don't couple to concrete part classes."""
    events: list[dict] = []
    for msg in messages:
        parts = getattr(msg, "parts", []) or []
        kind = getattr(msg, "kind", "")  # 'request' | 'response'
        if kind == "response":
            content: list[dict] = []
            for part in parts:
                pk = getattr(part, "part_kind", "")
                if pk == "text":
                    content.append({"type": "text", "text": getattr(part, "content", "")})
                elif pk == "tool-call":
                    content.append({
                        "type": "tool_use",
                        "name": getattr(part, "tool_name", ""),
                        "input": getattr(part, "args", None),
                    })
                elif pk == "thinking":
                    content.append({"type": "thinking"})
            ts = getattr(msg, "timestamp", None)
            events.append({
                "type": "assistant",
                "message": {"content": content},
                **({"timestamp": ts.isoformat()} if hasattr(ts, "isoformat") else {}),
            })
        else:  # request — surface tool returns as `user` events (wall-time anchor)
            tool_results = [
                {"type": "tool_result", "tool_name": getattr(p, "tool_name", "")}
                for p in parts if getattr(p, "part_kind", "") == "tool-return"
            ]
            if tool_results:
                ts = getattr(msg, "timestamp", None) or _first_part_ts(parts)
                events.append({
                    "type": "user",
                    "message": {"content": tool_results},
                    **({"timestamp": ts.isoformat()} if hasattr(ts, "isoformat") else {}),
                })
    return events


def _first_part_ts(parts: list[Any]):
    for p in parts:
        ts = getattr(p, "timestamp", None)
        if ts is not None:
            return ts
    return None


def write_trace(
    run_dir: Path,
    messages: list[Any],
    usage: Any,
    *,
    model: str,
    wall_ms: float,
    num_turns: int,
) -> None:
    """Write tool_trace.jsonl (+ pai_messages.json) for the post-run tooling."""
    events = _events_from_messages(messages)
    u = _usage_dict(usage)
    events.append({
        "type": "result",
        "duration_ms": round(wall_ms),
        "duration_api_ms": round(wall_ms),  # no separate API timing from the SDK
        "total_cost_usd": _estimate_cost(u, model),
        "num_turns": num_turns,
        "usage": u,
    })
    (run_dir / "tool_trace.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in events)
    )
    # Full structured dump for rich debugging (best-effort; some parts may not be
    # JSON-trivial, so fall back to repr per message).
    dump = []
    for m in messages:
        try:
            dump.append(json.loads(json.dumps(m, default=lambda o: getattr(o, "__dict__", str(o)))))
        except (TypeError, ValueError):
            dump.append({"repr": repr(m)})
    (run_dir / "pai_messages.json").write_text(json.dumps(dump, indent=2, default=str))
