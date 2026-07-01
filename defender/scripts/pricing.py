"""Model token pricing — the one place the price table lives.

Token counts in `tool_trace.jsonl` are exact; cost is *computed* from them
(the first-party Anthropic API does not return a cost the way `claude -p` did).
This module is the single source for that computation — imported by the runtime
observability layer (to fill the `result` event's `total_cost_usd`) and by the
visualizer's data layer. Anthropic prices from anthropic.com/pricing; the
Fireworks-served GLM prices from fireworks.ai/pricing.
"""

from __future__ import annotations

# Per-million-token prices, USD. Anthropic pricing for claude-sonnet-4-6 /
# claude-haiku-4-5; Fireworks serverless pricing for the MAIN model GLM 5.2 (glm-5p2:
# $1.40 in / $0.14 cached-in / $4.40 out) and the GATHER model Kimi K2.5 (kimi-k2p5:
# $0.60 in / $3.00 out — size-based-priced on Fireworks with no separate cached rate,
# so `cache_r` = `in`). Fireworks caches automatically and does not bill cache writes
# separately (reports zero cache-write tokens), so `cache_w` mirrors `in` and is inert.
PRICING = {
    "claude-sonnet-4-6": {"in": 3.0, "out": 15.0, "cache_w": 3.75, "cache_r": 0.30},
    "claude-haiku-4-5":  {"in": 1.0, "out":  5.0, "cache_w": 1.25, "cache_r": 0.10},
    "glm-5.2":           {"in": 1.4, "out":  4.4, "cache_w": 1.40, "cache_r": 0.14},
    "kimi-k2.5":         {"in": 0.6, "out":  3.0, "cache_w": 0.60, "cache_r": 0.60},
}


def model_key(model: str) -> str:
    """Normalize a model id (which may carry a date suffix or a Fireworks
    `accounts/.../` path) to a PRICING key."""
    if not model:
        return "claude-sonnet-4-6"
    m = model.lower()
    if "glm" in m:
        return "glm-5.2"
    if "kimi" in m:
        return "kimi-k2.5"
    if "haiku" in m:
        return "claude-haiku-4-5"
    return "claude-sonnet-4-6"


def usage_cost(model: str, usage: dict) -> float:
    """USD cost for a usage block (`tool_trace.jsonl` key names)."""
    if not isinstance(usage, dict):
        return 0.0
    p = PRICING[model_key(model)]
    return (
        usage.get("input_tokens", 0) * p["in"]
        + usage.get("output_tokens", 0) * p["out"]
        + usage.get("cache_creation_input_tokens", 0) * p["cache_w"]
        + usage.get("cache_read_input_tokens", 0) * p["cache_r"]
    ) / 1_000_000
