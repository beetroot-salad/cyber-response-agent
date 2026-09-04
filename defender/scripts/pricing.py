
from __future__ import annotations

PRICING = {
    "claude-sonnet-4-6": {"in": 3.0, "out": 15.0, "cache_w": 3.75, "cache_r": 0.30},
    "claude-haiku-4-5":  {"in": 1.0, "out":  5.0, "cache_w": 1.25, "cache_r": 0.10},
    # The three Fireworks rows below are the serverless STANDARD tier, read off each model's own
    # page (2026-08-07) as the triple Fireworks publishes: input / cached input / output.
    # Priority (+25%), Fast (+50%) and the US-only endpoint (+10%) are markups on these; we call
    # none of those routers, so none is carried here.
    #
    # `cache_w` equals `in` for every Fireworks row — that is the price, not a placeholder:
    # Fireworks caching is automatic with no separate write price, so cache-populating tokens
    # bill as ordinary input. Only the Anthropic rows above carry a write premium.
    "glm-5.2":           {"in": 1.4,  "out": 4.4,  "cache_w": 1.40, "cache_r": 0.14},
    "kimi-k2.6":         {"in": 0.95, "out": 4.0,  "cache_w": 0.95, "cache_r": 0.16},
    "kimi-k3":           {"in": 3.0,  "out": 15.0, "cache_w": 3.00, "cache_r": 0.30},
    # docs.fireworks.ai/serverless/pricing 2026-09-01, Standard tier. The clerk's model (#996).
    "glm-5.3-flash":     {"in": 0.15, "out": 0.50, "cache_w": 0.15, "cache_r": 0.03},
}


def model_key(model: str) -> str:
    if not model:
        return "claude-sonnet-4-6"
    m = model.lower()
    # Must precede the generic glm branch, or 5.3 Flash bills at 5.2's rate.
    if "glm-5p3-flash" in m or "glm-5.3-flash" in m:
        return "glm-5.3-flash"
    if "glm" in m:
        return "glm-5.2"
    # Must precede the generic kimi branch, or K3 bills at K2.6's rate.
    if "kimi-k3" in m:
        return "kimi-k3"
    if "kimi" in m:
        return "kimi-k2.6"
    if "haiku" in m:
        return "claude-haiku-4-5"
    return "claude-sonnet-4-6"


def usage_cost(model: str, usage: dict) -> float:
    if not isinstance(usage, dict):
        return 0.0
    p = PRICING[model_key(model)]
    return (
        usage.get("input_tokens", 0) * p["in"]
        + usage.get("output_tokens", 0) * p["out"]
        + usage.get("cache_creation_input_tokens", 0) * p["cache_w"]
        + usage.get("cache_read_input_tokens", 0) * p["cache_r"]
    ) / 1_000_000
