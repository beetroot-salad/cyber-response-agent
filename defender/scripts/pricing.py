
from __future__ import annotations

PRICING = {
    "claude-sonnet-4-6": {"in": 3.0, "out": 15.0, "cache_w": 3.75, "cache_r": 0.30},
    "claude-haiku-4-5":  {"in": 1.0, "out":  5.0, "cache_w": 1.25, "cache_r": 0.10},
    # The three Fireworks rows below are the serverless STANDARD tier, read off each model's
    # own page (2026-08-07) as the triple Fireworks publishes: input / cached input / output.
    # Priority (+25%), Fast (+50%) and the US-only endpoint (+10%) are markups on these; we
    # call none of those routers, so none is carried here.
    #
    # `cache_w` equals `in` for every Fireworks row, and that is the price rather than a
    # placeholder: Fireworks caching is automatic and has no separate write price — the tokens
    # that populate a cache entry bill as ordinary input. Only the Anthropic rows above carry a
    # write premium, because only Anthropic charges one.
    "glm-5.2":           {"in": 1.4,  "out": 4.4,  "cache_w": 1.40, "cache_r": 0.14},
    "kimi-k2.6":         {"in": 0.95, "out": 4.0,  "cache_w": 0.95, "cache_r": 0.16},
    "kimi-k3":           {"in": 3.0,  "out": 15.0, "cache_w": 3.00, "cache_r": 0.30},
}


def model_key(model: str) -> str:
    if not model:
        return "claude-sonnet-4-6"
    m = model.lower()
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
