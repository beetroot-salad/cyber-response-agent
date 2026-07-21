
from __future__ import annotations

PRICING = {
    "claude-sonnet-4-6": {"in": 3.0, "out": 15.0, "cache_w": 3.75, "cache_r": 0.30},
    "claude-haiku-4-5":  {"in": 1.0, "out":  5.0, "cache_w": 1.25, "cache_r": 0.10},
    "glm-5.2":           {"in": 1.4, "out":  4.4, "cache_w": 1.40, "cache_r": 0.14},
    "kimi-k2.6":         {"in": 0.6, "out":  3.0, "cache_w": 0.60, "cache_r": 0.60},
}


def model_key(model: str) -> str:
    if not model:
        return "claude-sonnet-4-6"
    m = model.lower()
    if "glm" in m:
        return "glm-5.2"
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
