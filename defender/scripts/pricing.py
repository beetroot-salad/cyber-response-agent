
from __future__ import annotations

import re

PRICING = {
    "claude-sonnet-4-6": {"in": 3.0, "out": 15.0, "cache_w": 3.75, "cache_r": 0.30},
    "claude-haiku-4-5":  {"in": 1.0, "out":  5.0, "cache_w": 1.25, "cache_r": 0.10},
    # Fireworks rows are the serverless Standard tier (input / cached input / output, USD per
    # M tokens); Priority, Fast and US-only markups are not used. `cache_w` equals `in` because
    # Fireworks caching has no separate write price.
    # `glm-5.2`, `kimi-k2.6` and `deepseek-v4-flash` are decommissioned but stay, so archived
    # traces that name them are still costed.
    "glm-5.2":           {"in": 1.4,  "out": 4.4,  "cache_w": 1.40, "cache_r": 0.14},
    "kimi-k2.6":         {"in": 0.95, "out": 4.0,  "cache_w": 0.95, "cache_r": 0.16},
    "kimi-k3":           {"in": 3.0,  "out": 15.0, "cache_w": 3.00, "cache_r": 0.30},
    # docs.fireworks.ai/serverless/pricing 2026-09-01, Standard: DeepSeek V4 Flash (0731).
    "deepseek-v4-flash": {"in": 0.22, "out": 0.66, "cache_w": 0.22, "cache_r": 0.007},
    # Provisional: copies 0731's price until the pricing page lists V4.1 (Fireworks already
    # routes the 0731 name to `deepseek-v4p1-flash`).
    "deepseek-v4.1-flash": {"in": 0.22, "out": 0.66, "cache_w": 0.22, "cache_r": 0.007},
    # docs.fireworks.ai/serverless/pricing 2026-09-01, Standard: GLM 5.3 Flash $0.15 / $0.03 / $0.50.
    "glm-5.3-flash":     {"in": 0.15, "out": 0.50, "cache_w": 0.15, "cache_r": 0.03},
    # docs.fireworks.ai/serverless/pricing 2026-09-09, Standard. Same as 5.2 except `cache_r`,
    # so billing 5.3 on 5.2's row would be quietly ~7% light on cache-heavy runs.
    "glm-5.3":           {"in": 1.40, "out": 4.40, "cache_w": 1.40, "cache_r": 0.26},
}


class UnknownModel(KeyError):
    """A model spelling no row claims. Raised rather than absorbed: a fallback to a similar or
    default row would produce a plausible but wrong bill."""


#: Every spelling that names a row, exactly. Fireworks writes `5p3` where its docs write `5.3`,
#: and a model may arrive as a bare alias, an `accounts/...` id or `fireworks:`-prefixed, so
#: spellings are enumerated rather than pattern-matched. A new model needs a new entry.
_ROW_BY_NAME = {
    "claude-sonnet-4-6": "claude-sonnet-4-6",
    "claude-haiku-4-5": "claude-haiku-4-5",
    "glm-5.2": "glm-5.2",
    "glm-5p2": "glm-5.2",
    "glm-5.3": "glm-5.3",
    "glm-5p3": "glm-5.3",
    "glm-5.3-flash": "glm-5.3-flash",
    "glm-5p3-flash": "glm-5.3-flash",
    "kimi-k2.6": "kimi-k2.6",
    "kimi-k2p6": "kimi-k2.6",
    "kimi-k3": "kimi-k3",
    "deepseek-v4-flash": "deepseek-v4-flash",
    "deepseek-v4.1-flash": "deepseek-v4.1-flash",
    "deepseek-v4p1-flash": "deepseek-v4.1-flash",
}

#: An Anthropic id carries a release date the price does not vary by.
_DATE_SUFFIX = re.compile(r"-\d{8}$")


def normalize_model(model: str) -> str:
    """A raw model string reduced to the spelling `_ROW_BY_NAME` is keyed on: strips the
    provider prefix, a Fireworks registry path and an Anthropic release date, none of which
    select a price."""
    m = model.lower().strip()
    for prefix in ("fireworks:", "anthropic:"):
        if m.startswith(prefix):
            m = m[len(prefix):]
    m = m.rsplit("/", 1)[-1]
    return _DATE_SUFFIX.sub("", m)


def model_key(model: str) -> str:
    """The pricing row `model` names. Raises `UnknownModel` when no row claims it.

    An empty string is the one absorbed case: no model was recorded on the call, which
    predates every provider in this table."""
    if not model:
        return "claude-sonnet-4-6"
    name = normalize_model(model)
    try:
        return _ROW_BY_NAME[name]
    except KeyError:
        raise UnknownModel(
            f"no pricing row for model {model!r} (normalized to {name!r}); add one to "
            f"PRICING and a spelling to _ROW_BY_NAME rather than letting it bill as a "
            f"neighbour. Known: {sorted(set(_ROW_BY_NAME.values()))}"
        ) from None


def usage_cost(model: str, usage: dict) -> float:
    """`model`'s bill for `usage`, or 0.0 when no row prices it.

    Zero rather than a raise because this runs per response inside a live run
    (`observe.write_trace`) and over every archived trace, and zero rather than a guessed rate
    because an obviously wrong total is better than a plausible one."""
    if not isinstance(usage, dict):
        return 0.0
    try:
        p = PRICING[model_key(model)]
    except UnknownModel:
        return 0.0
    return (
        usage.get("input_tokens", 0) * p["in"]
        + usage.get("output_tokens", 0) * p["out"]
        + usage.get("cache_creation_input_tokens", 0) * p["cache_w"]
        + usage.get("cache_read_input_tokens", 0) * p["cache_r"]
    ) / 1_000_000
