
from __future__ import annotations

import re

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
    # docs.fireworks.ai/serverless/pricing 2026-09-01, Standard tier: DeepSeek V4 Flash (0731)
    # $0.22 in / $0.007 cached / $0.66 out per M. (An earlier row here used the TRAINING-API
    # table's prefill/sample prices by mistake — 8x too high.) Experiment invlang-clerk-986 arm D.
    "deepseek-v4-flash": {"in": 0.22, "out": 0.66, "cache_w": 0.22, "cache_r": 0.007},
    # PROVISIONAL (2026-09-11): Fireworks serves `deepseek-v4p1-flash` and routes the 0731 name
    # to it, but the pricing page still lists only V4 Flash 0731. This row copies 0731's until
    # the page names a V4.1 price; a run costed on it before then is costed on that assumption.
    "deepseek-v4.1-flash": {"in": 0.22, "out": 0.66, "cache_w": 0.22, "cache_r": 0.007},
    # docs.fireworks.ai/serverless/pricing 2026-09-01, Standard: GLM 5.3 Flash $0.15 / $0.03 / $0.50.
    "glm-5.3-flash":     {"in": 0.15, "out": 0.50, "cache_w": 0.15, "cache_r": 0.03},
    # docs.fireworks.ai/serverless/pricing 2026-09-09, Standard: GLM 5.3 $1.40 / $0.26 / $4.40.
    # IDENTICAL to 5.2 on input and output, and that is the trap: only `cache_r` differs
    # (0.26 vs 0.14), so 5.3 billed on 5.2's row costs out ~7% light on a cache-heavy run
    # and nothing downstream reads as wrong.
    "glm-5.3":           {"in": 1.40, "out": 4.40, "cache_w": 1.40, "cache_r": 0.26},
}


class UnknownModel(KeyError):
    """A model spelling no row claims. Raised rather than absorbed: every silent fallback this
    table has had cost a real run its real number. The generic `"glm" in m` branch billed GLM
    5.3 on 5.2's row — right on input and output, wrong only on cached input, so the run read
    as priced (#1023). The catch-all `return "claude-sonnet-4-6"` under it was worse: it
    answered for EVERY unrecognised name, including any `fireworks:` passthrough, at the most
    expensive rate in the table."""


#: Every spelling that names a row, exactly. Fireworks writes `5p3` where its own docs write
#: `5.3`, and a model arrives here as a bare alias, a full `accounts/...` id, or a
#: `fireworks:`-prefixed one — so the spellings are enumerated rather than pattern-matched.
#: A new model is a new pair here; it is NOT absorbed by a neighbour whose name it contains.
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
    """A raw model string reduced to the one spelling `_ROW_BY_NAME` is keyed on.

    Strips only what genuinely does not select a price: the provider prefix a caller may have
    typed, the registry path a Fireworks id carries, and an Anthropic release date. Everything
    left has to match a row EXACTLY."""
    m = model.lower().strip()
    for prefix in ("fireworks:", "anthropic:"):
        if m.startswith(prefix):
            m = m[len(prefix):]
    m = m.rsplit("/", 1)[-1]
    return _DATE_SUFFIX.sub("", m)


def model_key(model: str) -> str:
    """The pricing row `model` names. Raises `UnknownModel` when no row claims it.

    An empty string is the one absorbed case and it is a DIFFERENT question: it means no model
    was recorded on the call at all, which predates every provider in this table."""
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

    A zero is the honest answer to "what does this cost?" when the table cannot say, and it is
    deliberately not a guess: this runs per-response inside a live run (`observe.write_trace`)
    and on every archived trace the visualizers read, so raising would cost a finished
    investigation its trace over a number nobody is billed on. A zero total reads as WRONG to
    anyone looking at it; the Sonnet-rate fallback this replaces read as correct."""
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
