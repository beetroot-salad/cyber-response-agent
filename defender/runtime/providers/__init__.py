"""LLM serving providers for the PydanticAI runtime — one provider per *infra*.

A provider is the serving infra (not a model): `anthropic` (native protocol,
`claude-*`) and `fireworks` (OpenAI-compatible, serving the open models GLM 5.2
and Kimi K2.5). Models belong to a provider's model set, keyed by name. The
registry resolves a model name → provider from each provider's declarative
`aliases` + `prefixes`; construction and per-role settings live on the provider.

Public surface (`from defender.runtime import providers; providers.<name>`):
  - `provider_for(name)` / `provider_id_for(name)` — route a model name to its infra
  - `build(name, role)` — the `BuiltModel(model, settings)` the driver factory returns
  - `api_key_vars()` — every billable key var (run.py sources them, run_env strips them)
  - `PROVIDERS`, `ANTHROPIC`, `FIREWORKS`, `Provider`, `BuiltModel`

The heavy pydantic-ai imports are lazy inside `build`/`settings`, so importing this
package for routing / key-var metadata needs no model backend and no runtime extra.
"""
from __future__ import annotations

from ..agent_role import AgentRole
from .anthropic import AnthropicProvider
from .base import BuiltModel, Provider
from .openai_compat import OpenAICompatProvider

# The serving infras. `anthropic` is a peer, not the fallback — an unknown name
# fails loud (see `provider_for`). Fireworks serves the production defaults
# (`DEFAULT_MODEL = "glm-5.2"`, `DEFAULT_GATHER_MODEL = "kimi-k2.5"`); `glm-5p2` /
# `kimi-k2p5` mirror Fireworks' own id spelling. Any other Fireworks model is
# reachable via an explicit `fireworks:<id>`.
ANTHROPIC = AnthropicProvider()
FIREWORKS = OpenAICompatProvider(
    id="fireworks",
    base_url="https://api.fireworks.ai/inference/v1",
    api_key_var="FIREWORKS_API_KEY",
    aliases={
        "glm-5.2": "accounts/fireworks/models/glm-5p2",
        "glm-5p2": "accounts/fireworks/models/glm-5p2",
        "kimi-k2.5": "accounts/fireworks/models/kimi-k2p5",
        "kimi-k2p5": "accounts/fireworks/models/kimi-k2p5",
    },
    main_effort="low",       # MAIN loop (GLM 5.2)
    gather_effort="none",    # GATHER subagent — mechanical ES|QL
)
PROVIDERS: tuple[Provider, ...] = (ANTHROPIC, FIREWORKS)


def provider_for(name: str) -> Provider:
    """The serving infra for a model `name`: a friendly alias (case-insensitive)
    first, then an explicit prefix (`claude-`, `fireworks:`, …). Fail loud on no
    match — an unknown name is a typo, not a silent default to some provider."""
    low = name.lower()
    for p in PROVIDERS:
        if low in p.aliases:
            return p
    for p in PROVIDERS:
        if any(name.startswith(pre) for pre in p.prefixes):
            return p
    raise ValueError(
        f"unknown model {name!r}; expected a claude-* id or a Fireworks alias "
        "(glm-5.2 / kimi-k2.5) / fireworks:<id>"
    )


def provider_id_for(name: str) -> str:
    """The provider id (`"anthropic"` / `"fireworks"`) serving `name`."""
    return provider_for(name).id


def build(name: str, role: AgentRole) -> BuiltModel:
    """Construct the model for `name` + its per-role settings, paired. The driver's
    model factory returns this so build sites never re-derive a model's provider."""
    p = provider_for(name)
    return BuiltModel(p.build_model(name), p.settings(role))


def api_key_vars() -> set[str]:
    """Every billable provider key var — run.py sources the ones a run needs;
    run_common.run_env strips all of them from the bash tool's subprocess env."""
    return {p.api_key_var for p in PROVIDERS}


__all__ = [
    "ANTHROPIC",
    "FIREWORKS",
    "PROVIDERS",
    "BuiltModel",
    "Provider",
    "api_key_vars",
    "build",
    "provider_for",
    "provider_id_for",
]
