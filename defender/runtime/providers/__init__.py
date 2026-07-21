from __future__ import annotations

from ..agent_role import AgentRole
from .anthropic import AnthropicProvider
from .base import BuiltModel, Provider
from .openai_compat import OpenAICompatProvider

ANTHROPIC = AnthropicProvider()
FIREWORKS = OpenAICompatProvider(
    id="fireworks",
    base_url="https://api.fireworks.ai/inference/v1",
    api_key_var="FIREWORKS_API_KEY",
    aliases={
        "glm-5.2": "accounts/fireworks/models/glm-5p2",
        "glm-5p2": "accounts/fireworks/models/glm-5p2",
        "kimi-k2.6": "accounts/fireworks/models/kimi-k2p6",
        "kimi-k2p6": "accounts/fireworks/models/kimi-k2p6",
    },
    main_effort="low",
    gather_effort="none",
)
PROVIDERS: tuple[Provider, ...] = (ANTHROPIC, FIREWORKS)


def provider_for(name: str) -> Provider:
    low = name.lower()
    for p in PROVIDERS:
        if low in p.aliases:
            return p
    for p in PROVIDERS:
        if any(name.startswith(pre) for pre in p.prefixes):
            return p
    raise ValueError(
        f"unknown model {name!r}; expected a claude-* id or a Fireworks alias "
        "(glm-5.2 / kimi-k2.6) / fireworks:<id>"
    )


def provider_id_for(name: str) -> str:
    return provider_for(name).id


def effort_for_role(name: str, role: AgentRole) -> str | None:
    return provider_for(name).effort_for_role(role)


def build_for_effort(name: str, effort: str | None) -> BuiltModel:
    p = provider_for(name)
    return BuiltModel(p.build_model(name), p.settings_for_effort(effort))


def api_key_vars() -> set[str]:
    return {p.api_key_var for p in PROVIDERS}


__all__ = [
    "ANTHROPIC",
    "FIREWORKS",
    "PROVIDERS",
    "BuiltModel",
    "Provider",
    "api_key_vars",
    "build_for_effort",
    "effort_for_role",
    "provider_for",
    "provider_id_for",
]
