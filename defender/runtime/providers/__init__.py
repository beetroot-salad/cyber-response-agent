from __future__ import annotations

from typing import TYPE_CHECKING

from ..agent_role import AgentRole
from .anthropic import AnthropicProvider
from .base import BuiltModel, Provider
from .openai_compat import OpenAICompatProvider

if TYPE_CHECKING:
    from pydantic_ai.settings import ModelSettings

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
        "kimi-k3": "accounts/fireworks/models/kimi-k3",
    },
    main_effort="low",
    gather_effort="none",
)
PROVIDERS: tuple[Provider, ...] = (ANTHROPIC, FIREWORKS)


def selectable_aliases() -> tuple[str, ...]:
    """One spelling per distinct model behind the Fireworks alias map, in declaration order.

    DERIVED rather than written out. The literal this replaced named the two models that
    happened to exist when it was typed, and nothing makes adding an alias update it — an
    operator who typos a model added later is then handed a list that omits it, and goes off
    to check whether it is supported at all. A list that cannot drift from the map it
    describes cannot do that.
    """
    seen: set[str] = set()
    names: list[str] = []
    for alias, target in FIREWORKS.aliases.items():
        if target not in seen:
            seen.add(target)
            names.append(alias)
    return tuple(names)


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
        f"({' / '.join(selectable_aliases())}) / fireworks:<id>"
    )


def provider_id_for(name: str) -> str:
    return provider_for(name).id


def effort_for_role(name: str, role: AgentRole) -> str | None:
    return provider_for(name).effort_for_role(role)


def build_for_effort(name: str, effort: str | None) -> BuiltModel:
    p = provider_for(name)
    return BuiltModel(p.build_model(name), p.settings_for_effort(effort))


def cache_affinity(
    name: str, settings: ModelSettings | None, key: str
) -> ModelSettings | None:
    """`settings` plus `name`'s provider's prompt-cache affinity hint for `key`.

    An UNROUTABLE name returns `settings` untouched instead of raising. The hint is an
    optimization — refusing to build an agent because a routing nicety could not be attached
    would turn a cache miss into a dead run — and every name a real run reaches has already
    been through `provider_for` in `run.py`'s all-roles preflight, which is where an unknown
    model is supposed to fail and does.
    """
    try:
        provider = provider_for(name)
    except ValueError:
        return settings
    return provider.cache_affinity(settings, key)


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
    "cache_affinity",
    "effort_for_role",
    "provider_for",
    "provider_id_for",
    "selectable_aliases",
]
