from __future__ import annotations

from typing import TYPE_CHECKING, cast

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
    # Only models Fireworks still serves; an unlisted name fails at `provider_for` with the
    # alias list rather than at first dispatch with a 404.
    aliases={
        "glm-5.3": "accounts/fireworks/models/glm-5p3",
        "glm-5p3": "accounts/fireworks/models/glm-5p3",
        "glm-5.3-flash": "accounts/fireworks/models/glm-5p3-flash",
        "glm-5p3-flash": "accounts/fireworks/models/glm-5p3-flash",
        "kimi-k3": "accounts/fireworks/models/kimi-k3",
        # Fireworks spells 4.1 as `v4p1`; the pre-4.1 `deepseek-v4-flash` id is a compatibility
        # route to the same model until 2026-09-25, so it gets no alias of its own.
        "deepseek-v4.1-flash": "accounts/fireworks/models/deepseek-v4p1-flash",
        "deepseek-v4p1-flash": "accounts/fireworks/models/deepseek-v4p1-flash",
    },
    main_effort="low",
    gather_effort="none",
    # GLM 5.3 and its Flash variant always reason; the API refuses `none`, so gather's `none`
    # runs at `low` on them.
    thinking_only=frozenset({
        "accounts/fireworks/models/glm-5p3",
        "accounts/fireworks/models/glm-5p3-flash",
    }),
)
PROVIDERS: tuple[Provider, ...] = (ANTHROPIC, FIREWORKS)


def selectable_aliases() -> tuple[str, ...]:
    """One spelling per distinct model behind the Fireworks alias map, in declaration order.

    Derived so newly added models are never omitted.
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
    return provider_for(name).effort_for_role(name, role)


def build_for_effort(name: str, effort: str | None) -> BuiltModel:
    p = provider_for(name)
    # `BuiltModel.settings` is typed as a plain dict so provider extension keys survive.
    return BuiltModel(p.build_model(name), cast("dict | None", p.settings_for_effort(effort)))


def cache_affinity(
    name: str, settings: ModelSettings | None, key: str
) -> ModelSettings | None:
    """`settings` plus `name`'s provider's prompt-cache affinity hint for `key`.

    An unroutable name returns `settings` untouched: the hint is an optimization, and unknown
    models already fail in `run.py`'s preflight.
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
