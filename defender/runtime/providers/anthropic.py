from __future__ import annotations

from typing import TYPE_CHECKING

from ..agent_role import AgentRole

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

_ANTHROPIC_PREFIX = "anthropic:"

_EFFORT_CHOICES = ("low", "medium", "high", "xhigh", "max", "default")


class AnthropicProvider:

    id: str = "anthropic"
    api_key_var: str = "ANTHROPIC_API_KEY"
    prefixes: tuple[str, ...] = ("claude-", _ANTHROPIC_PREFIX)

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self._cache: ModelSettings | None = None

    def build_model(self, name: str) -> Model:
        from pydantic_ai.models.anthropic import AnthropicModel

        return AnthropicModel(name.removeprefix(_ANTHROPIC_PREFIX))

    def _cache_settings(self) -> ModelSettings:
        if self._cache is None:
            from pydantic_ai.models.anthropic import AnthropicModelSettings

            self._cache = AnthropicModelSettings(
                anthropic_cache_instructions="1h",
                anthropic_cache_tool_definitions="1h",
                anthropic_cache="5m",
            )
        return self._cache

    def effort_for_role(self, role: AgentRole) -> str | None:
        return None

    def settings_for_effort(self, effort: str | None) -> ModelSettings | None:
        if effort is not None and effort not in _EFFORT_CHOICES:
            raise ValueError(
                f"unsupported Anthropic effort {effort!r}; expected one of {_EFFORT_CHOICES}"
            )
        from pydantic_ai.models.anthropic import AnthropicModelSettings

        merged = dict(self._cache_settings())
        if effort not in (None, "default"):
            merged["anthropic_effort"] = effort
        return AnthropicModelSettings(**merged)  # type: ignore[typeddict-item]
