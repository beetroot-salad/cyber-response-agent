"""The Anthropic serving infra — the native (non-OpenAI) protocol, keyed off
`ANTHROPIC_API_KEY`, serving `claude-*` models."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..agent_role import AgentRole

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

_ANTHROPIC_PREFIX = "anthropic:"


class AnthropicProvider:
    """Builds `AnthropicModel`s and applies Anthropic's three-part prompt cache.

    The pydantic-ai imports are lazy (inside the methods), so importing the
    providers package for routing / key-var metadata never requires the backend."""

    id: str = "anthropic"
    api_key_var: str = "ANTHROPIC_API_KEY"
    aliases: dict[str, str] = {}
    prefixes: tuple[str, ...] = ("claude-", _ANTHROPIC_PREFIX)

    def __init__(self) -> None:
        self._cache: ModelSettings | None = None

    def build_model(self, name: str) -> Model:
        from pydantic_ai.models.anthropic import AnthropicModel

        model_id = name[len(_ANTHROPIC_PREFIX):] if name.startswith(_ANTHROPIC_PREFIX) else name
        return AnthropicModel(model_id)

    def settings(self, role: AgentRole) -> ModelSettings | None:
        # Three-part caching (same for every role/claude model). The byte-stable
        # preamble — the SKILL system prompt (~9K tokens, re-sent every request) and
        # the tool schemas — is cached at 1h: it's written ~once and must survive the
        # one gap that can exceed 5m (a long gather sub-run blocks the main loop while
        # no main request refreshes its cache). The growing message tail uses
        # `anthropic_cache` — a top-level breakpoint the server moves forward as the
        # conversation grows — at 5m: the tail is re-read on the very next turn (max
        # main-loop gap is bash's 120s timeout, always < 5m, and each read slides the
        # TTL), and each turn writes only the new delta, so 5m's 1.25x write beats
        # 1h's 2x on every one of up to DEFAULT_REQUEST_LIMIT turns. Budget: the
        # automatic breakpoint claims one of Anthropic's 4 cache-point slots, leaving
        # 3 for explicit ones; instructions(1) + tools(1) = 2, within budget
        # (pydantic-ai trims excess newest-first if it's ever exceeded). Verify via the
        # per-response cache_read/creation token counts already logged in observe.py.
        # Memoized so the settings object is import-deferred yet identity-stable.
        if self._cache is None:
            from pydantic_ai.models.anthropic import AnthropicModelSettings

            self._cache = AnthropicModelSettings(
                anthropic_cache_instructions="1h",
                anthropic_cache_tool_definitions="1h",
                anthropic_cache="5m",
            )
        return self._cache
