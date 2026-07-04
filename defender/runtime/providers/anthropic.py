"""The Anthropic serving infra — the native (non-OpenAI) protocol, keyed off
`ANTHROPIC_API_KEY`, serving `claude-*` models."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..agent_role import AgentRole

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

_ANTHROPIC_PREFIX = "anthropic:"

# The native effort domain (pydantic-ai `AnthropicModelSettings.anthropic_effort`),
# the same lever `claude -p --effort` set. `default` is the sentinel to omit the
# override (fall back to the model's own default).
_EFFORT_CHOICES = ("low", "medium", "high", "xhigh", "max", "default")


class AnthropicProvider:
    """Builds `AnthropicModel`s and applies Anthropic's three-part prompt cache.

    The pydantic-ai imports are lazy (inside the methods), so importing the
    providers package for routing / key-var metadata never requires the backend."""

    id: str = "anthropic"
    api_key_var: str = "ANTHROPIC_API_KEY"
    prefixes: tuple[str, ...] = ("claude-", _ANTHROPIC_PREFIX)

    def __init__(self) -> None:
        # Per-instance (not a class attr) so it mirrors OpenAICompatProvider and can't
        # alias across instances; empty because claude-* ids need no friendly aliases.
        self.aliases: dict[str, str] = {}
        self._cache: ModelSettings | None = None

    def build_model(self, name: str) -> Model:
        from pydantic_ai.models.anthropic import AnthropicModel

        return AnthropicModel(name.removeprefix(_ANTHROPIC_PREFIX))

    def _cache_settings(self) -> ModelSettings:
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
        # Memoized so the base is import-deferred yet built once (the role-invariant
        # cache preamble every claude settings object carries).
        if self._cache is None:
            from pydantic_ai.models.anthropic import AnthropicModelSettings

            self._cache = AnthropicModelSettings(
                anthropic_cache_instructions="1h",
                anthropic_cache_tool_definitions="1h",
                anthropic_cache="5m",
            )
        return self._cache

    def effort_for_role(self, role: AgentRole) -> str | None:
        # Anthropic exposes no role→effort policy — the cache preamble is the same for
        # every role and there is no per-role reasoning knob to cap. `None` omits the
        # `anthropic_effort` override for both MAIN and GATHER, so the role→settings path
        # `settings_for_effort(effort_for_role(role))` is cache-only for every role.
        return None

    def settings_for_effort(self, effort: str | None) -> ModelSettings | None:
        """Explicit effort → the native `anthropic_effort` knob (the same lever
        `claude -p --effort` set), on top of the three-part prompt cache. This is the
        equivalence-critical path for the judge: a BOUNDED effort mirrors what the
        `claude -p` judge ran under, rather than Sonnet's adaptive-by-default thinking
        (which, un-capped, both diverges and overruns). `None` (the canonical omit) and
        the tolerated `"default"` string both omit the override (model default)."""
        if effort is not None and effort not in _EFFORT_CHOICES:
            raise ValueError(
                f"unsupported Anthropic effort {effort!r}; expected one of {_EFFORT_CHOICES}"
            )
        from pydantic_ai.models.anthropic import AnthropicModelSettings

        # Copy the (role-independent) cache settings and add the effort — never mutate
        # the memoized cache object.
        merged = dict(self._cache_settings())
        if effort not in (None, "default"):
            merged["anthropic_effort"] = effort
        # ** expansion of a widened `dict[str, object]` into a TypedDict is a known mypy
        # limitation; the keys are exactly the cache settings + anthropic_effort.
        return AnthropicModelSettings(**merged)  # type: ignore[typeddict-item]
