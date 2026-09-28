from __future__ import annotations

from defender._model import model
from typing import TYPE_CHECKING, Any, Protocol

# pydantic_ai names are `TYPE_CHECKING`-only: this package is imported by the runtime-free
# install. So `BuiltModel.model` is typed `Any` — a pydantic field annotated with a
# `TYPE_CHECKING`-only name leaves the class incomplete and fails at first construction.
if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

    from ..agent_role import AgentRole


@model(frozen=True)
class BuiltModel:

    #: A `pydantic_ai.models.Model`, typed `Any` (see the comment above the imports).
    model: Any
    #: `dict[str, Any]`, not `ModelSettings`: pydantic validates a `TypedDict` by its declared
    #: keys and would strip provider-specific extension keys (e.g. `openai_prompt_cache_key`).
    settings: dict[str, Any] | None


class Provider(Protocol):

    id: str
    api_key_var: str
    aliases: dict[str, str]
    prefixes: tuple[str, ...]

    def build_model(self, name: str) -> Model:
        ...

    def effort_for_role(self, name: str, role: AgentRole) -> str | None:
        """Takes the model as well as the role: whether an effort can be served depends on it."""
        ...

    def settings_for_effort(self, effort: str | None) -> ModelSettings | None:
        ...

    def cache_affinity(self, settings: ModelSettings | None, key: str) -> ModelSettings | None:
        """This provider's settings plus whatever it needs to keep `key`'s prompt prefix warm.

        Separate from `settings_for_effort`: effort is per role, known at model build; the key
        identifies the conversation and is known only at the agent's composition root.

        Providers whose caching needs no key return `settings` unchanged. `key` is an opaque
        routing hint, not a secret; cache reuse still requires an exact prefix match.
        """
        ...
