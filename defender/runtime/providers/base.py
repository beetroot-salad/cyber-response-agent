from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

    from ..agent_role import AgentRole


@dataclass(frozen=True)
class BuiltModel:

    model: Model
    settings: ModelSettings | None


class Provider(Protocol):

    id: str
    api_key_var: str
    aliases: dict[str, str]
    prefixes: tuple[str, ...]

    def build_model(self, name: str) -> Model:
        ...

    def effort_for_role(self, role: AgentRole) -> str | None:
        ...

    def settings_for_effort(self, effort: str | None) -> ModelSettings | None:
        ...

    def cache_affinity(self, settings: ModelSettings | None, key: str) -> ModelSettings | None:
        """This provider's settings plus whatever it needs to keep `key`'s prompt prefix warm.

        SEPARATE from `settings_for_effort` because the two are keyed on different things:
        effort is a property of the ROLE, known when the model is built; the affinity key
        identifies the CONVERSATION and is only known at the agent's composition root.
        Folding it in would put a per-call identity into the `MakeModel` seam, which every
        engine in the tree passes as a two-positional-argument callable.

        Providers whose caching needs no key return `settings` unchanged. `key` is an opaque
        routing hint, never a secret: it only steers which replica serves the request, and a
        cache entry is still reused only on an exact prefix match.
        """
        ...
