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
