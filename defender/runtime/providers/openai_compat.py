from __future__ import annotations

from typing import TYPE_CHECKING

from defender._env import env_str

from ..agent_role import AgentRole

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

_REASONING_EFFORT_CHOICES = ("low", "medium", "high", "none", "default")
_MAIN_EFFORT_ENV = "DEFENDER_MAIN_REASONING_EFFORT"
_GATHER_EFFORT_ENV = "DEFENDER_GATHER_REASONING_EFFORT"


class OpenAICompatProvider:

    def __init__(
        self, id: str, base_url: str, api_key_var: str,
        aliases: dict[str, str], main_effort: str, gather_effort: str,
        prefixes: tuple[str, ...] | None = None,
    ) -> None:
        self.id = id
        self.base_url = base_url
        self.api_key_var = api_key_var
        self.aliases = {k.lower(): v for k, v in aliases.items()}
        self.prefixes = prefixes if prefixes is not None else (f"{id}:",)
        self._effort = {AgentRole.MAIN: main_effort, AgentRole.GATHER: gather_effort}

    def _model_id(self, name: str) -> str:
        alias = self.aliases.get(name.lower())
        if alias is not None:
            return alias
        for pre in self.prefixes:
            if name.startswith(pre):
                return name[len(pre):]
        return name

    def build_model(self, name: str) -> Model:
        import os

        api_key = os.environ.get(self.api_key_var)
        if not api_key:
            raise RuntimeError(
                f"model {name!r} needs {self.api_key_var} — set it in <repo>/.env or "
                f"$DEFENDER_ENV_FILE ({self.id} bills its OpenAI-compatible API)."
            )
        try:
            from pydantic_ai.models.openai import OpenAIChatModel
            from pydantic_ai.providers.openai import OpenAIProvider
        except ImportError as e:
            raise RuntimeError(
                f"the {self.id} (OpenAI-compatible) path needs the openai extra — "
                "reinstall defender with "
                "`uv pip install --python .venv/bin/python -e '.[runtime]'`."
            ) from e
        return OpenAIChatModel(
            self._model_id(name),
            provider=OpenAIProvider(base_url=self.base_url, api_key=api_key),
        )

    def effort_for_role(self, role: AgentRole) -> str | None:
        is_gather = role is AgentRole.GATHER
        env = _GATHER_EFFORT_ENV if is_gather else _MAIN_EFFORT_ENV
        default = self._effort[AgentRole.GATHER if is_gather else AgentRole.MAIN]
        effort = env_str(env, default, choices=_REASONING_EFFORT_CHOICES)
        return None if effort == "default" else effort

    def settings_for_effort(self, effort: str | None) -> ModelSettings | None:
        if effort is not None and effort not in _REASONING_EFFORT_CHOICES:
            raise ValueError(
                f"unsupported reasoning_effort {effort!r}; "
                f"expected one of {_REASONING_EFFORT_CHOICES}"
            )
        if effort in (None, "default"):
            return None
        from pydantic_ai.models.openai import OpenAIChatModelSettings

        return OpenAIChatModelSettings(extra_body={"reasoning_effort": effort})
