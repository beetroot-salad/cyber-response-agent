from __future__ import annotations

from typing import TYPE_CHECKING

from defender._env import FatalConfigError, env_str

from ..agent_role import AgentRole

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

_REASONING_EFFORT_CHOICES = ("low", "medium", "high", "none", "default")
#: The effort a thinking-only model gets instead of `none`, which its API refuses with a 400.
_THINKING_ONLY_FLOOR = "low"
_MAIN_EFFORT_ENV = "DEFENDER_MAIN_REASONING_EFFORT"
_GATHER_EFFORT_ENV = "DEFENDER_GATHER_REASONING_EFFORT"


class OpenAICompatProvider:

    def __init__(
        self, id: str, base_url: str, api_key_var: str,
        aliases: dict[str, str], main_effort: str, gather_effort: str,
        prefixes: tuple[str, ...] | None = None,
        thinking_only: frozenset[str] = frozenset(),
    ) -> None:
        self.id = id
        self.base_url = base_url
        self.api_key_var = api_key_var
        self.aliases = {k.lower(): v for k, v in aliases.items()}
        self.prefixes = prefixes if prefixes is not None else (f"{id}:",)
        self._effort = {AgentRole.MAIN: main_effort, AgentRole.GATHER: gather_effort}
        #: Resolved model IDs (alias values), so `fireworks:` passthrough spellings match too.
        self.thinking_only = thinking_only

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

    def effort_for_role(self, name: str, role: AgentRole) -> str | None:
        """The role's effort for this model — a provider preference clamped to a model
        capability.

        A default `none` on a thinking-only model is clamped to the floor. An explicit env
        request for `none` is refused instead, so the operator's choice is not silently
        overridden."""
        import os

        is_gather = role is AgentRole.GATHER
        env = _GATHER_EFFORT_ENV if is_gather else _MAIN_EFFORT_ENV
        default = self._effort[AgentRole.GATHER if is_gather else AgentRole.MAIN]
        effort = env_str(env, default, choices=_REASONING_EFFORT_CHOICES)
        if effort == "none" and self._model_id(name) in self.thinking_only:
            if os.environ.get(env) is not None:
                raise FatalConfigError(
                    f"{env}=none names an effort {name!r} cannot serve: it is a thinking-only "
                    f"model and its API refuses a disabled reasoning_effort outright. Choose "
                    f"one of {_REASONING_EFFORT_CHOICES[:3]}, or 'default' to send none at all."
                )
            effort = _THINKING_ONLY_FLOOR
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

    def cache_affinity(self, settings: ModelSettings | None, key: str) -> ModelSettings | None:
        """Attach `key` as the request's `prompt_cache_key`.

        Fireworks caches prefixes per replica; the key is its documented routing hint so a
        conversation's turns land where the prefix is warm. Creates settings when `None` (the
        common case).
        """
        from pydantic_ai.models.openai import OpenAIChatModelSettings

        merged = dict(settings) if settings is not None else {}
        merged["openai_prompt_cache_key"] = key
        return OpenAIChatModelSettings(**merged)  # type: ignore[typeddict-item]
