from __future__ import annotations

from typing import TYPE_CHECKING

from defender._env import FatalConfigError, env_str

from ..agent_role import AgentRole

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

_REASONING_EFFORT_CHOICES = ("low", "medium", "high", "none", "default")
#: What a THINKING-ONLY model answers a `reasoning_effort` of `none` with. Not a preference:
#: the API refuses the request outright ("GLM-5.3 is a thinking-only model; disabling thinking
#: is not supported"), so the run dies on its first dispatch to that lane with an HTTP 400
#: naming the model rather than the mismatch. `low` is the cheapest thinking such a model has.
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
        #: Resolved model IDs — the alias map's VALUES — because that is what `_model_id`
        #: answers and what the API sees; keying on the alias would miss every `fireworks:`
        #: passthrough spelling of the same model, which is exactly how #1023 reached it.
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
        """The role's effort for THIS model — a provider preference clamped to a model
        capability.

        Keyed on the model and not just the role because `gather_effort="none"` is one value
        the provider states for every model it serves, and `none` is not a thing every model
        can do. The shipped default is a PREFERENCE ("gather wants the cheapest thinking on
        offer") and the floor is a CAPABILITY, so clamping one to the other changes nothing
        the operator asked for.

        An EXPLICIT env request is different and is refused rather than clamped: an operator
        who typed `none` for a thinking-only model has named something the model cannot do,
        and answering `low` would hide the one thing they wrote."""
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

        Fireworks prompt caching is on by default and needs no opt-in. What it cannot do by
        itself is ROUTING: cached prefixes are local to a replica, so a conversation whose
        turns land on different replicas re-pays for a prefix already warm elsewhere. The key
        is the documented affinity hint for that, in the OpenAI spelling Fireworks reads.

        A `None` settings object is the common case (the review lenses and any role at
        `default` effort resolve to no settings), so the key must be able to CREATE the
        settings rather than only merge into them.
        """
        from pydantic_ai.models.openai import OpenAIChatModelSettings

        merged = dict(settings) if settings is not None else {}
        merged["openai_prompt_cache_key"] = key
        return OpenAIChatModelSettings(**merged)  # type: ignore[typeddict-item]
