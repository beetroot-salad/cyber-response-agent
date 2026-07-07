"""OpenAI-compatible serving infra — the generic provider class behind the
OpenAI chat protocol. One class, parameterized per infra: Fireworks (open models
GLM/Kimi) is a configured instance in `__init__.py`; a future `openai` (gpt-*)
instance would be another. Each instance carries its own `base_url`, key var, and
model set, so a second OpenAI-compatible endpoint is data, not a new class."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender._env import env_str

from ..agent_role import AgentRole

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

# reasoning_effort is a closed enum; the sentinel `default` omits the param (falls
# back to the provider's own full-reasoning default). Read via env_str(choices=…) so
# a typo'd or empty operator value fails loud at startup, not silently forwarded.
_REASONING_EFFORT_CHOICES = ("low", "medium", "high", "none", "default")
_MAIN_EFFORT_ENV = "DEFENDER_MAIN_REASONING_EFFORT"
_GATHER_EFFORT_ENV = "DEFENDER_GATHER_REASONING_EFFORT"


class OpenAICompatProvider:
    """An OpenAI-compatible serving infra. Builds `OpenAIChatModel`s against
    `base_url`, keyed off `api_key_var`, and applies per-role `reasoning_effort`.

    Reasoning models (GLM, Kimi, …) reason by default and bill that thinking as
    output tokens — a big cost/latency driver — so effort is capped by ROLE: the
    per-role default (`main_effort`/`gather_effort`) is overridable via
    `DEFENDER_MAIN_REASONING_EFFORT` / `DEFENDER_GATHER_REASONING_EFFORT`
    (`low`|`medium`|`high`|`none`, or `default` to omit the param). The pydantic-ai
    imports are lazy so importing the package for routing/key metadata needs no
    openai extra."""

    def __init__(
        self, id: str, base_url: str, api_key_var: str,
        aliases: dict[str, str], main_effort: str, gather_effort: str,
        prefixes: tuple[str, ...] | None = None,
    ) -> None:
        self.id = id
        self.base_url = base_url
        self.api_key_var = api_key_var
        # Friendly name (lowercased) → bare model id.
        self.aliases = {k.lower(): v for k, v in aliases.items()}
        self.prefixes = prefixes if prefixes is not None else (f"{id}:",)
        self._effort = {AgentRole.MAIN: main_effort, AgentRole.GATHER: gather_effort}

    def _model_id(self, name: str) -> str:
        """The bare model id for a name this provider serves: a friendly alias, or a
        `<id>:`-prefixed raw id with the prefix stripped."""
        alias = self.aliases.get(name.lower())
        if alias is not None:
            return alias
        for pre in self.prefixes:
            if name.startswith(pre):
                return name[len(pre):]
        return name  # already bare (defensive; the registry routes by alias/prefix)

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
        except ImportError as e:  # the openai extra isn't installed
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
        # GATHER vs. everything-else(=MAIN): pick the env knob and its default from the
        # SAME branch so a future third AgentRole degrades to the MAIN effort (as the
        # env line already does) instead of KeyError-ing on the `self._effort[role]` lookup.
        is_gather = role is AgentRole.GATHER
        env = _GATHER_EFFORT_ENV if is_gather else _MAIN_EFFORT_ENV
        default = self._effort[AgentRole.GATHER if is_gather else AgentRole.MAIN]
        # env_str fails loud (FatalConfigError) on a typo'd or empty value: an
        # operator knob misconfig should surface at startup, not silently forward a
        # bad reasoning_effort to the API — nor, on an empty string, drop the cost cap.
        effort = env_str(env, default, choices=_REASONING_EFFORT_CHOICES)
        # Normalize the `default` sentinel to None — the single canonical OMIT spelling
        # (#495), so only one omit value (None) ever reaches an AgentDefinition's effort. The
        # EXPLICIT `none` (reasoning disabled — the gather default) is distinct and
        # survives verbatim: a set knob, not an absent one.
        return None if effort == "default" else effort

    def settings_for_effort(self, effort: str | None) -> ModelSettings | None:
        """Explicit reasoning effort → the `extra_body.reasoning_effort` shape. `None`
        (the canonical omit) and the tolerated `"default"` string both omit the param
        (fall back to the provider's own full-reasoning default); any other value is
        validated and forwarded. Used by the collapsed `settings(role)` path and
        directly by the judge's per-invocation effort config."""
        if effort is not None and effort not in _REASONING_EFFORT_CHOICES:
            raise ValueError(
                f"unsupported reasoning_effort {effort!r}; "
                f"expected one of {_REASONING_EFFORT_CHOICES}"
            )
        if effort in (None, "default"):
            return None
        from pydantic_ai.models.openai import OpenAIChatModelSettings

        return OpenAIChatModelSettings(extra_body={"reasoning_effort": effort})
