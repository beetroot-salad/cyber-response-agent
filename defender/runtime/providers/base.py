"""The provider abstraction: one class per serving *infra* (not per model).

A `Provider` owns everything vendor/protocol-specific for one serving infra —
how to build the pydantic-ai `Model` for a name it serves, the per-role
`ModelSettings` that name takes, and which env var carries its billable API key —
so the driver / run entrypoint stay provider-neutral. Adding an infra is a new
`Provider` instance in `__init__.py`, not another `isinstance` branch in the loop.

Routing is **declarative data**: each provider exposes `aliases` (friendly name →
bare model id) and `prefixes` (e.g. ``"fireworks:"``). The registry (`__init__.py`)
resolves a model name to a provider from that data — no per-provider `matches`
predicate, so there is no first-match ordering fragility.

The heavy pydantic-ai imports live **lazily inside** `build_model`/`settings`, so
importing this package for routing / key-var metadata (what `run.py` and
`run_common.py` need) pulls in no model backend and requires no runtime extra.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

    from ..agent_role import AgentRole


@dataclass(frozen=True)
class BuiltModel:
    """A constructed model paired with the `ModelSettings` its provider + role
    dictate. Produced together (the provider that builds the model owns its
    settings) so build sites never re-derive a model's provider from its type."""

    model: Model
    settings: ModelSettings | None


class Provider(Protocol):
    """One serving infra. `id` is the infra name (``"anthropic"`` / ``"fireworks"``);
    `api_key_var` is the env var carrying its billable key; `aliases` maps a friendly
    model name (lowercased) to the bare model id; `prefixes` are the explicit
    selectors (``"claude-"``, ``"fireworks:"``) that route a name here."""

    id: str
    api_key_var: str
    aliases: dict[str, str]
    prefixes: tuple[str, ...]

    def build_model(self, name: str) -> Model:
        """Construct the pydantic-ai model for a name this provider serves."""
        ...

    def settings(self, role: AgentRole) -> ModelSettings | None:
        """The per-role `ModelSettings` for this provider, or `None` for none."""
        ...

    def settings_for_effort(self, effort: str) -> ModelSettings | None:
        """`ModelSettings` for an EXPLICIT per-call reasoning effort, rather than the
        role-keyed env defaults `settings(role)` derives. For an agent whose effort is
        per-invocation config (the judge, whose two direction legs run concurrently at
        possibly different efforts — a single role env can't carry two values). Each
        provider maps `effort` to its own knob (Anthropic's `anthropic_effort`,
        OpenAI-compatible's `reasoning_effort`) and fails loud on an unsupported value."""
        ...
