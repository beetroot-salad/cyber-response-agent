from __future__ import annotations

from defender._model import model
from typing import TYPE_CHECKING, Any, Protocol

# `Model` is `TYPE_CHECKING`-only, like every other pydantic_ai name in this package: this
# module is on the import path of the runtime-free install (`run_common.run_env`,
# `learning.core.config.source_first_party_key` both import `providers`), and a module-scope
# `from pydantic_ai ...` would make that install fail at import. `BuiltModel.model` is
# therefore typed `Any` at runtime rather than `Model` (#1067): a strict pydantic field
# annotated with a name bound only under `TYPE_CHECKING` leaves the class silently
# `__pydantic_complete__ = False`, failing at its first real construction far from here. The
# class is a pure carrier to `Agent(...)` and never calls anything on the field, so nothing
# is lost — `build_model`'s return type still says `Model` for the reader.
if TYPE_CHECKING:
    from pydantic_ai.models import Model
    from pydantic_ai.settings import ModelSettings

    from ..agent_role import AgentRole


@model(frozen=True)
class BuiltModel:

    #: A `pydantic_ai.models.Model` — `Any` for the reason the module comment gives.
    model: Any
    #: `dict[str, Any]`, never the real `ModelSettings` (#1067): `ModelSettings` is a
    #: `TypedDict`, and pydantic validates a `TypedDict` field by its OWN declared keys —
    #: dropping any key the TypedDict does not name. A provider-specific settings dict (an
    #: Anthropic/OpenAI/Google extension key `ModelSettings`'s base shape does not declare) is
    #: real, legitimate data every provider in this tree constructs, and this class is a pure
    #: carrier to `Agent(...)` that never reads a single key out of it — strict-validating it
    #: against the narrower base shape would silently strip exactly the keys a provider added
    #: it FOR. `test_build_agent_core_threads_def_model_and_effort_to_make_model` caught this
    #: as a dropped synthetic key before it could catch it as a dropped `openai_prompt_cache_key`
    #: sibling in production.
    settings: dict[str, Any] | None


class Provider(Protocol):

    id: str
    api_key_var: str
    aliases: dict[str, str]
    prefixes: tuple[str, ...]

    def build_model(self, name: str) -> Model:
        ...

    def effort_for_role(self, name: str, role: AgentRole) -> str | None:
        """Takes the MODEL as well as the role: whether an effort can be served at all is a
        property of the model, and a provider serving many cannot answer for one of them."""
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
