"""The verb contract an adapter is written against (#1080): the `@verb` decorator, the marks it
sets and their readers, and the call context as an adapter sees it. The registry that loads and
serves adapters stays in `runtime.verbs`; so does the engine table (`engine_for`).

`VerbContext` here is a protocol naming only what an adapter reads. The runtime's concrete
`runtime.verbs.VerbContext` satisfies it, so adapters annotate their leading parameter with this
one and never import the runtime."""
from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from defender.kit.faults import ConfigFault
from defender.kit.settings import SystemConfig


class TenantRecord(Protocol):
    """The run's tenant record, as an adapter reads it."""

    @property
    def systems(self) -> Mapping[str, SystemConfig | ConfigFault]:
        """Each configured system's parsed `config.env`, or the fault for why there is none."""
        ...

    @property
    def agent(self) -> Path:
        """The agent-knowledge root the run reads."""
        ...


class Capture(Protocol):
    """A recorder of the outbound requests an adapter makes."""

    def record(self, *, system: str, url: str, method: str) -> None: ...


class RunClock(Protocol):
    """The run clock an adapter stamps a capture with."""

    def now(self) -> datetime: ...


class VerbContext(Protocol):
    """The call context a verb receives, as an adapter sees it."""

    @property
    def env(self) -> Mapping[str, str]: ...

    @property
    def tenant(self) -> TenantRecord: ...

    @property
    def capture(self) -> Capture | None: ...

    @property
    def run_state(self) -> RunClock | None: ...

    @property
    def as_of(self) -> datetime | None: ...


Verb = Callable[..., Any]



_ENGINE_ATTR = "__verb_engine__"
_BODY_PARAM_ATTR = "__verb_body_param__"
_VERB_CLASS_ATTR = "__verb_class__"
_WRAPPER_ONLY_ATTR = "__verb_wrapper_only__"


def verb(
    *, engine: str = "none", body_param: str | None = None, verb_class: str = "r",
    wrapper_only: tuple[str, ...] = (),
) -> Callable[[Verb], Verb]:
    """`wrapper_only` names params a first-party wrapper binds and no model may.

    E.g. `ticket`'s `require_closed`: the closed-ticket tool pins it, while a gather lead that
    set it would silently drop the open siblings it was dispatched to correlate. A marked param
    is refused by `validate_params` and omitted from `model_facing_params`; the wrapper calls
    `fn(ctx, **params)` directly and never crosses that check.
    """
    # Checked at decoration because both mistakes are silent: a bare string reserves its
    # characters, and a misspelt name reserves nothing, leaving the param model-settable.
    if isinstance(wrapper_only, str):
        raise TypeError(
            f"@verb(wrapper_only={wrapper_only!r}) is a bare string — it would iterate into "
            "characters and reserve no param. Pass a tuple: (\"<param>\",)"
        )
    reserved = frozenset(wrapper_only)

    def decorate(fn: Verb) -> Verb:
        declared = declared_params(fn)
        undeclared = sorted(reserved - set(declared))
        if undeclared:
            raise ValueError(
                f"@verb(wrapper_only=…) on {getattr(fn, '__name__', fn)!r} reserves "
                f"{undeclared}, which the signature does not declare as keyword-only param(s) "
                f"— a reserved name that matches nothing is silently no reservation at all"
            )
        # A reserved param needs a default: it is outside the required set `validate_params`
        # checks, so without one every model call would raise TypeError inside the verb body
        # and be filed as an infra fault.
        undefaulted = sorted(
            n for n in reserved if declared[n].default is inspect.Parameter.empty
        )
        if undefaulted:
            raise ValueError(
                f"@verb(wrapper_only=…) on {getattr(fn, '__name__', fn)!r} reserves "
                f"{undefaulted}, which the signature declares WITHOUT a default — a reserved "
                f"param is dropped from the required set the boundary checks, so no model call "
                f"can ever supply it and every one of them would fault inside the verb body. "
                f"Give it the default the wrapper overrides"
            )
        setattr(fn, _ENGINE_ATTR, engine)
        setattr(fn, _BODY_PARAM_ATTR, body_param)
        setattr(fn, _VERB_CLASS_ATTR, verb_class)
        setattr(fn, _WRAPPER_ONLY_ATTR, reserved)
        return fn

    return decorate


def engine_of(fn: Verb) -> str:
    return getattr(fn, _ENGINE_ATTR, "none")


def body_param_of(fn: Verb) -> str | None:
    return getattr(fn, _BODY_PARAM_ATTR, None)


def verb_class_of(fn: Verb) -> str:
    """The verb_class a verb body declares via `@verb(verb_class=…)`; `r` when undecorated."""
    return getattr(fn, _VERB_CLASS_ATTR, "r")


def declared_params(fn: Verb) -> dict[str, inspect.Parameter]:
    return {
        p.name: p
        for p in inspect.signature(fn).parameters.values()
        if p.kind is inspect.Parameter.KEYWORD_ONLY
    }


def wrapper_only_params(fn: Verb) -> frozenset[str]:
    """The params `@verb(wrapper_only=…)` reserves to a first-party wrapper."""
    return getattr(fn, _WRAPPER_ONLY_ATTR, frozenset())


def model_facing_params(fn: Verb) -> dict[str, inspect.Parameter]:
    """The declared params a model may bind: `declared_params` minus the wrapper-only set.

    Both `validate_params` and `list_verbs` use this, so what is accepted and what is published
    cannot disagree."""
    hidden = wrapper_only_params(fn)
    return {n: p for n, p in declared_params(fn).items() if n not in hidden}


__all__ = [
    "Capture",
    "RunClock",
    "TenantRecord",
    "Verb",
    "VerbContext",
    "body_param_of",
    "declared_params",
    "engine_of",
    "model_facing_params",
    "verb",
    "verb_class_of",
    "wrapper_only_params",
]
