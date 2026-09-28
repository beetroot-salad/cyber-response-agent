"""The one dataclass decorator every boundary type in the tree is built with.

`@model` wraps `pydantic.dataclasses.dataclass`, usable bare or as `@model(frozen=True)`, with:
strict by default (no coercion — `"3"` is never an `int`); `extra="forbid"` (pydantic's default
silently drops unknown keywords, so a typo in a constructor or `dataclasses.replace` would keep
the old value); and `arbitrary_types_allowed`.

**Forward references.** A field naming a class defined later in the same module leaves the
schema incomplete, and pydantic finishes it on first construction from whichever thread gets
there first. Call `complete(cls)` at module end to finish it at import.

**Validator exceptions.** Pydantic wraps only `ValueError`/`AssertionError` into its
`ValidationError`; anything else propagates unchanged. So:

- Raise a **domain exception** (deriving from `Exception`, not `ValueError`) when the reader is
  a human with a traceback: it arrives unconverted, first-fail. A `ValueError` subclass would be
  wrapped and a caller's `except ThatClass` would silently miss it.
- Raise **`ValueError`** when a model reads the message back as a tool result: pydantic batches
  every failed check into one `ValidationError` naming each field path.

**`strict` is a per-class knob.** Nested in another schema, a strict dataclass demands an
actual instance, not a mapping: `TypeAdapter(list[Foo]).validate_python({...})` raises
`dataclass_exact_type`. `pydantic_ai` validates tool args in Python mode when a provider hands
back already-parsed args, so a strict dataclass as a tool parameter type can refuse a
well-typed call; the same holds for our own read-back sites building records from parsed
YAML/JSON (`judge._grade_from_document`). Pass `strict=False` for a class instantiated from
external data at such a boundary — lax mode only adds ordinary coercions, never `int` for `str`.

**`ArgsKwargs`.** On a pydantic dataclass a `mode="before"` validator receives a
`pydantic_core.ArgsKwargs` (positional and keyword args held separately), not a `dict`. Call
`unwrap_before(cls, value)` first to get the field-name -> value `dict`.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any, TypeVar, cast, dataclass_transform, overload

from pydantic import ConfigDict
from pydantic.dataclasses import dataclass as _pydantic_dataclass
from pydantic.dataclasses import rebuild_dataclass as _rebuild_dataclass
from pydantic_core import ArgsKwargs

__all__ = ["complete", "model", "unwrap_before"]

T = TypeVar("T")


def complete(cls: type[T]) -> type[T]:
    """Finish the schema of a `@model` class whose field names a class defined after it in the
    same module — call once at module end. Returns `cls`.

    Otherwise pydantic builds the schema lazily on first construction, and two threads doing
    that at once race on the class's validator. `cast(Any, ...)` because the
    `PydanticDataclass` protocol is only published from pydantic's `_internal`.
    `_parent_namespace_depth=3` resolves names in this function's caller's frame, so records
    defined inside a function resolve too."""
    _rebuild_dataclass(cast(Any, cls), _parent_namespace_depth=3)
    return cls


def unwrap_before(cls: type, value: Any) -> Any:
    """A `mode="before"` validator's raw input as a field name -> value `dict`; `value`
    unchanged when it is not an `ArgsKwargs`.

    Arity is checked here because returning a `dict` bypasses pydantic's own check: a surplus
    positional would be dropped and a keyword duplicating a positional would silently win.
    Both raise `TypeError`, as stdlib `@dataclass` does.
    """
    if not isinstance(value, ArgsKwargs):
        return value
    positional = [f.name for f in dataclasses.fields(cls) if f.init and not f.kw_only]
    if len(value.args) > len(positional):
        raise TypeError(
            f"{cls.__name__} takes {len(positional)} positional argument(s) but "
            f"{len(value.args)} were given")
    merged = dict(zip(positional, value.args, strict=False))
    kwargs = value.kwargs or {}
    twice = sorted(set(merged) & set(kwargs))
    if twice:
        raise TypeError(f"{cls.__name__} got multiple values for argument(s) {twice}")
    merged.update(kwargs)
    return merged


#: The `ConfigDict` keys, read off the TypedDict so they track the installed pydantic.
_CONFIG_KEYS: frozenset[str] = frozenset(ConfigDict.__annotations__)
#: The stdlib `@dataclass` knobs `model` forwards by name (the refusal names them).
_STDLIB_KNOBS: frozenset[str] = frozenset(
    {"frozen", "eq", "order", "unsafe_hash", "repr", "kw_only", "slots"})


# Two overloads: in the keyword-config form `T` appears only in the return type, and mypy
# would resolve it to `Never` from a single signature, making every field an "unexpected
# keyword argument". Mirrors how `pydantic.dataclasses.dataclass` is typed.
@overload
def model(cls: type[T]) -> type[T]: ...
@overload
def model(cls: None = None, *, frozen: bool = False, strict: bool = True, eq: bool = True,
         order: bool = False, unsafe_hash: bool = False, repr: bool = True,
         kw_only: bool = False, slots: bool = False,
         **config_kwargs: Any) -> Callable[[type[T]], type[T]]: ...
@dataclass_transform(field_specifiers=(dataclasses.field,))
def model(cls: type[T] | None = None, *, frozen: bool = False, strict: bool = True,  # noqa: PLR0913 — one keyword per stdlib `@dataclass` knob, each forwarded by name
         eq: bool = True, order: bool = False, unsafe_hash: bool = False, repr: bool = True,
         kw_only: bool = False, slots: bool = False,
         **config_kwargs: Any) -> Callable[[type[T]], type[T]] | type[T]:
    """The shared boundary-type decorator (conventions in the module docstring).

    The stdlib `@dataclass` knobs are forwarded to pydantic by name because they are not
    `ConfigDict` keys: splatted into the config, pydantic would silently ignore them. Every
    other keyword must be a real `ConfigDict` key and is refused otherwise, so a typo cannot
    vanish the same way. The config is built as a plain `dict` and `cast`, since the
    `TypedDict` constructor rejects caller-supplied names statically."""
    unknown = sorted(set(config_kwargs) - _CONFIG_KEYS)
    if unknown:
        raise TypeError(
            f"@model got {unknown} — not a stdlib @dataclass knob this decorator forwards "
            f"({sorted(_STDLIB_KNOBS)}) and not a pydantic ConfigDict key, so pydantic would "
            "have ignored it in silence")
    # `extra="forbid"`: otherwise `replace(cfg, bx=box)` would return an unchanged copy.
    config = cast(ConfigDict,
                 {"strict": strict, "extra": "forbid", "arbitrary_types_allowed": True,
                  **config_kwargs})

    # Not named `wrap`: a test's AST census treats every `def wrap` as a frame primitive.
    def decorate(inner_cls: type[T]) -> type[T]:
        return cast(type[T],
                    _pydantic_dataclass(inner_cls, config=config, frozen=frozen, eq=eq,
                                        order=order, unsafe_hash=unsafe_hash, repr=repr,
                                        kw_only=kw_only, slots=slots))

    if cls is not None:
        return decorate(cls)
    return decorate
