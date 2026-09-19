"""The one dataclass decorator every boundary type in the tree is built with (#1067).

`@model` wraps `pydantic.dataclasses.dataclass`: STRICT by default (no coercion — `"3"` is
never an `int`), `arbitrary_types_allowed` by default (many fields here are typed `Any` /
`Callable` / a Protocol / another arbitrary class), and `frozen` passed through exactly as the
caller spells it — same shape as stdlib `@dataclass`, usable bare or with keyword config
(`@model` or `@model(frozen=True)`).

**Exception-class convention for a `model_validator`/`field_validator` this decorates:**
pydantic wraps a validator's raised exception into its own `ValidationError` ONLY when that
exception is a `ValueError` or `AssertionError` — anything else propagates unchanged. Each rule
picks its failure mode by which it raises:

- **A domain exception** (`JudgeRefused`, `StoreAppendError`, `PayloadNotRepresentable`,
  `GrantError`, ...) — for a validator whose reader is a human with a traceback. It reaches the
  caller unconverted, first-fail, in whatever order the checks are written, exactly like a
  hand-written `__post_init__`.
- **`ValueError`** — for a validator whose reader is a model reading the message back as a tool
  result. Pydantic batches every failed check into one `ValidationError` naming every field
  path, and passes the `ValueError` text through verbatim — the gain is the batching, not the
  wording.

**`strict` defaults on, but is a real per-class knob, not a fixed rule.** Nested inside
another schema (a `list[Foo]` tool parameter, a field on a bigger record), a STRICT dataclass
demands an actual instance of itself, not a mapping — `TypeAdapter(list[Foo]).validate_python`
raises `dataclass_exact_type` on a plain `{"a": 1, "b": 2}` even though every field would pass.
`validate_json` never hits this (a JSON object has no "dict vs. instance" distinction to
enforce), but `pydantic_ai`'s tool-call path validates in Python mode whenever a provider hands
back already-parsed args (`tool_manager._validate_tool_args`: str args go through
`validate_json`, anything else through `validate_python`) — so a strict dataclass used as a
tool's parameter type can refuse a real, well-typed model call. The same applies to OUR OWN
read-back sites that build a record from a parsed YAML/JSON `dict` (`judge._grade_from_document`
and its nested `NotGradedStamp`): a nested strict record must be constructed first from its
mapping, or its owner passes `strict=False`. Pass `strict=False` for a class
instantiated FROM external data at a boundary like that one; every other still-typed check on
its fields still runs, lax mode only adds the ordinary coercions (a numeric string into an
`int`, and the like), never `int` where `str` is declared. (Verified directly against this
decorator, not carried over from a caller: the tree held no such tool-parameter dataclass at
the time this module was written — `author/verify_forward/tool.py`'s `Pair` was removed by
#773 between the design pass and this port landing.)

**The `ArgsKwargs` quirk.** On a pydantic *dataclass* (not a `BaseModel`), a `mode="before"`
validator does not receive a plain `dict` — it receives a `pydantic_core.ArgsKwargs`, which
holds positional args and keyword args separately (`Foo(1, 2)` puts `1, 2` in `.args` and
nothing in `.kwargs`; `Foo(a=1, b=2)` is the reverse). Call `unwrap_before(cls, value)` at the
top of a before-validator to get back the single `dict` of field name -> value a plain
`BaseModel` validator would have seen, whichever calling convention the constructor was used
with.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any, TypeVar, cast, dataclass_transform, overload

from pydantic import ConfigDict
from pydantic.dataclasses import dataclass as _pydantic_dataclass
from pydantic_core import ArgsKwargs

__all__ = ["model", "unwrap_before"]

T = TypeVar("T")


def unwrap_before(cls: type, value: Any) -> Any:
    """A `mode="before"` validator's raw input, as the single `dict` of field name -> value a
    `BaseModel` validator would see — `value` unchanged when it is not an `ArgsKwargs` at all
    (a re-validation, or a caller passing a mapping directly)."""
    if not isinstance(value, ArgsKwargs):
        return value
    names = [f.name for f in dataclasses.fields(cls)]
    merged = dict(zip(names, value.args, strict=False))
    merged.update(value.kwargs or {})
    return merged


# Two `@overload`s, not one signature: `T` appears only in the RETURN of the keyword-config
# form (`@model(frozen=True)` — no `cls` argument to solve it from), and mypy resolves a
# typevar it cannot solve from that call's own arguments to `Never` rather than leaving it open
# for the decorated class to fill in later — every field on the class then looks like an
# "unexpected keyword argument". Splitting the bare and keyword-config forms into their own
# overloads (matching how `pydantic.dataclasses.dataclass` itself is typed) keeps `T` solvable
# at the point the returned callable is actually applied to a class.
@overload
def model(cls: type[T]) -> type[T]: ...
@overload
def model(cls: None = None, *, frozen: bool = False, strict: bool = True, eq: bool = True,
         **config_kwargs: Any) -> Callable[[type[T]], type[T]]: ...
@dataclass_transform(field_specifiers=(dataclasses.field,))
def model(cls: type[T] | None = None, *, frozen: bool = False, strict: bool = True,
         eq: bool = True, **config_kwargs: Any) -> Callable[[type[T]], type[T]] | type[T]:
    """The shared boundary-type decorator — see module docstring for the convention it fixes.

    Usable bare (`@model`) or with keyword config (`@model(frozen=True)`), matching stdlib
    `@dataclass`. `strict` defaults on; pass `strict=False` for a class built FROM external
    data at a boundary pydantic itself validates in Python mode (a tool parameter type — see
    the module docstring's `dataclass_exact_type` note) rather than by our own code handing it
    already-typed values. `arbitrary_types_allowed` is always on (≈227 fields in this tree are
    typed `Any`/`Callable`/a Protocol/another arbitrary class). `eq` is stdlib `@dataclass`'s
    own knob, not a `ConfigDict` key (`eq=False` for a class where two equal-content instances
    must still compare unequal — identity equality, `RosterRead`'s "two reads are two reads").
    Extra `ConfigDict` keys (e.g. a class that wants `validate_assignment=True`) pass through
    — build the plain `dict` and `cast` it, rather than splat them straight into the
    `ConfigDict(...)` call, since a `TypedDict` constructor checks each keyword against its
    known keys and an arbitrary caller-supplied name is not one of them."""
    config = cast(ConfigDict,
                 {"strict": strict, "arbitrary_types_allowed": True, **config_kwargs})

    # Not named `wrap`: `defender._untrusted.wrap` is the tree's one frame primitive, and
    # `test_systemic_stage_frames_680`'s AST census counts every `def wrap` as a second one.
    def decorate(inner_cls: type[T]) -> type[T]:
        return cast(type[T],
                    _pydantic_dataclass(inner_cls, config=config, frozen=frozen, eq=eq))

    if cls is not None:
        return decorate(cls)
    return decorate
