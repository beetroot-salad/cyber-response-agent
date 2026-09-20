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

The first bullet holds only for a domain exception that is NOT itself a `ValueError`: raised
inside a validator, a `ValueError` subclass is wrapped like any other `ValueError`, and a
caller's `except ThatClass` silently misses it. `learning/judge/_errors.py`'s `JudgeRefused`
was one until #1067 PR5 found this porting `enqueue`'s row rules onto `QueueRow`; a domain
exception meant to reach the caller unconverted derives from `Exception`, never `ValueError`.
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
    (a re-validation, or a caller passing a mapping directly).

    Arity is checked HERE, because a before-validator that returns a `dict` has replaced the
    `ArgsKwargs` pydantic would otherwise have checked itself: a surplus positional would be
    dropped on the floor, and a keyword naming a field a positional already filled would win
    over it in silence — a caller mis-ordering the positional form would get a record with
    the wrong value in it rather than the refusal the class promises. Both raise `TypeError`,
    the class stdlib `@dataclass` raises for the same two mistakes.
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


#: The `ConfigDict` keys, read off the TypedDict itself so the refusal in `model` tracks the
#: installed pydantic rather than a hand-kept copy.
_CONFIG_KEYS: frozenset[str] = frozenset(ConfigDict.__annotations__)
#: The stdlib `@dataclass` knobs `model` forwards by name (the refusal names them).
_STDLIB_KNOBS: frozenset[str] = frozenset(
    {"frozen", "eq", "order", "unsafe_hash", "repr", "kw_only", "slots"})


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
         order: bool = False, unsafe_hash: bool = False, repr: bool = True,
         kw_only: bool = False, slots: bool = False,
         **config_kwargs: Any) -> Callable[[type[T]], type[T]]: ...
@dataclass_transform(field_specifiers=(dataclasses.field,))
def model(cls: type[T] | None = None, *, frozen: bool = False, strict: bool = True,  # noqa: PLR0913 — one keyword per stdlib `@dataclass` knob, each forwarded by name
         eq: bool = True, order: bool = False, unsafe_hash: bool = False, repr: bool = True,
         kw_only: bool = False, slots: bool = False,
         **config_kwargs: Any) -> Callable[[type[T]], type[T]] | type[T]:
    """The shared boundary-type decorator — see module docstring for the convention it fixes.

    Usable bare (`@model`) or with keyword config (`@model(frozen=True)`), matching stdlib
    `@dataclass`. `strict` defaults on; pass `strict=False` for a class built FROM external
    data at a boundary pydantic itself validates in Python mode (a tool parameter type — see
    the module docstring's `dataclass_exact_type` note) rather than by our own code handing it
    already-typed values. `arbitrary_types_allowed` is always on (≈227 fields in this tree are
    typed `Any`/`Callable`/a Protocol/another arbitrary class).

    The stdlib `@dataclass` knobs — `frozen`, `eq`, `order`, `unsafe_hash`, `repr`, `kw_only`,
    `slots` — are each named here and forwarded to the pydantic decorator BY NAME, because
    they are not `ConfigDict` keys: splatted into the config instead, pydantic ignores them
    without a word, and `@model(frozen=True, kw_only=True)` would build a positional
    constructor (`eq=False` is the one already in use — identity equality, `RosterRead`'s "two
    reads are two reads"). Everything else in `**config_kwargs` must be a real `ConfigDict`
    key (e.g. `validate_assignment=True`) and is refused otherwise, so a knob this list does
    not carry (`init`, which pydantic only accepts as `False`, or a typo) cannot vanish the
    same way. The plain `dict` is built and `cast` rather than splatted straight into the
    `ConfigDict(...)` call, since a `TypedDict` constructor checks each keyword against its
    known keys and an arbitrary caller-supplied name is not one of them."""
    unknown = sorted(set(config_kwargs) - _CONFIG_KEYS)
    if unknown:
        raise TypeError(
            f"@model got {unknown} — not a stdlib @dataclass knob this decorator forwards "
            f"({sorted(_STDLIB_KNOBS)}) and not a pydantic ConfigDict key, so pydantic would "
            "have ignored it in silence")
    config = cast(ConfigDict,
                 {"strict": strict, "arbitrary_types_allowed": True, **config_kwargs})

    # Not named `wrap`: `defender._untrusted.wrap` is the tree's one frame primitive, and
    # `test_systemic_stage_frames_680`'s AST census counts every `def wrap` as a second one.
    def decorate(inner_cls: type[T]) -> type[T]:
        return cast(type[T],
                    _pydantic_dataclass(inner_cls, config=config, frozen=frozen, eq=eq,
                                        order=order, unsafe_hash=unsafe_hash, repr=repr,
                                        kw_only=kw_only, slots=slots))

    if cls is not None:
        return decorate(cls)
    return decorate
