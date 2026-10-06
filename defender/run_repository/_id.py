"""`RunId`: a run's id as a closed value type (#1105 D12; MF-02, MF-08).

Built only by `RunId.parse(text)` (a pinned id, or one read back from storage) and
`RunId.mint(label, *, clock=)` (the host's own id). Both admit by `_run_id.run_id_fault`:
today's grammar, case stability and a bound of 206 bytes on the id (`RUN_ID_MAX_BYTES`, whose
derivation is there, beside the rule the host's composed ids are judged by too). Every refusal
is `RunRefused`.

Unforgeable: a direct `RunId(...)`, `RunId.__new__(RunId)` and a subclass each raise
`RunRefused`, and every copy route (pickle, `copy.copy`, `copy.deepcopy`) rebuilds through
`RunId.parse`. A strict value: not a `str`, not path-like, not JSON-serialisable, never equal
to a `str` and unordered against one; `str(run_id)` is its text, an exact `str`.

The sidecar clause is not part of `RunId`: `run_exists` takes a `RunId` and answers for a
sidecar file at such a name (D2.1). Pydantic-free (NM-05).
"""
from __future__ import annotations

import datetime as _dt
from collections.abc import Callable
from typing import Any, NoReturn

from defender._run_id import RUN_ID_ALLOWED, _utc_now, mint_run_id, run_id_fault
from defender._shown import quoted
from defender.run_repository._errors import RunRefused

#: The bound on a run id's bytes (D12.3): 255 - 25 - 24. See the module docstring.
def _admit(text: str) -> str:
    """`text` if it is a run id `RunId` admits (`run_id_fault`), else `RunRefused`. `text` is
    an exact `str`."""
    if (why := run_id_fault(text)) is not None:
        raise RunRefused(why)
    return text


def _exact_str(value: object, what: str) -> str:
    """An exact-`str` copy of `value` (a `str` subclass is admitted, its own `__str__` never
    asked), or `RunRefused` for anything that is not text."""
    if not isinstance(value, str):
        raise RunRefused(f"a run id {what} must be text, not {type(value).__name__}")
    return str.__str__(value)


def _rebuild(text: str) -> RunId:
    """The one route a copy or an unpickled payload takes back to a `RunId`."""
    return RunId.parse(text)


class RunId:
    """A run's id. Build one with `RunId.parse` or `RunId.mint`; see the module docstring."""

    __slots__ = ("_text",)
    _text: str

    def __new__(cls, *args: Any, **kwargs: Any) -> RunId:  # noqa: PYI034 — it never returns
        raise RunRefused("a RunId is built only by RunId.parse or RunId.mint")

    def __init_subclass__(cls, **kwargs: Any) -> NoReturn:
        raise RunRefused("RunId cannot be subclassed")

    @classmethod
    def _built(cls, text: str) -> RunId:
        run_id = object.__new__(cls)
        object.__setattr__(run_id, "_text", _admit(text))
        return run_id

    @classmethod
    def parse(cls, text: object) -> RunId:
        """The `RunId` for `text`, or `RunRefused`: text `refuse_bad_run_id` refuses, text
        that is not case-stable, text over 206 bytes, or anything that is not text."""
        return cls._built(_exact_str(text, "to parse"))

    @classmethod
    def mint(cls, label: object, *,
             clock: Callable[[], _dt.datetime] = _utc_now) -> RunId:
        """The host's own id, `<UTC timestamp>-<label>` case-folded (today's `mint_run_id`),
        or `RunRefused`. The bound is measured on the folded id, since folding can lengthen a
        label (`ß` -> `ss`); the label is never truncated to fit."""
        label = _exact_str(label, "label")
        try:
            text = mint_run_id(label, clock=clock)
        except ValueError:
            raise RunRefused(f"cannot mint a run id from the label {quoted(label)} "
                             f"(allowed: {RUN_ID_ALLOWED})") from None
        return cls._built(text)

    def __str__(self) -> str:
        return self._text

    def __repr__(self) -> str:
        return f"RunId({self._text!r})"

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError(f"a RunId is frozen; cannot assign {name!r}")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError(f"a RunId is frozen; cannot delete {name!r}")

    def __reduce__(self) -> tuple[Callable[[str], RunId], tuple[str]]:
        return (_rebuild, (self._text,))

    def __copy__(self) -> RunId:
        return _rebuild(self._text)

    def __deepcopy__(self, memo: dict[int, Any]) -> RunId:
        return _rebuild(self._text)

    def __eq__(self, other: object) -> bool:
        if type(other) is not RunId:
            return NotImplemented
        return self._text == other._text

    def __hash__(self) -> int:
        return hash((RunId, self._text))

    def __lt__(self, other: object) -> bool:
        if type(other) is not RunId:
            return NotImplemented
        return self._text < other._text

    def __le__(self, other: object) -> bool:
        if type(other) is not RunId:
            return NotImplemented
        return self._text <= other._text

    def __gt__(self, other: object) -> bool:
        if type(other) is not RunId:
            return NotImplemented
        return self._text > other._text

    def __ge__(self, other: object) -> bool:
        if type(other) is not RunId:
            return NotImplemented
        return self._text >= other._text
