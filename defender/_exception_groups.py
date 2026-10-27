"""Finding one named failure inside an exception group (#1243).

Concurrent tasks may deliver a failure inside an exception group, however deep. A run-level
catch that must end the run on a named failure looks for it here, so every such catch reads a
group the same way."""
from __future__ import annotations

from typing import TypeVar

_E = TypeVar("_E", bound=BaseException)


def carried(exc: BaseException, kind: type[_E]) -> _E | None:
    """The `kind` that `exc` is or carries (an exception group may wrap it, however deep)."""
    if isinstance(exc, kind):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for inner in exc.exceptions:
            found = carried(inner, kind)
            if found is not None:
                return found
    return None


def carried_unless_overridden(
    exc: BaseException, kind: type[_E], overriding: tuple[type[BaseException], ...],
) -> _E | None:
    """The `kind` that `exc` is or carries, unless `exc` is a group that also carries a failure
    with its own meaning for the run: an interrupt or cancellation (not an `Exception`) or one of
    `overriding`. Those must not be dropped for `kind`'s end, so the group propagates as before.
    An ordinary error beside `kind` is not such a failure."""
    found = carried(exc, kind)
    if found is None:
        return None
    pending = [exc]
    while pending:
        leaf = pending.pop()
        if isinstance(leaf, BaseExceptionGroup):
            pending.extend(leaf.exceptions)
        elif not isinstance(leaf, Exception) or isinstance(leaf, overriding):
            return None
    return found
