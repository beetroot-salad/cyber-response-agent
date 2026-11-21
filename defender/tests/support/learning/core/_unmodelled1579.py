"""#1579 R7: a model-seam fake never silently accepts an input it does not model.

An input a fake has no honest answer for (a text reply to a typed call, a call with nothing
scripted) is recorded on the fake's own `unmodelled` list, and `tests/conftest.py` asserts every
registered list empty at teardown: production containment (the judge's draw loop, the
questioner's degrade handlers) may swallow the fake's exception, the record still fails the test.
A test that exercises the refusal itself reads the list, asserts it and `.clear()`s it.
"""
from __future__ import annotations

#: Every fake's `unmodelled` list, registered at its construction; emptied at each teardown.
_LISTS: list[list[str]] = []


def new_list() -> list[str]:
    """A fresh `unmodelled` list for one fake, registered for the teardown check."""
    entries: list[str] = []
    _LISTS.append(entries)
    return entries


def drain() -> list[str]:
    """Every unmodelled input recorded since the last drain (each list emptied, still registered)."""
    seen = [entry for entries in _LISTS for entry in entries]
    for entries in _LISTS:
        entries.clear()
    return seen
