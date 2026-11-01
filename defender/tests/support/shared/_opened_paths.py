"""Which files the process opens, seen through Python's own audit events (no patching of `open`) — NO test functions.

A read that its caller then ignores (an error swallowed) leaves no trace in a result; the audit event does."""
from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Iterator
from pathlib import Path

_watching: list[list[str]] = []


def _hook(event: str, args: tuple) -> None:
    if event == "open" and _watching and args and isinstance(args[0], (str, bytes, os.PathLike)):
        path = os.fsdecode(args[0])
        for seen in _watching:
            seen.append(path)


sys.addaudithook(_hook)  # an audit hook cannot be removed; it records only while `opened_paths` is open


@contextlib.contextmanager
def opened_paths() -> Iterator[list[str]]:
    """The paths opened (any mode, success or not) while the block runs, as the caller spelled them."""
    seen: list[str] = []
    _watching.append(seen)
    try:
        yield seen
    finally:
        _watching.remove(seen)


def opened(seen: list[str], path: Path) -> bool:
    """Whether `path` (by absolute or resolved spelling) is among `seen`."""
    names = {str(path), str(path.absolute()), os.path.realpath(path)}
    return any(s in names or os.path.realpath(s) in names for s in seen)
