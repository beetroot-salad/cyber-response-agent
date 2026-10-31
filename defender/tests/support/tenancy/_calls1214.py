"""#1214 r10.1: watch the calls of one production function without patching it. Test support only.

`watching(function, on_call)` installs a profile hook (`sys.setprofile`, and `threading.setprofile` for threads
started inside the block); `on_call(arguments)` runs, in the calling thread, at the start of every call of
`function`, with its arguments by name. The hook may block, which pins an interleaving a test needs. Nothing is
replaced, so a renamed or inlined function fails the case that watches it instead of silently passing.
"""
from __future__ import annotations

import contextlib
import sys
import threading
from collections.abc import Callable, Iterator
from types import FrameType
from typing import Any


@contextlib.contextmanager
def watching(function: Callable[..., Any], on_call: Callable[[dict[str, Any]], None]) -> Iterator[None]:
    """Watch `function` for the length of the block. The profile hooks that were installed before (a coverage tool's, an
    outer `watching`) are put back at exit, and a thread started inside the block, which keeps its hook for its own life,
    stops reporting once the block has ended."""
    code = function.__code__
    active = True
    prior_sys, prior_threads = sys.getprofile(), threading.getprofile()

    def hook(frame: FrameType, event: str, _arg: object) -> None:
        if active and event == "call" and frame.f_code is code:
            on_call(dict(frame.f_locals))

    threading.setprofile(hook)
    sys.setprofile(hook)
    try:
        yield
    finally:
        active = False
        sys.setprofile(prior_sys)
        threading.setprofile(prior_threads)
