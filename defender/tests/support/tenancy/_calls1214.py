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
    code = function.__code__

    def hook(frame: FrameType, event: str, _arg: object) -> None:
        if event == "call" and frame.f_code is code:
            on_call(dict(frame.f_locals))

    threading.setprofile(hook)
    sys.setprofile(hook)
    try:
        yield
    finally:
        sys.setprofile(None)
        threading.setprofile(None)
