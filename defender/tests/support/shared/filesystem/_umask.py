"""The one spelling of "this block runs under umask M", for every test that asserts a file's mode."""
from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator


@contextlib.contextmanager
def umask(mask: int) -> Iterator[None]:
    """Run the block under `mask`, restoring the previous umask however it exits."""
    old = os.umask(mask)
    try:
        yield
    finally:
        os.umask(old)
