"""The one spelling of "this block runs under umask M", for every test that asserts a file's mode.

Every `_io` lane that makes a file lands 0644 masked by the process umask (#1144: no lane
overrides it). The kernel masks the 0644 an open asks for, and the unnamed create lane masks it
itself. So a test that asserts an exact mode asserts it UNDER a umask, and has to pin that umask
itself rather than inherit whatever the host or CI runner set. The umask is process-wide: a
pinned block covers the threads it starts, and the children it spawns inherit it.

It defines no tests. pytest does not collect it because its name matches neither of pytest's
default `python_files` patterns (`test_*.py`, `*_test.py`); the leading underscore only marks it
as one of the suite's helper modules.
"""
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
