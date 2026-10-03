"""The one spelling of "this block runs under umask M", for every test that asserts a file's mode.

`_io`'s writers ask for 0644 and let the kernel mask it by the process umask (#1144: no lane
overrides it), so a test that asserts an exact mode asserts it UNDER a umask, and has to pin
that umask itself rather than inherit whatever the host or CI runner set. The umask is
process-wide: a pinned block covers threads it starts, and children it spawns inherit it.

Underscore-prefixed so pytest does not collect it; it defines no tests.
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
