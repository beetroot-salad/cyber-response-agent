"""The test worlds open now (#1496): a world registers itself as it opens, and `tests/conftest.py` closes every one a
test opened when the test ends, so a world's database, pools and loop thread never outlive its test. A world a wider
fixture opened (module scope) was open before the test began and is that fixture's to close. Standard library only:
the suite-wide conftest imports this."""
from __future__ import annotations

import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

_OPEN: weakref.WeakSet[Any] = weakref.WeakSet()


def opened(world: Any) -> None:
    """Register `world` (it has an idempotent `close()`)."""
    _OPEN.add(world)


@contextmanager
def closing_new_worlds() -> Iterator[None]:
    """Close, on exit, every world opened inside the block."""
    before = set(_OPEN)
    try:
        yield
    finally:
        for world in [w for w in _OPEN if w not in before]:
            world.close()
