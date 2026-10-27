"""The running test as the owner of the session stores its helpers open (#1324).

A store is open only inside a `with` block. A test that opens one in its own `with` owns it
there. The shared helpers that hand a test a store instead (`make_store`, `owned_store`,
`reread`) enter it into the running test's `ExitStack`, which the autouse fixture in
`tests/conftest.py` closes at teardown. A helper called with no test
running (a module-scoped fixture's setup) is refused: such a fixture opens its store in its own
`with`.
"""
from __future__ import annotations

import contextlib
from collections.abc import Iterator
from contextvars import ContextVar
from pathlib import Path
from typing import Any

_OWNER: ContextVar[contextlib.ExitStack | None] = ContextVar("store_owner", default=None)


@contextlib.contextmanager
def stores_owned_by_the_test() -> Iterator[None]:
    """Make the running test the owner of the stores `owned()` is handed, until it ends."""
    with contextlib.ExitStack() as stack:
        token = _OWNER.set(stack)
        try:
            yield
        finally:
            _OWNER.reset(token)


def owning_stack() -> contextlib.ExitStack:
    """The running test's `ExitStack`; a helper enters its store there:
    `owning_stack().enter_context(open_store(...))`."""
    stack = _OWNER.get()
    if stack is None:
        raise RuntimeError(
            "no test owns this store: a module-scoped fixture opens its store in its own `with`")
    return stack


def reread(handle_or_path: Any) -> Any:
    """A read connection to the store a run already closed — the run owns what it opens, so a
    test reads the rows back through its own connection, closed when the test ends."""
    from defender.records import session_store as ss

    path = Path(getattr(handle_or_path, "path", handle_or_path))
    return owning_stack().enter_context(ss.open_store_for_read(path))


def owned_store(**open_store_kwargs: Any) -> Any:
    """`open_store(**open_store_kwargs)`, closed when the test ends."""
    from defender.records import session_store as ss

    return owning_stack().enter_context(ss.open_store(**open_store_kwargs))
