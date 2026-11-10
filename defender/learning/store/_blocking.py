"""The store's synchronous face (#1278): the same verbs for code that runs no event loop (the revert CLI, the judge, the
queue view). A portal thread owns the loop and the store's connections; each call runs there to its end."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from anyio.from_thread import BlockingPortal, start_blocking_portal

from ._store import LearningStore


class BlockingStore:
    def __init__(self, portal: BlockingPortal, store: LearningStore) -> None:
        self._portal, self._store = portal, store

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._store, name)
        if not inspect.iscoroutinefunction(target):
            return target

        def call(*args: Any, **kwargs: Any) -> Any:
            return self._portal.call(lambda: target(*args, **kwargs))
        return call


@contextmanager
def blocking(dsn: str, **knobs: Any) -> Iterator[BlockingStore]:
    """`with blocking(dsn) as store:` the store's verbs as plain calls."""
    with start_blocking_portal() as portal:
        store: LearningStore = portal.call(lambda: LearningStore(dsn, **knobs))
        try:
            yield BlockingStore(portal, store)
        finally:
            portal.call(store.close)


__all__: list[Callable[..., Any] | str] = ["BlockingStore", "blocking"]
