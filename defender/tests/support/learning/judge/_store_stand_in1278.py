"""#1278: the learning store a launcher's judge frame inserts its findings into, as an in-memory stand-in.

An episode launch grades with the operator's judge, which inserts findings into the learning store at the host's
database address. A test about something else the launch does (the page, the stage timing, the record) needs that frame
to succeed, not a database: `stand_in_store` names a placeholder address and answers `blocking(dsn)` with a `MemoryStore`
(the judge sink's two verbs, `support/learning/judge/_memory_store.py`), returned so a test can read what was queued.
A test about the sink itself uses the real store (`support/learning/core/_store1278.py`)."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from defender.tests.support.learning.judge._memory_store import MemoryStore

DSN_ENV = "DEFENDER_DATABASE_DSN"


def stand_in_store(monkeypatch: Any) -> MemoryStore:
    """Point the launcher's judge frame at a fresh `MemoryStore`; returns it."""
    store = MemoryStore()

    @contextmanager
    def blocking(_dsn: str):
        yield store

    monkeypatch.setenv(DSN_ENV, "postgresql://stand-in.invalid/none")
    monkeypatch.setattr("defender.learning.store.blocking", blocking)  # lint-monkeypatch: ok — the judge frame opens its store itself (`branch.cli._grade`); this test is not about the sink
    return store
