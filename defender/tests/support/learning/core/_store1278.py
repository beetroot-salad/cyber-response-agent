"""#1278 sketch: the learning store as tests drive and observe it, and the tick's test seams.

The store under test is `defender.learning.store.LearningStore(dsn, **knobs)`: SQLAlchemy async over
PostgreSQL schema `learning`, tenant id the first positional argument of every verb (as `JobStore`).
Nothing here implements store policy: helpers open the store, call one verb, read one view, lapse a
lease by the database's clock, and record what a curator step saw. The target is imported inside each
helper, so a missing module is a per-test red, never a collection error.
"""
from __future__ import annotations

import importlib
from collections.abc import AsyncIterator, Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio

from defender.tests.support.shared._postgres1339 import execute

#: The lane the findings kinds feed (design r8: lane follows from kind).
AUTHOR_LANE = "author"
#: The tick reads its store from the same variable the worker's children read their tenant records from.
DSN_ENV = "DEFENDER_DATABASE_DSN"


def store_mod() -> Any:
    return importlib.import_module("defender.learning.store")


@asynccontextmanager
async def learning_store(dsn: str, **knobs: Any) -> AsyncIterator[Any]:
    """The store under test on `dsn`, closed after. `knobs` (sketch): `lease`, seconds a claim or
    renewal holds a batch, counted by the database's clock."""
    store = store_mod().LearningStore(dsn, **knobs)
    try:
        yield store
    finally:
        await store.close()


def call(dsn: str, verb: str, *args: Any, **kw: Any) -> Any:
    """One store verb from sync code (a drain-level test), on a store of its own, in a thread of its
    own: a curator step's observation must not depend on whether the drain runs an event loop."""
    async def go() -> Any:
        async with learning_store(dsn) as store:
            return await getattr(store, verb)(*args, **kw)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(anyio.run, go).result()


def work(dsn: str, tenant_id: str) -> dict[str, Any]:
    """O2's view of `tenant_id`'s items, by item key."""
    return {item.key: item for item in call(dsn, "work", tenant_id)}


def batches(dsn: str, tenant_id: str) -> list[Any]:
    return list(call(dsn, "batches", tenant_id))


def lapse_lease(dsn: str, batch_id: str) -> None:
    """The batch's lease ran out an hour ago by the database's clock (past any lease plus grace).
    Sketch choice: columns `learning.batches.id` and `lease_expiry`."""
    execute(dsn, "UPDATE learning.batches SET lease_expiry = now() - interval '1 hour' WHERE id = %s",
            (batch_id,))


def finding(fid: str, *, run_id: str | None = None) -> dict[str, Any]:
    """A defender finding row the lessons gate admits (`_drain719.finding_row`)."""
    from defender.tests.support.learning.curation._drain719 import finding_row

    return finding_row(fid, run_id=run_id or f"run-{fid}")


def lesson_citing(*finding_ids: str) -> str:
    from defender.tests.support.learning.curation._spec773 import lesson

    return lesson(*finding_ids)


class LessonWriter:
    """The drain's `trigger_author` seam as a curator that writes `lessons` (name -> text) into its
    batch's draft lane and commits them once per batch through the batch's own commit-maker.
    `before_commit(batch)` runs between the write and the commit (an observation or a fault).
    Records the batches it served and each commit refusal; a refusal is re-raised, as a curator's
    would be. It ignores what else the drain hands it (the sketch pins only `batch=`)."""

    def __init__(self, lessons: dict[str, str], *, before_commit: Callable[[Any], None] | None = None) -> None:
        self.lessons = lessons
        self.before_commit = before_commit
        self.served: list[str] = []
        self.commits: list[str] = []
        self.refused: list[BaseException] = []

    def __call__(self, *_args: Any, batch: Any, **_kw: Any) -> None:
        if batch.id in self.served:
            return
        self.served.append(batch.id)
        for name, text in self.lessons.items():
            target = Path(batch.draft_root) / "agent" / "lessons" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        if self.before_commit is not None:
            self.before_commit(batch)
        try:
            self.commits.append(batch.commit(batch.change_set(), f"learning: batch {batch.id}"))
        except BaseException as refused:
            self.refused.append(refused)
            raise


def files_under(root: Path) -> dict[str, bytes]:
    """Every regular file below `root` (relative path -> bytes); `{}` when `root` is absent."""
    if not root.is_dir():
        return {}
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}
