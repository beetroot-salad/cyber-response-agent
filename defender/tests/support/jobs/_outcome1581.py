"""#1581 machinery for the alert list's outcome: the design's O1 computed in Python from investigation rows (the oracle of
AP1), the alert's stored copy read by SQL, the statements a store runs, and raw-connection lock holders.

FORCED CHOICE (the design names `NoOutcome` as the marker the route hands the port for `outcome=none`, and says the store
never sees the string; it names neither the marker's home nor whether it is a class or a value): `no_outcome()` is the one
place the tests spell it, as an instance of `defender._vocab.NoOutcome`, the module that owns `Disposition`."""
from __future__ import annotations

import contextlib
import datetime as dt
import re
from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any

from defender.tests.support.shared._postgres1339 import execute

#: (id, stage, disposition, created_at) of one investigation row, as SQL reads it.
Row = tuple[str, str, str | None, dt.datetime]
#: The three stored columns: (outcome, source investigation id, source `created_at`).
Copy = tuple[str | None, str | None, dt.datetime | None]


class Reader:
    """One autocommit connection that reads rows as `execute` does (a uuid as its text), for a test that reads after every
    step: pass it where a `dsn` is taken below."""

    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.string import TextLoader

        self._conn = psycopg.connect(dsn, autocommit=True)
        self._conn.adapters.register_loader("uuid", TextLoader)

    def rows(self, statement: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        cur = self._conn.execute(statement, params or None)  # type: ignore[arg-type]
        return cur.fetchall() if cur.description else []

    def close(self) -> None:
        self._conn.close()


def _rows(source: str | Reader, statement: str, params: tuple[Any, ...]) -> list[tuple[Any, ...]]:
    return execute(source, statement, params) if isinstance(source, str) else source.rows(statement, params)


def no_outcome() -> Any:
    from defender._vocab import NoOutcome

    return NoOutcome()


def investigations_of(dsn: str | Reader, alert_id: str) -> list[Row]:
    return _rows(dsn, "SELECT id, stage, disposition, created_at FROM jobs.investigations WHERE alert_id = %s", (alert_id,))  # type: ignore[return-value]


def expected_copy(rows: Sequence[Row]) -> Copy:
    """O1: the disposition of the newest `completed` investigation by `(created_at, id)`, with its id and `created_at`; all
    null when there is none."""
    done = [(created_at, inv_id, disposition) for inv_id, stage, disposition, created_at in rows if stage == "completed"]
    if not done:
        return (None, None, None)
    created_at, inv_id, disposition = max(done)
    return (disposition, inv_id, created_at)


def expected_latest_status(rows: Sequence[Row]) -> str | None:
    """O1: the status of the newest investigation of any status by `(created_at, id)`, or null."""
    return max(((created_at, inv_id, stage) for inv_id, stage, _, created_at in rows), default=(None, None, None))[2]


def stored_copy(dsn: str | Reader, alert_id: str) -> Copy:
    """What `jobs.alerts` holds for the alert, by SQL on a separate connection."""
    [found] = _rows(dsn, "SELECT outcome, outcome_investigation_id, outcome_created_at FROM jobs.alerts WHERE id = %s", (alert_id,))
    return found  # type: ignore[return-value]


#: A select list naming `raw`, or a star: either would read the alert's raw payload.
READS_RAW = re.compile(r"\braw\b|(?:select|,)\s*(?:[\w\".]+\.)?\*", re.IGNORECASE)


@contextlib.contextmanager
def statements(store: Any) -> Iterator[list[str]]:
    """Every statement text `store`'s engine hands its driver while the block runs (SQLAlchemy's `before_cursor_execute`)."""
    from sqlalchemy import event

    engine = store._engine.sync_engine  # the one engine every transaction of the store uses
    seen: list[str] = []

    def record(conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, executemany: bool) -> None:
        seen.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        yield seen
    finally:
        event.remove(engine, "before_cursor_execute", record)


#: One node of a plan's main spine: (node type, index name or None).
Node = tuple[str, str | None]


def spine(plan: dict[str, Any]) -> list[Node]:
    """The nodes of the plan's main line, from the root down through every child that is not a sub-plan: what reads and
    orders the page itself, without the per-row lookups of the listed `latest_status`."""
    nodes = [(plan["Node Type"], plan.get("Index Name"))]
    for child in plan.get("Plans", []):
        if child.get("Parent Relationship") not in {"SubPlan", "InitPlan"}:
            nodes += spine(child)
    return nodes


@contextlib.contextmanager
def planned(store: Any) -> Iterator[list[list[Node]]]:
    """For every `SELECT` `store`'s engine runs while the block runs, the spine of the plan PostgreSQL chooses for it, by an
    `EXPLAIN` of the very statement with its parameters on the same connection."""
    from sqlalchemy import event

    engine = store._engine.sync_engine
    seen: list[list[Node]] = []

    def explain(conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, executemany: bool) -> None:
        if statement.lstrip().upper().startswith("SELECT"):
            cursor.execute("EXPLAIN (FORMAT JSON) " + statement, parameters)
            seen.append(spine(cursor.fetchall()[0][0][0]["Plan"]))

    event.listen(engine, "before_cursor_execute", explain)
    try:
        yield seen
    finally:
        event.remove(engine, "before_cursor_execute", explain)


@contextlib.asynccontextmanager
async def holding(dsn: str, statement: str, params: tuple[Any, ...] = ()) -> AsyncIterator[None]:
    """`statement` (a locking `SELECT`) run on a raw connection in an open transaction, committed on exit."""
    import psycopg

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        cur = await conn.execute(statement, params)  # type: ignore[arg-type]
        assert await cur.fetchall(), "premise: the row to hold exists"
        try:
            yield
        finally:
            await conn.commit()
