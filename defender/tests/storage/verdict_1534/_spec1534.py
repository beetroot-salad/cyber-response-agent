"""Shared machinery for the #1534 contract: the closing record in the run's session database (no tests here).

The contract-chosen production names live in `.contract-first/1534/interface.md` and are binding: the record module
`defender.records.closing` (types, vocabulary, `treat`, bounds, lookup results, `for_run`), the store write
`session_store.write_closing_record` (second write: `ClosingRecordExists`), and `AgentDeps.session_store`.

Production names that do not exist yet are imported inside functions, so a missing one reds only the tests that use
it. Valid rows are planted through the production write; faults are made with real primitives (a scalar column
UPDATE, a dropped table, a deleted file, a non-JSON pointer, a held lock), never by encoding the structured columns."""
from __future__ import annotations

import asyncio
import contextlib
import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

from defender.records import SessionPaths
from defender.tests.support.shared._locations_1210 import fixture_runs_base

TABLE = "closing_record"
SCALAR_COLUMNS = ("run_id", "disposition", "outcome", "cause", "failure_kind", "drafted_disposition", "summary")

#: Model text a reader must show escaped: markup and an ampersand.
MARKUP_SUMMARY = "The pivot from the bastion is <b>confirmed</b> by the second login & the sudo chain."


def runs_base(tmp_path: Path) -> Path:
    """A runs base of this test's own: its sessions folder is `tmp_path/sessions`, never shared with another test."""
    base = tmp_path / "runs"
    base.mkdir(parents=True, exist_ok=True)
    return base


@contextlib.contextmanager
def run_store(base: Path, case_id: str) -> Iterator[Any]:
    """The real store for `case_id` beside `base`, open for the block (as the driver holds it during a run)."""
    from defender.records.session_store._write import open_store

    with open_store(case_id=case_id, sessions=SessionPaths(fixture_runs_base(base))) as store:
        yield store


def with_store(deps: Any, store: Any) -> Any:
    """MAIN deps carrying the run's open store, as the driver hands it to the close."""
    return replace(deps, session_store=store)


def handle(run_dir: Path) -> Any:
    """The host's `Run` handle on a run folder."""
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    return fixture_run(run_dir)


def point(run_dir: Path, store: Any, *, session_id: str | None = None) -> None:
    """`run_dir`'s session pointer naming `store`, as the driver writes it."""
    from defender.records import session_store as ss

    ss.write_case_pointer(handle(run_dir), case_id=store.case_id, store_path=store.path, session_id=session_id)


def closing_deps(tmp_path: Path, companion: str | None) -> tuple[Any, Path]:
    """MAIN deps through the real `bind` seam (`_spec923.main_deps`), the run folder under this test's own runs base."""
    from defender.tests.support.runtime.engine import _spec923 as S

    return S.main_deps(tmp_path, companion)


def a_record(run_id: str, **fields: Any) -> Any:
    """A valid `ClosingRecord` for `run_id`: a `malicious` close that stood, with `fields` overriding."""
    from defender.records import closing as C

    base: dict[str, Any] = {
        "run_id": run_id, "disposition": "malicious", "outcome": C.STANDS, "cause": C.CAUSE_STORY_SETTLED,
        "failure_kind": None, "drafted_disposition": None, "ceiling_test": (), "runtime_evidence": (),
        "summary": MARKUP_SUMMARY,
    }
    base.update(fields)
    return C.ClosingRecord(**base)


def plant(store: Any, record: Any) -> None:
    """Write `record` through the production write."""
    from defender.records import session_store as ss

    ss.write_closing_record(store, record)


def closed_run(tmp_path: Path, record_fields: dict[str, Any] | None = None, *, case_id: str = "c1534",
               run_name: str = "run") -> tuple[Path, Path]:
    """A run folder under this test's runs base with a pointer to a real store holding its closing record (or no
    record when `record_fields` is None). Returns `(run_dir, database)`."""
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    base = runs_base(tmp_path)
    run_dir = base / fixture_uuid(run_name)
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    with run_store(base, case_id) as store:
        store.new_session(agent_id="main")
        point(run_dir, store)
        if record_fields is not None:
            plant(store, a_record(run_dir.name, **record_fields))
        database = Path(store.path)
    return run_dir, database


def scalar_rows(database: Path, run_id: str) -> list[tuple]:
    """The record's scalar columns for `run_id`, by raw SQL (for "exactly one")."""
    conn = sqlite3.connect(database, timeout=30)
    try:
        return conn.execute(f"SELECT {', '.join(SCALAR_COLUMNS)} FROM {TABLE} WHERE run_id = ?",  # noqa: S608
                            (run_id,)).fetchall()
    finally:
        conn.close()


def corrupt(database: Path, run_id: str, column: str, value: Any) -> None:
    """Set one scalar column of `run_id`'s stored row to `value` (an out-of-vocabulary or invariant-breaking row)."""
    assert column in SCALAR_COLUMNS, column
    conn = sqlite3.connect(database, timeout=30)
    try:
        conn.execute("PRAGMA ignore_check_constraints = ON")  # reach the reader's own check, not the schema's
        conn.execute(f"UPDATE {TABLE} SET {column} = ? WHERE run_id = ?", (value, run_id))  # noqa: S608
        conn.commit()
    finally:
        conn.close()


def drop_table(database: Path) -> None:
    """A database as it stood before #1534: no `closing_record` table."""
    conn = sqlite3.connect(database, timeout=30)
    try:
        conn.execute(f"DROP TABLE IF EXISTS {TABLE}")
        conn.commit()
    finally:
        conn.close()


@contextlib.contextmanager
def write_locked(database: Path) -> Iterator[None]:
    """Hold the database's write lock for the block (another process mid-write)."""
    conn = sqlite3.connect(database, timeout=30, isolation_level=None)
    try:
        conn.execute("BEGIN EXCLUSIVE")
        yield
    finally:
        conn.execute("ROLLBACK")
        conn.close()


def drive_forced_close(deps: Any, store: Any, *, review_stages: Any = None) -> tuple[Any, Any, Any]:
    """`_spec923.drive_to_retry_exhaustion` with the run's real open store on deps and on the driver's flush seam, so
    the driver's own forced close writes the record. Returns `(run, truncated_by, exit_reason)`."""
    from defender.investigation import challenge_gate, driver
    from defender.tests.support.invlang.validation._invlang_warn_836 import build_main_agent
    from defender.tests.support.runtime.engine._spec923 import StuckModel

    session = store.new_session(agent_id="main")
    agent = build_main_agent(StuckModel(), review_stages=review_stages)
    run, end, exit_reason = asyncio.run(driver._drive_agent(
        agent, "go", with_store(deps, store), store, session, challenge_gate.default_bounds(),
    ))
    return run, end.truncated_by, exit_reason
