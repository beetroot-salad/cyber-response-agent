"""The closing record's write (#1534 V-ONE, V-FINAL): one row per run, never a second."""
from __future__ import annotations

import sqlite3
from typing import Any

from ._schema import ClosingRecordExists


def write_closing_record(store: Any, record: Any) -> None:
    """Insert `record` (a `records.closing.ClosingRecord`) into the store's `closing_record`
    table. A run that already has a row raises `ClosingRecordExists` and the row stands. The
    write waits for the store's ordinary busy timeout, not the ledger's short one; any other
    fault is raised as the database raises it."""
    from defender.records.closing import ClosingRecord, encode_entries

    if not isinstance(record, ClosingRecord):
        raise TypeError(f"a closing record is a ClosingRecord, not {type(record).__name__}")
    try:
        store.connection.execute(
            "INSERT INTO closing_record (run_id, disposition, outcome, cause, failure_kind, "
            "drafted_disposition, ceiling_test, runtime_evidence, summary, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (record.run_id, record.disposition, record.outcome, record.cause, record.failure_kind,
             record.drafted_disposition, encode_entries(record.ceiling_test),
             encode_entries(record.runtime_evidence), record.summary, record.confidence))
    except sqlite3.IntegrityError as e:
        held = store.connection.execute(
            "SELECT 1 FROM closing_record WHERE run_id = ?", (record.run_id,)).fetchone()
        if held is None:
            raise
        raise ClosingRecordExists(f"run {record.run_id} already has a closing record") from e
