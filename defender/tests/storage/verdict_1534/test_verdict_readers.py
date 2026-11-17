"""#1534 sketch: the one reader (V-READ). The worker, run page and ticket cases moved to each reader's own test file (slice c).

Rows are planted by raw SQL (`_spec1534.plant_verdict`), never through the close, and each reused fixture's
`report.md` is removed, so the file cannot answer for the record."""
from __future__ import annotations

import sqlite3

from defender.tests.storage.verdict_1534 import _spec1534 as V
from defender.tests.support.shared._fixture_uuid import fixture_uuid

RUN = fixture_uuid("verdict-1534-reader")


# --- the one reader --------------------------------------------------------------------------------------------------

def test_v_read_the_reader_returns_the_runs_own_typed_record_and_none_for_another_run(tmp_path):
    """Two runs share one database (a source and its arm): each reads its own row; a run with none reads `None`. (V-READ,
    V-ONE)"""
    arm = fixture_uuid("verdict-1534-arm")
    with V.run_store(tmp_path / "runs", "verdict-1534-reader") as store:
        database = store.path
    V.plant_verdict(database, RUN, disposition="malicious", ceiling_test=[V.receipt("query-empty", ref="l-003", note="n")])
    V.plant_verdict(database, arm, disposition="benign", summary=None)

    source = V.read_verdict(database, RUN)
    assert (source.disposition, source.summary) == ("malicious", V.PLANTED_SUMMARY)
    assert [(r.state, r.ref, r.cap, r.note) for r in source.ceiling_test] == [("query-empty", "l-003", None, "n")]
    assert (V.read_verdict(database, arm).disposition, V.read_verdict(database, arm).summary) == ("benign", None)
    assert V.read_verdict(database, fixture_uuid("never closed")) is None


def test_v_read_a_database_without_the_table_reads_no_verdict(tmp_path):
    """An older database with no `verdict` table: no verdict, not a fault (the ledger's `_has_table` rule). (V-READ)"""
    with V.run_store(tmp_path / "runs", "verdict-1534-old") as store:
        database = store.path
    conn = sqlite3.connect(database)
    try:
        conn.execute(f"DROP TABLE IF EXISTS {V.VERDICT_TABLE}")
        conn.commit()
    finally:
        conn.close()

    assert V.read_verdict(database, RUN) is None
