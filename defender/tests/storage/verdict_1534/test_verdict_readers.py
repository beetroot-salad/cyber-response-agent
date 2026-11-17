"""#1534 sketch: every reader of a run's verdict reads the record in the run's session database through the one reader;
a run with no record reads "no verdict" in each caller's own terms (V-READ, V-WORKER, V-PAGE).

Rows are planted by raw SQL (`_spec1534.plant_verdict`), never through the close, and each reused fixture's
`report.md` is removed, so the file cannot answer for the record."""
from __future__ import annotations

import re
import sqlite3

import pytest

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


# --- the worker's read, through JobLane -----------------------------------------------------------------------------

def test_v_worker_the_job_lane_reads_the_disposition_through_the_pointer_it_uses_for_cost(tmp_path):
    """The lane locates the database from the pointer's case id (as `cost` does) and reads the run's disposition from
    its record; a run with a pointer and no record reads `None` (the worker's `unparseable`). (V-WORKER)"""
    from defender.records import job_lane
    from defender.tenancy import data_root_from_path
    from defender.tests.support.jobs._jobs1342 import T1, session_db, session_pointer

    runs = tmp_path / "data" / T1 / "runs"
    runs.mkdir(parents=True)
    closed, unclosed = fixture_uuid("verdict-1534-closed"), fixture_uuid("verdict-1534-unclosed")
    with V.run_store(runs, "verdict-1534-lane") as store:
        store.new_session(agent_id="main")
    database = session_db(runs, "verdict-1534-lane")
    for inv in (closed, unclosed):
        (runs / f"{inv}.session-pointer.json").write_text(session_pointer("verdict-1534-lane"), encoding="utf-8")
    V.plant_verdict(database, closed, disposition="false-positive")

    with job_lane.JobLane.open(data_root_from_path(tmp_path / "data"), T1) as lane:
        # FORCED CHOICE: the method's name (today `report_disposition`, which `tests/jobs/test_worker.py:1140` keys a seam on).
        assert lane.verdict_disposition(closed) == "false-positive"
        assert lane.verdict_disposition(unclosed) is None


# --- the run page ----------------------------------------------------------------------------------------------------

def _headline(html: str) -> str:
    found = re.search(r'<section class="headline headline-runtime">(.*?)</section>', html, flags=re.S)
    assert found is not None, "no headline box"
    return found.group(1)


def test_v_page_the_headline_shows_the_records_disposition_and_its_summary_escaped(tmp_path, monkeypatch):
    """The headline box: the record's disposition, then the summary under it, HTML-escaped. (V-PAGE)"""
    from defender.records import session_store as ss
    from defender.tests.presentation.test_visualize_runtime import _build_run, _page
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    run = _build_run(tmp_path)
    (run / "report.md").unlink()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    V.plant_verdict(ss.resolve_store_path(fixture_run(run)), run.name, disposition="malicious")

    headline = _headline(_page(run))
    assert 'disp-badge disp-malicious' in headline
    assert "The pivot from 10.0.0.5 is &lt;b&gt;confirmed&lt;/b&gt; by the second login &amp; the sudo chain." in headline
    assert "<b>confirmed</b>" not in headline


def test_v_page_a_run_with_no_record_shows_not_completed(tmp_path, monkeypatch):
    """No record: the page's own "no verdict" (the unknown disposition), and no summary. (V-READ)"""
    from defender._vocab import UNKNOWN_DISPOSITION
    from defender.records import session_store as ss
    from defender.tests.presentation.test_visualize_runtime import _build_run, _page
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    run = _build_run(tmp_path)
    (run / "report.md").unlink()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    # The table exists (another run of the lineage closed); this run has no row.
    V.plant_verdict(ss.resolve_store_path(fixture_run(run)), fixture_uuid("another run"), disposition="benign")

    headline = _headline(_page(run))
    assert f"disp-{UNKNOWN_DISPOSITION}" in headline
    assert "disp-benign" not in headline
    # FORCED CHOICE: what fills the body slot when there is no summary (today "(no report body)").


# --- the ticket case record ------------------------------------------------------------------------------------------

def test_v_read_the_ticket_case_record_reads_the_record_and_renders_its_narrative(tmp_path):
    """The ticket's case record: disposition and cause from the record; the narrative a host rendering of the ceiling
    notes (and runtime-evidence lines), without the summary (OD7). (V-READ)"""
    from defender.tenancy.case_ticket import read_case_record
    from defender.tests.support.runtime.engine._spec923 import finished_run
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    run_dir = finished_run(tmp_path, disposition="inconclusive")
    (run_dir / "report.md").unlink()
    run = fixture_run(run_dir)
    database = V.store_with_pointer(run, tmp_path, "verdict-1534-ticket")
    note = "EDR execve logs for web-1 never came back"
    V.plant_verdict(database, run_dir.name, disposition="inconclusive",
                    cause="the challenge review examined the ceiling claim and found nothing further measurable",
                    ceiling_test=[V.receipt("query-failed", ref="l-002", note=note)])

    record = read_case_record(run)
    assert (record.disposition, record.cause) == (
        "inconclusive", "the challenge review examined the ceiling claim and found nothing further measurable")
    # FORCED CHOICE: the narrative's line format; the sketch keeps `ceiling_note_block`'s line, minus the placeholder.
    assert record.narrative == f"ceiling_test (query-failed, l-002): {note}"
    assert "pivot" not in record.narrative, "the summary reached the ticket comment (OD7: #1471 adds it)"


def test_v_read_a_run_with_no_record_takes_the_tickets_unreadable_branch(tmp_path):
    """No record: the ticket's own "no verdict" branch. (V-READ)"""
    from defender.tenancy.case_ticket import ReportNotParsable, read_case_record
    from defender.tests.support.runtime.engine._spec923 import finished_run
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    run_dir = finished_run(tmp_path, disposition="malicious")
    (run_dir / "report.md").unlink()
    run = fixture_run(run_dir)
    database = V.store_with_pointer(run, tmp_path, "verdict-1534-ticket-none")
    V.plant_verdict(database, fixture_uuid("another run"))

    # FORCED CHOICE: the refusal keeps its name `ReportNotParsable` and the fixed sentence naming report.md (V-NOFILE).
    with pytest.raises(ReportNotParsable) as refused:
        read_case_record(run)
    assert "report.md" not in str(refused.value), "the refusal still names report.md"  # lint-run-records: ok — a test oracle
