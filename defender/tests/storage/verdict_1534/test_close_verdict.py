"""#1534 sketch: the close commits the run's verdict as one row of the session database's `verdict` table, with a summary
built from `:T conclude`'s closing rows (V-ONE, V-FINAL, V-FIELDS, V-SUM, V-NOFILE).

Entry: the real close (`_spec923.close` -> `close_tool._close_investigation_async`) over MAIN deps from the real `bind`
seam, carrying a real open session store (`AgentDeps.session_store`, sketch-chosen). Read back through the one reader
(`session_store.read_verdict`, sketch-chosen) and, for 'exactly one', by raw SQL."""
from __future__ import annotations

import sqlite3

import pytest

from defender.tests.storage.verdict_1534 import _spec1534 as V
from defender.tests.support.runtime.engine import _spec923 as S

CASE = "verdict-1534-close"

#: `S.pays_every_price`'s two free-text `:T conclude` rows, in the design's join order (summary, detection_notes).
SUMMARY_ROW = "one document that owes no keyword anything"
DETECTION_ROW = "Groups by host, so the actor the rule names is never tested."
#: FORCED CHOICE (join): the design says "joined in this order" without a separator; the sketch pins one space.
JOINED = f"{SUMMARY_ROW} {DETECTION_ROW}"


def _closed(tmp_path, disposition: str, *, companion: str | None, **close_kw):
    """Close `disposition` over `companion` with the run's store open on deps; return (close result, database, run id)."""
    deps, run_dir = S.main_deps(tmp_path, companion)
    with V.run_store(tmp_path, CASE) as store:
        result = S.close(V.with_store(deps, store), disposition, **close_kw)
        database = store.path
    return result, database, run_dir


def test_v_one_a_confident_close_commits_one_typed_record_and_no_report_file(tmp_path):
    """A reviewed `malicious` close that stands: one row keyed by the run id, its typed fields the host's own values, the
    summary built from the closing rows, and no `report.md` in the run folder. (V-ONE, V-FIELDS, V-SUM, V-NOFILE)"""
    from defender.investigation.close_tool import CAUSE_STORY_SETTLED, STANDS

    _result, database, run_dir = _closed(tmp_path, "malicious", companion=S.pays_every_price("malicious"))

    assert len(V.verdict_rows(database, run_dir.name)) == 1, "a closed run has exactly one verdict row"
    verdict = V.read_verdict(database, run_dir.name)
    assert (verdict.disposition, verdict.outcome, verdict.cause, verdict.failure_kind) == (
        "malicious", STANDS, CAUSE_STORY_SETTLED, None)
    # FORCED CHOICE: `ceiling_test` is keyed on the committed disposition today (`inconclusive` only), so a confident
    # close carries none even when its `:T conclude` names a paying receipt.
    assert tuple(verdict.ceiling_test) == ()
    assert verdict.summary == JOINED
    assert not (run_dir / "report.md").exists(), "the close wrote report.md"


def test_v_sum_a_false_positive_summary_carries_the_detection_notes(tmp_path):
    """`false-positive`'s summary is the same one rule: `summary` then `detection_notes`. (V-SUM)"""
    _result, database, run_dir = _closed(tmp_path, "false-positive", companion=S.pays_every_price("false-positive"))

    verdict = V.read_verdict(database, run_dir.name)
    assert verdict.disposition == "false-positive"
    assert verdict.summary == JOINED


def test_v_fields_an_inconclusive_close_carries_its_ceiling_receipts_as_typed_values(tmp_path):
    """The receipts an `inconclusive` close paid with: state, ref or cap, note. (V-FIELDS)"""
    _result, database, run_dir = _closed(tmp_path, "inconclusive", companion=S.paid(S.PAYING_ROW))

    verdict = V.read_verdict(database, run_dir.name)
    assert verdict.disposition == "inconclusive"
    assert [(r.state, r.ref, r.cap, r.note) for r in verdict.ceiling_test] == [
        ("query-failed", "l-002", None, "EDR execve logs for web-1 never came back; the collector returned HTTP 503")]
    assert verdict.summary == "could not settle the actor"


def test_v_sum_an_unresolved_override_opens_with_the_stock_sentence_for_its_cause(tmp_path):
    """A confident close whose review could not complete is overridden to `unresolved`: the record says so in its typed
    fields, and the summary opens with the stock sentence the cause selects, then the closing rows. (V-SUM, OD3)"""
    from defender.investigation.close_tool import (
        CAUSE_REVIEW_INCOMPLETE, FORCED_INCONCLUSIVE, STAGE_ERROR, UNRESOLVED_SUMMARY_OPENERS,
    )

    _result, database, run_dir = _closed(tmp_path, "malicious", companion=S.pays_every_price("malicious"), stages=None)

    verdict = V.read_verdict(database, run_dir.name)
    assert (verdict.disposition, verdict.outcome, verdict.cause, verdict.failure_kind) == (
        "unresolved", FORCED_INCONCLUSIVE, CAUSE_REVIEW_INCOMPLETE, STAGE_ERROR)
    opener = UNRESOLVED_SUMMARY_OPENERS[CAUSE_REVIEW_INCOMPLETE]
    # FORCED CHOICE: the drafted rows argue `malicious`; the design keeps them after the opener on an override too.
    assert verdict.summary == f"{opener} {JOINED}"


def test_v_sum_the_forced_close_of_a_run_cut_short_opens_with_the_cut_short_sentence(tmp_path):
    """The host's `unresolved` close of a run cut short (the driver's forced close): not reviewed, and the summary opens
    with the cut-short sentence, then the closing rows the model drafted before the cut. (V-SUM, OD3)"""
    from defender.investigation.close_tool import CAUSE_NOT_REVIEWED, STANDS, UNRESOLVED_SUMMARY_OPENERS

    _result, database, run_dir = _closed(tmp_path, S.MEMBER, companion=S.pays_every_price("malicious"), forced=True)

    verdict = V.read_verdict(database, run_dir.name)
    assert (verdict.disposition, verdict.outcome, verdict.cause) == ("unresolved", STANDS, CAUSE_NOT_REVIEWED)
    # FORCED CHOICE: "cut short" is keyed on CAUSE_NOT_REVIEWED, the only cause the forced close carries; the close does
    # not know the exit class. And the forced close skips the flagged/structure gates, so these rows were never checked.
    assert verdict.summary == f"{UNRESOLVED_SUMMARY_OPENERS[CAUSE_NOT_REVIEWED]} {JOINED}"


def test_v_sum_a_forced_close_with_no_document_has_the_stock_sentence_alone(tmp_path):
    """No `investigation.md` at all: no piece exists, but an `unresolved` summary is never null. (V-SUM)"""
    from defender.investigation.close_tool import CAUSE_NOT_REVIEWED, UNRESOLVED_SUMMARY_OPENERS

    _result, database, run_dir = _closed(tmp_path, S.MEMBER, companion=None, forced=True)

    assert V.read_verdict(database, run_dir.name).summary == UNRESOLVED_SUMMARY_OPENERS[CAUSE_NOT_REVIEWED]


def test_v_sum_the_summary_is_normalized_once_when_built(tmp_path):
    """URL-shaped text is removed, whitespace collapsed, and a long summary capped at a word boundary with an ellipsis.
    (V-SUM)"""
    long_tail = " ".join(["the actor re-used the service key"] * 40)
    summary = f'"see https://evil.example/pwn and www.evil.example    for   the rest; {long_tail}"'
    companion = S.doc(S.PROLOGUE, S.LEADS, S.LEAD_RESULT, S.conclude(
        disposition="malicious", confidence="high", **{"termination.category": "data-ceiling"},
        summary=summary))

    _result, database, run_dir = _closed(tmp_path, "malicious", companion=companion)

    from defender.investigation.close_tool import SUMMARY_MAX_CHARS

    built = V.read_verdict(database, run_dir.name).summary
    assert "://" not in built, built
    assert "www." not in built, built
    assert "  " not in built, built
    # FORCED CHOICE: whether the ellipsis counts inside the 600.
    assert len(built) <= SUMMARY_MAX_CHARS
    assert built.endswith("…")
    assert built[:-1].rstrip().split()[-1] in set(long_tail.split()), f"the cap cut inside a word: {built!r}"


def test_v_one_a_second_write_for_the_same_run_is_refused_by_the_database(tmp_path):
    """A row already stands for this run id (the state flag cannot see it: a fresh deps): the database refuses the
    insert, the close is not final, and the standing row is unchanged. (V-ONE, V-FINAL)"""
    from defender.investigation import challenge_gate

    deps, run_dir = S.main_deps(tmp_path, S.pays_every_price("malicious"))
    with V.run_store(tmp_path, CASE) as store:
        V.plant_verdict(store.path, run_dir.name, disposition="benign")
        before = V.verdict_rows(store.path, run_dir.name)
        carrying = V.with_store(deps, store)
        # FORCED CHOICE: the refusal's type (sqlite's own, or a store error naming the run).
        with pytest.raises(sqlite3.IntegrityError):
            S.close(carrying, "malicious")
        assert not challenge_gate.ReviewState.of(carrying).closed, "a refused verdict write made the close final"
        assert V.verdict_rows(store.path, run_dir.name) == before


def test_v_nofile_the_layout_no_longer_names_report_md():
    """`report.md` is not named by the run layout any more. (V-NOFILE)"""
    from defender.records import RUN_LAYOUT

    assert not hasattr(RUN_LAYOUT, "report")
