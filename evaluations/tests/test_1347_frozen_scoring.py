"""#1347 r6: the scorer binds a run to its case's current freeze and lists what it cannot score."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from test_held_out_scoring import (
    _fixture_set,
    _row,
    _run,
    _scored_rc,
    _verdicts,
    freeze_digest,
    freeze_doc,
    unscored,
    write_freeze,
)

GOOD, OTHER = "m05-lsass-access", "m07-cron-persistence"
SLUGS = {GOOD, OTHER}


def _esql(query: str) -> dict:
    return {"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "esql",
            "query_id": "elastic.esql", "params": {"query": query}}


def _search(**params: Any) -> dict:
    return {"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "query",
            "query_id": "elastic.query",
            "params": {"limit": 20, "index": "logs-*", "sort": "desc", **params}}


CLEAN = [_esql('FROM logs-* | WHERE @timestamp >= "2026-10-20T07:00:00Z" | LIMIT 1')]
NOW_ESQL = [_esql("FROM logs-* | WHERE @timestamp > now() - 1 hour | LIMIT 5")]


def _cases(tmp_path: Path) -> tuple[Path, Path]:
    fixtures = _fixture_set(tmp_path / "held-out", {GOOD: "benign", OTHER: "malicious"})
    return fixtures, tmp_path / "runs"


def _ok(runs: Path, says: str = "benign") -> str:
    return _run(runs, says=says, queries=CLEAN).name


def _dropped(runs: Path, says: str = "malicious") -> str:
    return _run(runs, says=says, queries=NOW_ESQL).name


def _why(text: str, slug: str) -> str:
    return unscored(text, SLUGS).get(slug, "")


def test_a_row_for_the_current_freeze_scores_and_a_complete_set_exits_zero(tmp_path):
    """O9/O11: rows bound to each case's current freeze score; the complete set exits 0 and is
    not called incomplete (positive control for every refusal below)."""
    fixtures, runs = _cases(tmp_path)
    rc, said = _scored_rc(tmp_path, runs, fixtures,
                          (GOOD, _ok(runs)), (OTHER, _ok(runs, "malicious")))

    assert (rc, _verdicts(said)) == (0, {GOOD: "OK", OTHER: "OK"}), said
    assert "incomplete" not in said.lower(), said


def test_a_row_for_an_older_freeze_is_ignored_not_refused(tmp_path):
    """O9: after the freeze changes, the old row no longer counts: the case reads as not run
    under its current freeze, the rest scores, and the index is not refused."""
    fixtures, runs = _cases(tmp_path)
    old_good, other = _ok(runs), _ok(runs, "malicious")
    old_row = _row(fixtures, GOOD, old_good)
    write_freeze(fixtures / GOOD, fingerprint={"logs-system.auth-2026.10.20|2026-10-20T08": [1, 1]})

    rc, said = _scored_rc(tmp_path, runs, fixtures, old_row, (OTHER, other))

    assert _verdicts(said) == {OTHER: "OK"}, said
    assert "not run" in _why(said, GOOD), said
    assert rc not in (0, 2), said


def test_the_newest_row_for_the_current_freeze_scores_past_a_later_older_freeze_row(tmp_path):
    """O9: rows bound to another freeze are skipped when picking the row to score, wherever they
    sit in the index."""
    fixtures, runs = _cases(tmp_path)
    current, stray = _ok(runs, "benign"), _ok(runs, "malicious")
    rows = [(GOOD, current), _row(fixtures, GOOD, stray, freeze="0" * 64), (OTHER, _ok(runs, "malicious"))]

    rc, said = _scored_rc(tmp_path, runs, fixtures, *rows)

    assert (rc, _verdicts(said)) == (0, {GOOD: "OK", OTHER: "OK"}), said


def test_a_pre_1347_row_without_a_freeze_never_counts_for_a_frozen_case(tmp_path):
    """O9: a `{slug, run_id}` row has no freeze, so its run is not scored for a frozen case; it
    is listed as not run, not refused."""
    fixtures, runs = _cases(tmp_path)
    old_style = {"slug": GOOD, "run_id": _ok(runs)}

    rc, said = _scored_rc(tmp_path, runs, fixtures, old_style, (OTHER, _ok(runs, "malicious")))

    assert _verdicts(said) == {OTHER: "OK"}, said
    assert "not run" in _why(said, GOOD), said
    assert rc not in (0, 2), said


def test_comments_key_order_and_line_endings_do_not_change_which_rows_count(tmp_path):
    """Freeze digest: a freeze.yaml rewritten with comments, reversed key order and CRLF is the
    same freeze (its row still scores); a changed value is another freeze (its row is ignored)."""
    fixtures, runs = _cases(tmp_path)
    good, other = _ok(runs), _ok(runs, "malicious")
    rows = [(GOOD, good), (OTHER, other)]
    index_rows = [_row(fixtures, s, r) for s, r in rows]
    doc = freeze_doc()
    text = "# re-saved by hand\n" + yaml.safe_dump(dict(reversed(list(doc.items()))), sort_keys=False)
    (fixtures / GOOD / "freeze.yaml").write_bytes(text.replace("\n", "\r\n").encode())

    rc, said = _scored_rc(tmp_path, runs, fixtures, *index_rows)
    assert (rc, _verdicts(said)) == (0, {GOOD: "OK", OTHER: "OK"}), said

    write_freeze(fixtures / GOOD, captured_at="2026-10-20T09:03:18Z")
    _rc, changed = _scored_rc(tmp_path, runs, fixtures, *index_rows)
    assert _verdicts(changed) == {OTHER: "OK"}, changed
    assert "not run" in _why(changed, GOOD), changed


def test_the_digest_row_binding_is_the_sorted_compact_json_digest(tmp_path):
    """Freeze digest: a row carrying sha256 of the sorted, compact JSON of the parsed freeze
    binds; one carrying the digest of the raw file bytes does not."""
    import hashlib

    fixtures, runs = _cases(tmp_path)
    raw = hashlib.sha256((fixtures / GOOD / "freeze.yaml").read_bytes()).hexdigest()
    assert raw != freeze_digest(fixtures / GOOD)
    good, other = _ok(runs), _ok(runs, "malicious")

    _rc, said = _scored_rc(tmp_path, runs, fixtures,
                           _row(fixtures, GOOD, good, freeze=raw), (OTHER, other))

    assert _verdicts(said) == {OTHER: "OK"}, said


def test_a_held_out_case_with_no_freeze_file_refuses_the_whole_set(tmp_path):
    """O9: one case lacking freeze.yaml refuses the set (exit 2, case named), scoring nothing,
    as a bad label does."""
    fixtures, runs = _cases(tmp_path)
    (fixtures / OTHER / "freeze.yaml").unlink()

    rc, said = _scored_rc(tmp_path, runs, fixtures, (GOOD, _ok(runs)))

    assert rc == 2, said
    assert OTHER in said, said
    assert "refused" in said, said
    assert _verdicts(said) == {}, said


@pytest.mark.parametrize("confirmed", [{}, None, "absent"], ids=["empty", "null", "absent"])
def test_a_case_whose_confirmed_block_is_empty_refuses_the_whole_set(tmp_path, confirmed):
    """Confirmation: capture leaves `confirmed` empty; a case not yet confirmed refuses the set
    like a missing freeze, whichever way the block is empty."""
    fixtures, runs = _cases(tmp_path)
    doc = freeze_doc()
    if confirmed == "absent":
        del doc["confirmed"]
    else:
        doc["confirmed"] = confirmed
    (fixtures / OTHER / "freeze.yaml").write_text(
        yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    rc, said = _scored_rc(tmp_path, runs, fixtures, (GOOD, _ok(runs)))

    assert rc == 2, said
    assert OTHER in said, said
    assert "refused" in said, said
    assert _verdicts(said) == {}, said


def test_a_malformed_index_row_still_refuses_the_whole_index(tmp_path):
    """O9: a line that is not a JSON row refuses the index (exit 2) even when other rows are
    well-formed r6 rows."""
    from evaluations import held_out

    fixtures, runs = _cases(tmp_path)
    index = tmp_path / "ops" / "index.jsonl"
    index.parent.mkdir()
    index.write_text(json.dumps(_row(fixtures, GOOD, _ok(runs))) + "\nnot json\n", encoding="utf-8")

    rc = held_out.main([str(runs), "--index", str(index), "--fixtures-dir", str(fixtures)])

    assert rc == 2


def test_a_run_whose_verdict_is_stale_is_listed_stale_not_scored(tmp_path):
    """Verdict: the bound run's stale verdict marks the case stale; it is not scored and the
    gate blocks, while the valid case beside it scores."""
    fixtures, runs = _cases(tmp_path)
    stale = _row(fixtures, OTHER, _ok(runs, "malicious"), verdict="stale",
                 reason="fingerprint differs in logs-system.auth-2026.10.20")

    rc, said = _scored_rc(tmp_path, runs, fixtures, (GOOD, _ok(runs)), stale)

    assert _verdicts(said) == {GOOD: "OK"}, said
    assert "stale" in _why(said, OTHER), said
    assert "Aggregate accuracy: 1/1" in said, said
    assert rc != 0, said
    assert "incomplete" in said.lower(), said


def test_the_newest_current_freeze_row_decides_between_stale_and_valid(tmp_path):
    """Verdict: a later stale row stales the case even after an earlier valid one; a later valid
    row after a stale one scores."""
    fixtures, runs = _cases(tmp_path)
    valid, stale = (GOOD, _ok(runs)), _row(fixtures, GOOD, _ok(runs), verdict="stale")
    other = (OTHER, _ok(runs, "malicious"))

    _rc, went_stale = _scored_rc(tmp_path, runs, fixtures, valid, stale, other)
    rc, recovered = _scored_rc(tmp_path, runs, fixtures, stale, valid, other)

    assert "stale" in _why(went_stale, GOOD), went_stale
    assert GOOD not in _verdicts(went_stale), went_stale
    assert (rc, _verdicts(recovered)) == (0, {GOOD: "OK", OTHER: "OK"}), recovered


@pytest.mark.parametrize("queries", [
    [_esql("FROM logs-* | WHERE @timestamp > now() - 1 hour | LIMIT 5")],
    [_esql("FROM logs-* | EVAL t = NOW()")],
    [_esql("FROM logs-* | EVAL t = Now ()")],
    [_search(native_query="user.name:root", start="now-1d")],
    [_search(native_query="user.name:root", end="now")],
    [_search(native_query="@timestamp:[now-1h TO *]")],
    [_esql("FROM logs-* | LIMIT 1"), _search(native_query="@timestamp:[now-1h TO *]")],
], ids=["now()", "NOW()", "Now ()", "start", "end", "query-string", "second-row"])
def test_a_run_that_uses_elasticsearchs_now_is_dropped_and_listed_for_rerun(tmp_path, queries):
    """D4/O5: now() in ES|QL, or `now` date math in a search's start, end or query string, drops
    the run: not scored, listed as needing a re-run, set incomplete."""
    fixtures, runs = _cases(tmp_path)
    clock_read = _run(runs, says="malicious", queries=queries).name

    rc, said = _scored_rc(tmp_path, runs, fixtures, (GOOD, _ok(runs)), (OTHER, clock_read))

    assert _verdicts(said) == {GOOD: "OK"}, said
    assert "re-run" in _why(said, OTHER), said
    assert rc != 0, said
    assert "incomplete" in said.lower(), said


def test_absolute_times_in_recorded_queries_are_not_a_clock_read(tmp_path):
    """D4 (positive control): ISO start/end and absolute ES|QL bounds score normally."""
    fixtures, runs = _cases(tmp_path)
    queries = [_search(native_query="user.name:root", start="2026-10-20T07:00:00Z",
                       end="2026-10-20T09:00:00Z"), *CLEAN]

    rc, said = _scored_rc(tmp_path, runs, fixtures, (GOOD, _run(runs, says="benign", queries=queries).name),
                          (OTHER, _ok(runs, "malicious")))

    assert (rc, _verdicts(said)) == (0, {GOOD: "OK", OTHER: "OK"}), said


def test_a_dropped_run_that_also_crashed_is_dropped_not_scored_wrong(tmp_path):
    """D4: a run that read `now` and has no report is a harness artifact: listed for re-run,
    absent from the wrong answers and the failure bucket."""
    fixtures, runs = _cases(tmp_path)
    crashed = _run(runs, says=None, queries=NOW_ESQL).name

    _rc, said = _scored_rc(tmp_path, runs, fixtures, (GOOD, _ok(runs)), (OTHER, crashed))

    assert "re-run" in _why(said, OTHER), said
    assert OTHER not in _verdicts(said), said
    assert "no parseable report" not in said, said


def test_a_crashed_or_unparseable_run_with_clean_queries_still_scores_wrong(tmp_path):
    """O11 (as today): a clean current-freeze run without a parseable report scores WRONG, and
    that complete set exits 0."""
    fixtures, runs = _cases(tmp_path)
    crashed = _run(runs, says=None, queries=CLEAN).name

    rc, said = _scored_rc(tmp_path, runs, fixtures, (GOOD, _ok(runs)), (OTHER, crashed))

    assert _verdicts(said) == {GOOD: "OK", OTHER: "WRONG"}, said
    assert (rc, "incomplete" in said.lower()) == (0, False), said


def _unscorable_after(tmp_path: Path, sequence: str) -> tuple[int, str]:
    """Score OTHER from rows `sequence` (`d` dropped, `c` clean; an uppercase letter is a row
    bound to another freeze); GOOD scores from one clean row."""
    fixtures, runs = _cases(tmp_path)
    rows: list[Any] = []
    for ch in sequence:
        run = _dropped(runs) if ch.lower() == "d" else _ok(runs, "malicious")
        rows.append(_row(fixtures, OTHER, run, **({"freeze": "f" * 64} if ch.isupper() else {})))
    return _scored_rc(tmp_path, runs, fixtures, (GOOD, _ok(runs)), *rows)


@pytest.mark.parametrize("sequence", ["ddd", "dddd", "cddd"])
def test_three_consecutive_dropped_rows_make_the_case_unscorable(tmp_path, sequence):
    """D13: three dropped rows in a row for one slug and freeze (a longer run, or one after an
    earlier clean row, included) make it unscorable, not another re-run."""
    rc, said = _unscorable_after(tmp_path, sequence)

    assert "unscorable" in _why(said, OTHER), said
    assert "re-run" not in _why(said, OTHER), said
    assert (rc != 0, "incomplete" in said.lower()) == (True, True), said


@pytest.mark.parametrize("sequence", ["dd", "ddcd", "dcdd", "dDd", "dDdd"])
def test_fewer_than_three_consecutive_drops_stay_a_rerun(tmp_path, sequence):
    """D13: a clean row resets the count and rows for another freeze do not count toward it, so
    these stay at a re-run."""
    _rc, said = _unscorable_after(tmp_path, sequence)

    assert "re-run" in _why(said, OTHER), said
    assert "unscorable" not in _why(said, OTHER), said


def test_a_clean_row_after_three_drops_resets_and_scores(tmp_path):
    """D13: dropped x3 then a clean row: the clean newest row scores, set complete, exit 0."""
    rc, said = _unscorable_after(tmp_path, "dddc")

    assert (rc, _verdicts(said)) == (0, {GOOD: "OK", OTHER: "OK"}), said


def test_every_case_not_scored_is_listed_with_its_reason_and_the_set_is_incomplete(tmp_path):
    """O11: one scored, one not run, one stale, one needing a re-run, one unscorable: each is
    listed with its reason; the report says incomplete, exits non-zero, scores only the first."""
    fixtures = _fixture_set(tmp_path / "held-out", {
        "a-scored": "benign", "b-not-run": "benign", "c-stale": "benign",
        "d-rerun": "malicious", "e-unscorable": "malicious"})
    runs = tmp_path / "runs"
    rows: list[Any] = [
        ("a-scored", _ok(runs)),
        _row(fixtures, "c-stale", _ok(runs), verdict="stale"),
        ("d-rerun", _dropped(runs)),
        *(("e-unscorable", _dropped(runs)) for _ in range(3)),
    ]

    rc, said = _scored_rc(tmp_path, runs, fixtures, *rows)

    slugs = {p.name for p in fixtures.iterdir()}
    listed = unscored(said, slugs)
    assert _verdicts(said) == {"a-scored": "OK"}, said
    assert {s: any(w in why for w in words) for s, why, words in [
        ("b-not-run", listed.get("b-not-run", ""), ["not run"]),
        ("c-stale", listed.get("c-stale", ""), ["stale"]),
        ("d-rerun", listed.get("d-rerun", ""), ["re-run"]),
        ("e-unscorable", listed.get("e-unscorable", ""), ["unscorable"]),
    ]} == dict.fromkeys(["b-not-run", "c-stale", "d-rerun", "e-unscorable"], True), said
    assert "Aggregate accuracy: 1/1" in said, said
    assert rc != 0, said
    assert "incomplete" in said.lower(), said
