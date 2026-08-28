"""Pins for control-window derivation (#711).

The whole point of `controls.py` is that "measure a control with the lead's own
predicate" stops being discipline and becomes construction. These tests pin that
property directly: a derived control differs from the lead's query in its two
timestamp literals and in NOTHING else.

Pure only — no ES calls here. `run_esql` and `window_is_live` are I/O and are
exercised by running the tool against the live stack.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, UTC
from pathlib import Path

import pytest

from defender.evals.oracle_golden import build_case as BUILD_CASE
from defender.evals.oracle_golden import controls as CONTROLS


# Shaped like a real lead: full predicate, two bounds, an aggregation.
LEAD_Q = (
    'FROM logs-system.auth-*\n'
    '| WHERE @timestamp >= "2026-07-25T07:45:35.000Z" '
    'AND @timestamp < "2026-07-25T07:48:37.065Z"\n'
    '        AND host.name == "canary-1"\n'
    '        AND event.outcome == "failure"\n'
    "| STATS failed_count = COUNT(*) BY source.ip, user.name"
)
UNBOUNDED_Q = ('FROM logs-zeek.ssh-*\n| WHERE source.ip == "172.18.0.15"\n'
               "| STATS events = COUNT(*) BY destination.ip")
# The same lead written on ONE line. ES|QL's `|` is a separator, not a line break, and
# the defender model writes both shapes — `case-010-crosstier-web2/l-006` is this one.
ONE_LINE_UNBOUNDED_Q = "FROM logs-zeek.ssh-* | LIMIT 1"
# The same window as LEAD_Q with its bounds written upper-first, which the model is
# equally free to do — `esql_window` sorts its answer, so only the operators say which
# literal is which.
UPPER_FIRST_Q = (
    'FROM logs-system.auth-*\n'
    '| WHERE @timestamp < "2026-07-25T07:48:37.065Z" '
    'AND @timestamp >= "2026-07-25T07:45:35.000Z"\n'
    '        AND host.name == "canary-1"\n'
    "| STATS failed_count = COUNT(*) BY source.ip"
)


def test_a_control_changes_the_bounds_and_nothing_else():
    """The property the whole module exists for. If a rewrite could touch the
    predicate, a control would describe a different envelope than the lead — the
    exact silent failure that produced case-003's wrong `-noise` label."""
    start = datetime(2026, 7, 18, 7, 45, 35, tzinfo=UTC)
    end = datetime(2026, 7, 18, 7, 48, 37, tzinfo=UTC)
    shifted = CONTROLS.shift_esql_window(LEAD_Q, start, end)

    without_times = lambda q: CONTROLS._BOUND.sub(r"\1<T>\3", q)  # noqa: E731
    assert without_times(shifted) == without_times(LEAD_Q)
    assert CONTROLS.esql_bounds(shifted) == ["2026-07-18T07:45:35.000Z",
                                             "2026-07-18T07:48:37.000Z"]


def test_a_control_binds_each_bound_to_its_own_operator_not_its_position():
    """`esql_window` sorts its pair low-then-high on purpose, so the ONLY thing saying
    which literal is the start is each match's operator. Substituting `[start, end]`
    positionally crossed them for a query that wrote its upper bound first, producing
    `< 19:45 AND >= 20:45` — unsatisfiable. ES|QL runs that happily and returns
    nothing, `window_is_live` probes the window separately and still answers true, so
    the record stores `live: true` with zero rows: the same empty baseline F-20
    produces, and `judge._control` drops the query string, so nothing downstream can
    see the inversion.

    All 510 two-bound queries in the committed cases happen to write the lower bound
    first — an LLM habit, not an invariant this module is entitled to assume.
    """
    start = datetime(2026, 7, 18, 7, 45, 35, tzinfo=UTC)
    end = datetime(2026, 7, 18, 7, 48, 37, tzinfo=UTC)
    shifted = CONTROLS.shift_esql_window(UPPER_FIRST_Q, start, end)

    without_times = lambda q: CONTROLS._BOUND.sub(r"\1<T>\3", q)  # noqa: E731
    assert without_times(shifted) == without_times(UPPER_FIRST_Q)
    # Source order is upper-then-lower, so the literals must come back in that order.
    assert CONTROLS.esql_bounds(shifted) == ["2026-07-18T07:48:37.000Z",
                                             "2026-07-18T07:45:35.000Z"]
    # The property that actually matters: the rewritten window is still satisfiable,
    # and it is the window that was asked for.
    assert CONTROLS.esql_window(shifted) == (start, end)


def test_a_pair_of_bounds_pointing_the_same_way_is_not_a_window():
    """Two literals are not a window. `>= A AND > B` bounds nothing above, so there is
    no start to shift onto one and no end onto the other — refused at both the
    `esql_window` read and the rewrite, in the spirit of the odd-bound-count guard."""
    same_way = ('FROM logs-* | WHERE @timestamp >= "2026-07-25T07:00:00Z" '
                'AND @timestamp > "2026-07-25T08:00:00Z"')
    assert CONTROLS.esql_window(same_way) is None
    with pytest.raises(ValueError, match="one lower and one upper"):
        CONTROLS.shift_esql_window(same_way, datetime.now(UTC), datetime.now(UTC))


def test_a_same_way_bound_pair_is_refused_rather_than_measured():
    """The reachable path: `measure_controls` must route it to the same refusal the
    odd-bound count gets, not let a `ValueError` out of a whole-case control run."""
    same_way = ('FROM logs-* | WHERE @timestamp >= "2026-07-25T07:00:00Z" '
                'AND @timestamp > "2026-07-25T08:00:00Z"')
    start = datetime(2026, 7, 25, 7, 0, tzinfo=UTC)
    controls, contribution = CONTROLS.measure_controls(
        same_way, (7,), operation_window=(start, start + timedelta(hours=1)),
        dry_run=True)
    assert controls == []
    assert contribution is None


def test_shifting_a_query_with_no_bounds_is_an_error_not_a_no_op():
    """Silently returning the query unchanged would produce a "control" that
    re-measures the attack window, reporting every event as baseline and turning
    every `+event` into `+noise` — the most dangerous failure this module has."""
    with pytest.raises(ValueError, match="2 @timestamp bounds"):
        CONTROLS.shift_esql_window(UNBOUNDED_Q, datetime.now(UTC),
                                   datetime.now(UTC))


def test_an_unbounded_query_gets_a_bound_added_after_the_source():
    """Adding a `WHERE @timestamp` narrows the row set and cannot widen it, which
    is the property that matters. case-001's six zeek leads carry no bound, so
    their stored payload mixes the attack with months of history."""
    start = datetime(2026, 7, 25, 7, 45, tzinfo=UTC)
    end = datetime(2026, 7, 25, 7, 49, tzinfo=UTC)
    got = CONTROLS.add_esql_window(UNBOUNDED_Q, start, end)
    lines = got.splitlines()
    assert lines[0] == "FROM logs-zeek.ssh-*"
    assert lines[1].startswith("| WHERE @timestamp >=")
    assert lines[2:] == UNBOUNDED_Q.splitlines()[1:]
    assert len(CONTROLS.esql_bounds(got)) == 2


def test_a_one_line_query_gets_its_bound_before_every_other_command():
    """The property above, driven on the shape that broke it. This used to splice
    after `splitlines()[0]`, so a whole pipeline written on one line got the clause
    appended after `LIMIT` — one arbitrary row taken and THEN timestamp-filtered.
    That is not a narrower row set but an empty one, and a zero-row control reads
    downstream as an empty baseline against which every observed row is
    distinguishable, so the label pass grades the lead `present`.

    `case-010-crosstier-web2/hidden/controls/l-006/1.json` is the artifact: three
    controls at `live: true, row_count: 0` for exactly this query, in a `held-out`
    case. Its sibling `6.json` is the same index over the same three windows written
    multi-line and returns 20 rows in each.
    """
    start = datetime(2026, 7, 25, 7, 45, tzinfo=UTC)
    end = datetime(2026, 7, 25, 7, 49, tzinfo=UTC)
    got = CONTROLS.add_esql_window(ONE_LINE_UNBOUNDED_Q, start, end)

    commands = [c.strip() for c in got.split("|")]
    assert commands[0] == "FROM logs-zeek.ssh-*", "the source command must stay first"
    assert commands[1].startswith("WHERE @timestamp >="), (
        f"the window must precede every other command, got {commands!r}")
    assert commands[2:] == ["LIMIT 1"], "the rest of the pipeline must survive verbatim"
    assert len(CONTROLS.esql_bounds(got)) == 2


def test_a_pipe_inside_a_string_literal_is_not_a_command_separator():
    """`|` is a separator only outside a string. `WHERE message RLIKE "sshd|sudo"` carries
    one as DATA, and splitting on it cuts the predicate in half — the clause would land
    mid-literal and the control would not parse, while a reader counting commands off the
    same naive split names the wrong command as the one that ran first."""
    assert CONTROLS.split_commands('FROM logs-* | WHERE m RLIKE "a|b" | LIMIT 1') == [
        "FROM logs-* ", ' WHERE m RLIKE "a|b" ', " LIMIT 1"]
    got = CONTROLS.add_esql_window('FROM "logs|weird"', datetime(2026, 7, 25, tzinfo=UTC),
                                   datetime(2026, 7, 25, 1, tzinfo=UTC))
    assert got.splitlines()[0] == 'FROM "logs|weird"', (
        f"the source command was cut at a quoted pipe: {got!r}")


def test_a_source_only_query_still_gets_its_bound():
    """A query with no `|` at all has no command to precede — the clause is appended,
    and appending is correct here precisely because there is nothing after it."""
    start = datetime(2026, 7, 25, 7, 45, tzinfo=UTC)
    end = datetime(2026, 7, 25, 7, 49, tzinfo=UTC)
    got = CONTROLS.add_esql_window("FROM logs-zeek.ssh-*", start, end)
    assert got.splitlines()[0] == "FROM logs-zeek.ssh-*"
    assert got.splitlines()[1].startswith("| WHERE @timestamp >=")
    assert len(CONTROLS.esql_bounds(got)) == 2


def test_adding_a_bound_to_a_bounded_query_is_refused():
    with pytest.raises(ValueError, match="already carries"):
        CONTROLS.add_esql_window(LEAD_Q, datetime.now(UTC),
                                 datetime.now(UTC))


def test_control_windows_keep_the_weekday():
    """The Poisson baseline generators are schedule-shaped, so a weekday control
    for a weekend capture is not a control. Whole-week offsets preserve it."""
    start = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)   # a Saturday
    end = start + timedelta(hours=2)
    for _, lo, _hi in CONTROLS.shape_matched_windows(start, end):
        assert lo.weekday() == start.weekday()


def test_a_short_operation_still_gets_a_long_enough_control():
    """case-004's operation lasted 21 seconds. Duration-matched 21-second controls
    observed almost nothing, so a routine `sre.alice` login graded `+event` — a
    manufactured catch. Controls widen to at least MIN_CONTROL_SECONDS."""
    start = datetime(2026, 7, 25, 10, 33, 5, tzinfo=UTC)
    end = datetime(2026, 7, 25, 10, 33, 26, tzinfo=UTC)
    windows = CONTROLS.shape_matched_windows(start, end)
    for _, lo, hi in windows:
        assert (hi - lo).total_seconds() >= CONTROLS.MIN_CONTROL_SECONDS


def test_a_long_operation_keeps_its_own_duration():
    """Widening is a floor, not a fixed size — a two-hour operation is not
    controlled against one hour."""
    start = datetime(2026, 7, 25, 8, 0, tzinfo=UTC)
    end = start + timedelta(hours=2)
    for _, lo, hi in CONTROLS.shape_matched_windows(start, end):
        assert (hi - lo) == timedelta(hours=2)


def test_the_control_window_is_centred_on_the_operation():
    start = datetime(2026, 7, 25, 10, 30, tzinfo=UTC)
    end = datetime(2026, 7, 25, 10, 40, tzinfo=UTC)
    _, lo, hi = CONTROLS.shape_matched_windows(start, end, (7,))[0]
    midpoint_operation = (start + (end - start) / 2) - timedelta(days=7)
    assert lo + (hi - lo) / 2 == midpoint_operation


@pytest.mark.parametrize("literal", [
    "2026-07-25T07:45:35.000Z",     # with millis
    "2026-07-25T07:45:35Z",         # without
])
def test_both_timestamp_literal_shapes_parse(literal):
    assert CONTROLS.parse_iso(literal).year == 2026


def test_a_query_with_one_bound_has_no_window():
    """One bound is not a window, and guessing the other would invent a control."""
    one = 'FROM logs-* | WHERE @timestamp >= "2026-07-25T07:00:00Z"'
    assert CONTROLS.esql_window(one) is None


def test_a_query_with_an_odd_bound_count_is_refused_not_patched():
    """Neither route is safe on one bound: there is nothing to shift, and ADDING a
    window would leave the original bound in place, so the "control" would filter
    on a mix of the attack window and the baseline window. Real defender queries
    carry this shape — it crashed the first campaign run."""
    one = 'FROM logs-* | WHERE @timestamp >= "2026-07-25T07:00:00Z" AND host.name == "x"'
    start = datetime(2026, 7, 25, 7, 0, tzinfo=UTC)
    controls, contribution = CONTROLS.measure_controls(
        one, (7,), operation_window=(start, start + timedelta(hours=1)), dry_run=True)
    assert controls == []
    assert contribution is None


# One producer of the ES|QL payload shape, not two (#834).

def test_controls_emit_the_adapters_payload_shape_because_they_use_its_shaper():
    """This module's docstring promises payloads "in the SAME shape the production `esql` verb
    stores", so `label.py` compares an attack window against its controls like with like. That
    promise used to rest on a SECOND copy of the adapter's zip living here — two producers, one
    invariant, and nothing keeping them equal. #834 changed the shape; a hand-maintained copy
    would have left `label.py` comparing dicts against arrays and calling it a measurement.

    Pinned at the seam rather than by re-asserting the shape: `run_esql` is I/O and untestable
    here, but the shaping it delegates to is not.
    """
    from defender.scripts.adapters import elastic_adapter

    assert CONTROLS.esql_payload is elastic_adapter.esql_payload, (
        "controls.py has grown its own copy of the payload shaper again"
    )


def test_the_esql_payload_leaves_rows_as_the_wire_sent_them():
    """`values` stays columnar: names once in `columns`, rows as bare arrays. The liveness
    probe below reads them positionally, which is only sound if nothing re-zips on the way."""
    raw = {"columns": [{"name": "total", "type": "long"}], "values": [[444]]}
    payload = CONTROLS.esql_payload("FROM logs-* | STATS total = COUNT(*)", raw)

    assert payload["values"] == [[444]]
    assert payload["row_count"] == 1
    assert payload["columns"] == raw["columns"]


def test_the_liveness_probe_reads_its_column_by_name_not_by_luck():
    """`named_cell` — the reader `window_is_live` runs — resolves `total`'s INDEX off
    `columns` rather than hardcoding 0. The probe projects one column today; a positional read
    that assumed so would misreport liveness the day it projects two, and a false "not live"
    silently drops a case from the measurement.

    Driven through the production reader, not a copy of it: an earlier version of this test
    re-derived the index inline and asserted on its own arithmetic, so it stayed green for
    every regression `window_is_live` could have. `window_is_live` itself is I/O and stays
    unexercised here; what is pinned is the only part of it that decides which cell is read.
    """
    payload = CONTROLS.esql_payload(
        "q", {"columns": [{"name": "first_seen", "type": "date"},
                          {"name": "total", "type": "long"}],
              "values": [["2026-07-25T09:22:37Z", 444]]})

    assert CONTROLS.named_cell(payload, "total") == 444, "the probe read the wrong cell"
    assert CONTROLS.named_cell(payload, "first_seen") == "2026-07-25T09:22:37Z"


def test_a_column_the_probe_did_not_project_is_not_a_zero():
    """An absent column and a measured zero are different facts. `named_cell` returns the
    caller's `default` for both "no such column" and "no rows" — `window_is_live` passes 0
    there deliberately (a window with no ingest is dead), and the day a caller needs to tell
    the two apart it can pass `None` instead of inferring it from a fabricated zero."""
    empty = CONTROLS.esql_payload("q", {"columns": [{"name": "total", "type": "long"}],
                                        "values": []})
    assert CONTROLS.named_cell(empty, "total", default=0) == 0
    assert CONTROLS.named_cell(empty, "total") is None

    mismatched = CONTROLS.esql_payload("q", {"columns": [{"name": "other", "type": "long"}],
                                             "values": [[7]]})
    assert CONTROLS.named_cell(mismatched, "total") is None, "read a cell it cannot name"


# A control is keyed by the QUERIES TABLE's seq, the same number its observed payload
# is named for — not by the position of the query in `leads.jsonl` (#841).

def _write_run(run: Path, lead_id: str, rows: list[tuple[int, str]]) -> None:
    """A run dir carrying the two tables, written the way the run writes them.

    `rows` is `(seq, query_id)`; a `∅.`-prefixed id is a sentinel — a writer-only record
    of something that never reached a system. `_next_seq` counts every row including
    those, which is the whole of why position and seq can diverge.
    """
    gd = run / "gather_raw"
    (gd / lead_id).mkdir(parents=True, exist_ok=True)
    (gd / f"{lead_id}.lead.json").write_text(
        json.dumps({"goal": "trace the write", "what_to_summarize": ["auth events"]}),
        encoding="utf-8")
    with (run / "executed_queries.jsonl").open("a", encoding="utf-8") as fh:
        for seq, query_id in rows:
            (gd / lead_id / f"{seq}.json").write_text(
                json.dumps({"columns": [], "values": [], "row_count": 0}), encoding="utf-8")
            fh.write(json.dumps({
                "lead_id": lead_id, "seq": seq, "system": "elastic", "verb": "query",
                "query_id": query_id,
                "params": {"query": f'FROM logs-* | WHERE q == "{seq}"'},
                "raw_command": "python3 elastic_adapter.py query",
                "payload_path": f"gather_raw/{lead_id}/{seq}.json",
                "exit_code": 0, "error_class": None,
                "payload_status": "ok", "payload_digest": "44 bytes, 1 line(s)",
            }) + "\n")


def test_a_control_is_keyed_by_the_seq_its_observed_payload_is_named_for(tmp_path):
    """The pairing this module's whole output rests on. Control records are written to
    `hidden/controls/{lead}/{seq}.json` and observed payloads to
    `hidden/observed/{lead}/{seq}.json`, and `judge.load_lead_inputs` joins them on that
    number. They were the same until #841 split the `∅.`-prefixed sentinels out of
    `JoinedLead.queries` while `record_query._next_seq` went on counting every row — so
    one refused query ahead of a real one makes the list position trail the table's seq
    for the rest of the lead.

    Keyed by position, query A's envelope is then diffed against query B's baseline, B
    gets no baseline at all, and baseline 0 has no envelope. `judge._control` drops the
    control's query string, so nothing downstream can detect the mispairing.

    A sentinel FIRST is the discriminating shape: with it last, position and seq agree
    for every real query and a broken keying passes.
    """
    run = tmp_path / "run"
    _write_run(run, "l-001", [(0, "∅.repeat-trip"), (1, "elastic.auth-by-host"),
                              (2, "elastic.auth-by-user")])
    case = tmp_path / "case-a"
    (tmp_path / "story.md").write_text("a story", encoding="utf-8")
    (tmp_path / "controls.yaml").write_text("{}\n", encoding="utf-8")
    assert BUILD_CASE.main([str(run), str(tmp_path / "story.md"),
                            str(tmp_path / "controls.yaml"), str(case)]) == 0

    observed = sorted(p.name for p in (case / "hidden" / "observed" / "l-001").glob("*.json"))
    assert observed == ["1.json", "2.json"], "the sentinel contributes no observed payload"

    seqs = [seq for lead_id, seq, _ in CONTROLS.lead_queries(case) if lead_id == "l-001"]
    assert seqs == [1, 2], (
        f"controls would be keyed {seqs}, but the payloads they pair with are {observed}")


def test_a_case_built_before_the_seq_field_falls_back_to_the_position(tmp_path):
    """The 17 committed cases carry no `seq` in `leads.jsonl`, and all predate #841 — no
    sentinel was ever split out of their `queries`, so position IS seq for them and the
    fallback is exact rather than a guess. Pinned so a later reader cannot mistake it for
    a general-purpose default and start relying on it for new cases."""
    case = tmp_path / "case-legacy"
    (case / "oracle_visible").mkdir(parents=True)
    (case / "oracle_visible" / "leads.jsonl").write_text(
        json.dumps({"lead_id": "l-001", "goal": "g", "what_to_summarize": [],
                    "queries": [{"query_id": "elastic.a", "params": {"query": "FROM a"}},
                                {"query_id": "elastic.b", "params": {"query": "FROM b"}}]})
        + "\n", encoding="utf-8")

    assert [seq for _, seq, _ in CONTROLS.lead_queries(case)] == [0, 1]
