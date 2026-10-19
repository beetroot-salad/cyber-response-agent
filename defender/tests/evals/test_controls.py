from __future__ import annotations

import json
from datetime import datetime, timedelta, UTC
from pathlib import Path

import pytest

from evaluations.oracle_golden import controls as CONTROLS


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
UPPER_FIRST_Q = (
    'FROM logs-system.auth-*\n'
    '| WHERE @timestamp < "2026-07-25T07:48:37.065Z" '
    'AND @timestamp >= "2026-07-25T07:45:35.000Z"\n'
    '        AND host.name == "canary-1"\n'
    "| STATS failed_count = COUNT(*) BY source.ip"
)


def test_a_control_changes_the_bounds_and_nothing_else():
    start = datetime(2026, 7, 18, 7, 45, 35, tzinfo=UTC)
    end = datetime(2026, 7, 18, 7, 48, 37, tzinfo=UTC)
    shifted = CONTROLS.shift_esql_window(LEAD_Q, start, end)

    without_times = lambda q: CONTROLS._BOUND.sub(r"\1<T>\3", q)  # noqa: E731
    assert without_times(shifted) == without_times(LEAD_Q)
    assert CONTROLS.esql_bounds(shifted) == ["2026-07-18T07:45:35.000Z",
                                             "2026-07-18T07:48:37.000Z"]


def test_a_control_binds_each_bound_to_its_own_operator_not_its_position():
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
    with pytest.raises(ValueError, match="2 @timestamp bounds"):
        CONTROLS.shift_esql_window(UNBOUNDED_Q, datetime.now(UTC),
                                   datetime.now(UTC))


def test_an_unbounded_query_gets_a_bound_added_after_the_source():
    start = datetime(2026, 7, 25, 7, 45, tzinfo=UTC)
    end = datetime(2026, 7, 25, 7, 49, tzinfo=UTC)
    got = CONTROLS.add_esql_window(UNBOUNDED_Q, start, end)
    lines = got.splitlines()
    assert lines[0] == "FROM logs-zeek.ssh-*"
    assert lines[1].startswith("| WHERE @timestamp >=")
    assert lines[2:] == UNBOUNDED_Q.splitlines()[1:]
    assert len(CONTROLS.esql_bounds(got)) == 2


def test_a_one_line_query_gets_its_bound_before_every_other_command():
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
    assert CONTROLS.split_commands('FROM logs-* | WHERE m RLIKE "a|b" | LIMIT 1') == [
        "FROM logs-* ", ' WHERE m RLIKE "a|b" ', " LIMIT 1"]
    got = CONTROLS.add_esql_window('FROM "logs|weird"', datetime(2026, 7, 25, tzinfo=UTC),
                                   datetime(2026, 7, 25, 1, tzinfo=UTC))
    assert got.splitlines()[0] == 'FROM "logs|weird"', (
        f"the source command was cut at a quoted pipe: {got!r}")


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
    start = datetime(2026, 7, 25, 10, 33, 5, tzinfo=UTC)
    end = datetime(2026, 7, 25, 10, 33, 26, tzinfo=UTC)
    windows = CONTROLS.shape_matched_windows(start, end)
    for _, lo, hi in windows:
        assert (hi - lo).total_seconds() >= CONTROLS.MIN_CONTROL_SECONDS


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
    one = 'FROM logs-* | WHERE @timestamp >= "2026-07-25T07:00:00Z" AND host.name == "x"'
    start = datetime(2026, 7, 25, 7, 0, tzinfo=UTC)
    controls, contribution = CONTROLS.measure_controls(
        one, (7,), operation_window=(start, start + timedelta(hours=1)), dry_run=True)
    assert controls == []
    assert contribution is None


# One producer of the ES|QL payload shape, not two (#834).

def test_controls_emit_the_adapters_payload_shape_because_they_use_its_shaper():
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
    payload = CONTROLS.esql_payload(
        "q", {"columns": [{"name": "first_seen", "type": "date"},
                          {"name": "total", "type": "long"}],
              "values": [["2026-07-25T09:22:37Z", 444]]})

    assert CONTROLS.named_cell(payload, "total") == 444, "the probe read the wrong cell"
    assert CONTROLS.named_cell(payload, "first_seen") == "2026-07-25T09:22:37Z"


def test_a_column_the_probe_did_not_project_is_not_a_zero():
    empty = CONTROLS.esql_payload("q", {"columns": [{"name": "total", "type": "long"}],
                                        "values": []})
    assert CONTROLS.named_cell(empty, "total", default=0) == 0
    assert CONTROLS.named_cell(empty, "total") is None

    mismatched = CONTROLS.esql_payload("q", {"columns": [{"name": "other", "type": "long"}],
                                             "values": [[7]]})
    assert CONTROLS.named_cell(mismatched, "total") is None, "read a cell it cannot name"


CASES_DIR = Path(CONTROLS.__file__).resolve().parent / "cases"

_ESQL_PAYLOAD_KEYS = ("query", "columns", "row_count", "values")


def _esql_payloads_in(doc):
    """Every ES|QL payload ANYWHERE in a document, found by shape.

    Recursive, and classified on the four keys rather than read off a list of the places
    payloads are known to sit (the observed root, `controls[i].payload`,
    `attack_contribution.payload`). The enumerated sweep is precisely the blind spot that
    produced #1054: it is correct until someone adds a fourth position, and then it is
    silently correct about nothing. A payload that moves must still be found.
    """
    if isinstance(doc, dict):
        if all(key in doc for key in _ESQL_PAYLOAD_KEYS):
            yield doc
        for value in doc.values():
            yield from _esql_payloads_in(value)
    elif isinstance(doc, list):
        for value in doc:
            yield from _esql_payloads_in(value)


def _rows_that_are_not_positional(cases_dir: Path) -> tuple[list[str], int]:
    """`(offending files, payloads examined)` over every JSON document under `hidden/`.

    A row is positional when it is a list exactly `len(columns)` long — cell `i` named by
    `columns[i]`, which is what `esql_payload` emits and what `named_cell` reads back. A
    row that is a dict is the pre-#842 form. Zero-byte files are recorded capture
    failures and carry no rows either way.
    """
    offenders: list[str] = []
    examined = 0
    for path in sorted(cases_dir.glob("*/hidden/**/*.json")):
        raw = path.read_bytes()
        if not raw.strip():
            continue
        rel = str(path.relative_to(cases_dir))
        for payload in _esql_payloads_in(json.loads(raw)):
            examined += 1
            width = len(payload["columns"])
            if any(not isinstance(row, list) or len(row) != width
                   for row in payload["values"]) and rel not in offenders:
                offenders.append(rel)
    return offenders, examined


def test_the_corpus_speaks_the_SAME_esql_encoding_production_does():
    offenders, examined = _rows_that_are_not_positional(CASES_DIR)

    assert examined > 0, (
        f"swept {CASES_DIR} and found no ES|QL payload at all — this guard would pass "
        f"over an empty tree, which is not the same fact as a uniform one")
    assert offenders == [], (
        f"{len(offenders)} file(s) under hidden/ still carry pre-#842 dict rows, so a "
        f"judge prompt built from them mixes two encodings: {offenders[:5]}"
        + (f" (+{len(offenders) - 5} more)" if len(offenders) > 5 else ""))


# A control is keyed by the QUERIES TABLE's seq, the same number its observed payload
# is named for — not by the position of the query in `leads.jsonl` (#841).


def test_a_case_built_before_the_seq_field_falls_back_to_the_position(tmp_path):
    case = tmp_path / "case-legacy"
    (case / "oracle_visible").mkdir(parents=True)
    (case / "oracle_visible" / "leads.jsonl").write_text(
        json.dumps({"lead_id": "l-001", "goal": "g", "what_to_summarize": [],
                    "queries": [{"query_id": "elastic.a", "params": {"query": "FROM a"}},
                                {"query_id": "elastic.b", "params": {"query": "FROM b"}}]})
        + "\n", encoding="utf-8")

    assert [seq for _, seq, _ in CONTROLS.lead_queries(case)] == [0, 1]
