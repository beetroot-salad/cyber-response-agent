"""Pins for control-window derivation (#711).

The whole point of `controls.py` is that "measure a control with the lead's own
predicate" stops being discipline and becomes construction. These tests pin that
property directly: a derived control differs from the lead's query in its two
timestamp literals and in NOTHING else.

Pure only — no ES calls here. `run_esql` and `window_is_live` are I/O and are
exercised by running the tool against the live stack.
"""
from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, UTC
from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


CONTROLS = _load("oracle_golden_controls", GOLDEN_DIR / "controls.py")

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
