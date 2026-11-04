"""#1347 O5: a wall-clock moment is restamped onto the run clock by a shift, not collapsed to a reading."""
from __future__ import annotations

import datetime as dt

from defender.investigation.run_state import RunState
from defender.tests.support.runtime.state import _1255_clock as C

AS_OF = dt.datetime(2026, 3, 2, 9, 0, 0, tzinfo=dt.UTC)


def test_on_run_clock_keeps_the_distance_between_two_wall_moments(tmp_path):
    """O5: stamps taken apart on the wall stay as far apart on the run clock; the shift is one offset."""
    state = RunState(tmp_path, "r1", clock=C.FakeClock(AS_OF))
    w1 = dt.datetime.now(dt.UTC)
    w2 = w1 - dt.timedelta(hours=1, minutes=7)

    gap = state.on_run_clock(w1) - state.on_run_clock(w2)

    assert abs((gap - (w1 - w2)).total_seconds()) < 1.0, f"the stamps' distance changed: {gap}"


def test_on_run_clock_lands_a_wall_now_on_the_run_clocks_reading(tmp_path):
    """O5 positive control: the wall moment of the call reads as the run clock, not as the wall."""
    state = RunState(tmp_path, "r1", clock=C.FakeClock(AS_OF))

    moved = state.on_run_clock(dt.datetime.now(dt.UTC))

    assert abs((moved - AS_OF).total_seconds()) < 5.0, f"{moved} is not the run clock's reading"
