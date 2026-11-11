"""#1347 r6.4.6 "Both clocks are anchored at one instant" (Amendment r6.4.6), lab side.

The launcher's clock step runs one shell command in the engine that reads the engine host's clock, writes the offset
`T - now_engine`, and prints that instant W; the run is handed `--as-of T --as-of-anchor W`. The rig engine keeps its
own time (the operator's plus `engine_skew`), so a launcher that reads the operator's clock to compute the offset
writes the skew into it.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from _lab_fakes import T, LabRig, instant
from test_1347_launcher import _offset_writes, _opt

SKEW = timedelta(hours=3, minutes=7)


@pytest.mark.parametrize("skew", [SKEW, -SKEW, timedelta(0)], ids=["engine-ahead", "engine-behind", "no-skew"])
def test_the_offset_is_T_minus_the_engines_own_reading_and_the_run_is_anchored_at_that_reading(tmp_path, skew):
    rig = LabRig(tmp_path, engine_skew=skew)
    rig.write_expected_case("drop")
    rig.launch()
    run_j = rig.journal.first("run")

    reads = [r for r in rig.docker.date_reads if r[0] < run_j]
    assert reads, "the clock step never read the engine's clock"
    read_j, read_at = reads[-1]
    writes = [w for w in _offset_writes(rig) if w[0] < run_j]
    assert writes, "the offset file was never written before the run"
    offset = writes[-1][2]
    assert read_j <= writes[-1][0], "the offset was written before the reading"
    assert abs(offset - (instant(T) - read_at).total_seconds()) <= 1, (offset, read_at)
    operator = instant(T) - writes[-1][1]
    assert abs(offset - operator.total_seconds() + skew.total_seconds()) <= 5, "the operator's clock leaked into the offset"
    assert instant(_opt(rig.argv, "--as-of")) == instant(T)
    assert abs((instant(_opt(rig.argv, "--as-of-anchor")) - read_at).total_seconds()) <= 1, rig.argv


def test_the_engine_is_read_once_for_the_offset_and_the_anchor_alike(tmp_path):
    """The offset and W come from one reading: the last engine reading before the run is the one the anchor names,
    and no later reading was used for the offset."""
    rig = LabRig(tmp_path, engine_skew=SKEW, clock_step=7)
    rig.write_expected_case("none")
    rig.launch()
    run_j = rig.journal.first("run")

    anchor = instant(_opt(rig.argv, "--as-of-anchor"))
    reads = [at for j, at in rig.docker.date_reads if j < run_j]
    assert reads and min(abs((anchor - at).total_seconds()) for at in reads) <= 1
    offset = [w for w in _offset_writes(rig) if w[0] < run_j][-1][2]
    assert abs(offset - (instant(T) - anchor).total_seconds()) <= 1
