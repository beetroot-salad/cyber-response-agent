"""#1347 O5 / G1: a run launched as frozen starts its run clock at the freeze moment."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from defender._clock import z_seconds
from defender.records import RunPaths
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.runtime.state import _1255_clock as C

pytestmark = pytest.mark.e2e

L1 = C.LESSONS[0]
MOMENT = dt.datetime(2026, 10, 20, 8, 0, 0, tzinfo=dt.UTC)
AS_OF = MOMENT + dt.timedelta(hours=1)
CAPTURED_AT = dt.datetime(2026, 10, 20, 9, 3, 17, tzinfo=dt.UTC)


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate configured roots and enable the real unboxed executor."""
    T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")


def frozen_argv(alert: Path, tenant_id: str) -> list[str]:
    """A natural held-out launch told it is frozen (G1 seam: three timestamps on the CLI)."""
    return [*C.natural_argv(alert, tenant_id),
            "--frozen-moment", z_seconds(MOMENT),
            "--as-of", z_seconds(AS_OF),
            "--captured-at", z_seconds(CAPTURED_AT)]


def test_a_frozen_runs_clock_starts_at_the_moment_not_at_launch(tmp_path):
    """O5: the first visible time is the moment plus the run's own elapsed seconds, whatever
    the clock source reads at launch."""
    _base, seed = T.runs_base(tmp_path)
    tenant_id = T.current_tenant().id
    clock = C.FakeClock(C.ARM_START)
    main = C.script(clock, (20, C.read_lesson(L1)), (5, C.DONE))

    out = C.run_main(frozen_argv(RunPaths(seed).alert, tenant_id), clock=clock, main=main)

    assert out.exit == 0, f"the frozen run did not run: exit={out.exit} refusal={out.refusal}"
    assert out.run_dir is not None
    assert C.lesson_reads(out.run_dir, L1) == [C.at(MOMENT, 20)], (
        f"the run clock did not start at the moment {MOMENT}: {C.lesson_rows(out.run_dir)}")
