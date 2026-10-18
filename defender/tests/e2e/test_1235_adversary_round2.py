"""#1235 round 2: the correlation lead's calls ride the run's one RunState; an enforced role with no state raises rather than reaching a live run's state; concurrent breaker charges lose no failure."""
from __future__ import annotations


import contextlib
import sys
import threading

import pytest

pytest.importorskip("pydantic_ai")

from defender.hooks import budget_enforcer as be  # noqa: E402
from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.runtime import circuit_breaker  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.tests.test_budget_seams_631 import _run_dir, drive_agent  # noqa: E402

pytestmark = pytest.mark.e2e

LEAD = "l-001"


# ======================================================================================
# the correlation lead (item 3, l-00c) is a gather lead of THIS run: its calls ride the
# run's one RunState, by reference.
# ======================================================================================

def test_the_correlation_leads_calls_ride_the_runs_one_state(tmp_path):
    from defender.tests.alert_front_door_1222 import _spec1222 as S

    busy = S.run_alert(tmp_path / "busy", run_id="k1-busy",
                       leads={S.L3: [S.query("elastic", "alerts", {"native_query": "k1:1"}),
                                     S.query("elastic", "alerts", {"native_query": "k1:2"}),
                                     S.text(S.DEFAULT_CORRELATION_SUMMARY)]})
    idle = S.run_alert(tmp_path / "idle", run_id="k1-idle")
    mine = [c for c in busy.backend.rec.calls if "k1:" in str(c.params.get("native_query"))]
    assert len(mine) == 2
    assert len(busy.rows_for(S.L3)) == 2
    assert idle.has_sidecar(S.L3)
    assert all(c.ctx.run_state is busy.run_state for c in mine)
    assert list(busy.run_state.lead_rows(S.L3)) == busy.rows_for(S.L3)
    assert busy.budget["tool_calls"] - idle.budget["tool_calls"] == 2


# ======================================================================================
# an enforced role whose deps carry no state raises — it never reaches a live run's state.
# ======================================================================================

def test_a_deps_with_no_state_raises_and_never_reaches_a_live_runs_state(tmp_path):
    """Round 3 (O2, the review's finding 2):"""
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1, "wall_clock_timeout": 3600,
              "grace_seconds": 600}
    run_dir = _run_dir(tmp_path, "k2")
    live = RunState(run_dir, "k2-live")
    be.account_call(live, "bash", limits=limits, tier="core")
    assert live.budget_snapshot()["tool_calls"] == 1
    script = [[("bash", {"command": "echo k2"})]]

    with pytest.raises(TypeError, match="RunState"):
        drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True, state=None)
    assert live.budget_snapshot()["tool_calls"] == 1, (
        "a deps carrying no state counted its call into the live run's state")

    carried, _ = drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True, state=live)
    assert "BUDGET" in str(carried.all_messages()).upper(), (
        "the control: carried, a call on a state at its cap was not refused")


def test_concurrent_breaker_charges_lose_no_failure(tmp_path):
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    per, workers = 2000, 16
    try:
        for trial in range(8):
            state = RunState(tmp_path, f"k7-{trial}")

            def work(w: int, state: RunState = state) -> None:
                for _ in range(per):
                    with contextlib.suppress(circuit_breaker.RunAborted):
                        circuit_breaker.record_outcome(state, f"sys{w % 2}", 2)

            threads = [threading.Thread(target=work, args=(w,)) for w in range(workers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            snap = state.breaker_snapshot()
            assert snap["total_failures"] == per * workers, f"trial {trial} lost a charge"
            assert sum(s["failures"] for s in snap["systems"].values()) == per * workers
    finally:
        sys.setswitchinterval(old)
