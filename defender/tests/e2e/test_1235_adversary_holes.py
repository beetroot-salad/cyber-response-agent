"""#1235: run-state edge cases: a payload's system is attributed from the run's state not a planted row, a gather at the cap counts no spawn, and budget increments survive thread preemption."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid



from defender.tests.support.shared.contracts._spec1077 import fixture_run

import json

import pytest

pytest.importorskip("pydantic_ai")

from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.records import RunPaths  # noqa: E402

pytestmark = pytest.mark.e2e


_SAME = {"native_query": "FROM logs"}


# X5 — a planted row cannot re-attribute a reducer failure to another system.
def test_1235_payload_attribution_reads_the_runs_state(tmp_path):
    from defender.investigation.run_state import RunState
    from defender.investigation import record_query as rq

    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    run_dir = tmp_path / fixture_uuid("run")
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    state = RunState(run_dir, "k-x5")
    row = rq.append_query_row(
        state, run=fixture_run(state.run_dir), lead_id="l-001", system="elastic", verb="query", query_id="elastic.q",
        params={"q": "a"}, raw_command="elastic query", payload_text="{}", exit_code=0,
        payload_status="ok", payload_digest="d", system_key="")
    RunPaths(run_dir).executed_queries.write_text(
        json.dumps({**row, "system": "cmdb"}) + "\n", encoding="utf-8")
    operand = run_dir / "gather_raw" / "l-001" / "0.json"
    assert rq.system_for_payload_operands(state, [operand]) == "elastic"


def test_1235_a_gather_at_the_cap_changes_nothing(tmp_path):
    from defender.hooks import budget_enforcer as be
    from defender.investigation.run_state import RunState
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    state = RunState(tmp_path, "r")
    be.account_call(state, "bash", limits=limits, tier="core")
    be.account_call(state, "gather", limits=limits, tier="core")
    assert state.budget_snapshot()["subagent_spawns"] == 0
    assert state.budget_snapshot()["tool_calls"] == 1


def test_1235_increments_survive_fine_grained_preemption(tmp_path):
    import sys
    import threading
    from defender.hooks import budget_enforcer as be
    from defender.investigation.run_state import RunState
    state = RunState(tmp_path, "r")
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 10**9}
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        def work():
            for _ in range(5000):
                be.account_call(state, "bash", limits=limits, tier="core")
        ts = [threading.Thread(target=work) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    finally:
        sys.setswitchinterval(old)
    assert state.budget_snapshot()["tool_calls"] == 8 * 5000
