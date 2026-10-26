from __future__ import annotations

from dataclasses import replace as _with_fixture_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _fixture_run_1165
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import asyncio
from dataclasses import replace

import pytest

pytest.importorskip("pydantic_ai")

from defender.records import RunPaths  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.query_tool import QueryCapture  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.tests.support.tenancy._tenants1106 import fixture_gather_def  # noqa: E402
from defender.tests.e2e._spec771 import DEFENDER  # noqa: E402


def test_a_capped_call_whose_view_write_is_refused_is_recorded_once(tmp_path):
    # #1187 (declared change 1): a run folder's name is its canonical UUID run id.
    run_dir = tmp_path / fixture_uuid("run")
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    state = RunState(run_dir, "adv3-capped")
    deps = replace(_with_fixture_run_1165(bind(fixture_gather_def(), run_dir, defender_dir=DEFENDER), run=_fixture_run_1165(run_dir)),
                   run_state=state, lead_id="l-00c", harness_lead=True)
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b"")
    RunPaths(run_dir).executed_queries.symlink_to(outside)

    with pytest.raises(OSError, match="alias|link|regular|plain"):
        asyncio.run(QueryCapture(registry=None, known_ids=frozenset())._record(
            deps, system="elastic", verb="query", query_id="elastic.probe", params={},
            payload={"hits": []}, exit_code=0, detail="", system_key=""))

    assert outside.read_bytes() == b""
    rows = state.lead_rows("l-00c")
    assert [(r["seq"], r["verb"], r["exit_code"]) for r in rows] == [(0, "query", 0)]
    assert state.breaker_snapshot()["total_failures"] == 0
