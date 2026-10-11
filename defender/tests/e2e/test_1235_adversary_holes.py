"""#1235: the holes the adversary pass found in the first two test commits (14436490).

Each test here fails under one implementation that passed the earlier suite while breaking the
issue's intent, and passes on an honest one:

- a hand-copied run folder still finding its store through an in-folder pointer (X2);
- the query tool opening the live view itself instead of the run start (X3);
- the view reloading from the file between leads (X4);
- a reducer failure's system read from the file (X5);
- the spawn cap or the dispatch-time breaker check honouring a planted file (X6, X8);
- `read_budget` handing out the live state, a gather at the cap still counting a spawn, and
  increments lost without the budget lock (X7a-c)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import branch, session_store  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3, ReplayFn, Turn, VerbRecorder, drive, materialize,
)
from defender.tests.e2e.test_1235_host_state_in_memory import (  # noqa: E402
    PlantingReplay, _cmdb, _registry,
)
from defender.tests.e2e.test_1235_queries_and_pointer import (  # noqa: E402
    OLD_POINTER_NAME, _finished_run, _pointer,
)
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402

pytestmark = pytest.mark.e2e


# X2 — a hand-copied folder reads as "no session" at EVERY pointer reader, not only
# source_store_if_any.
def test_1235_a_hand_copied_folder_has_no_link_at_any_reader(tmp_path):
    run_dir = _finished_run(tmp_path / "a", "k-x2")
    copy = tmp_path / "elsewhere" / "run"
    shutil.copytree(run_dir, copy)
    (copy / OLD_POINTER_NAME).write_text(json.dumps(_pointer(run_dir)), encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        session_store.resolve_store_path(copy)
    with pytest.raises(FileNotFoundError):
        session_store.resolve_session_id(copy)
    with pytest.raises(branch.BranchError):
        branch.open_source_store(copy)
    # control: the original resolves
    assert session_store.resolve_store_path(run_dir) == Path(_pointer(run_dir)["store_path"])


# X3 — no lazy load in the query tool: its row writer on a never-opened folder raises.
def test_1235_the_query_tool_never_opens_the_mirror_itself(tmp_path):
    import asyncio
    from dataclasses import replace

    from defender.runtime.agent_definition import bind
    from defender.runtime.query_tool import QueryCapture
    from defender.tests import _tenants1106
    from defender.tests.e2e._spec771 import DEFENDER

    run_dir = tmp_path / "run"
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    deps = replace(bind(_tenants1106.fixture_gather_def(), run_dir, defender_dir=DEFENDER),
                   lead_id="l-001")
    with pytest.raises(LookupError):
        asyncio.run(QueryCapture(registry=None)._record(
            deps, system="elastic", verb="search", query_id="elastic.ad-hoc", params={},
            payload=[{"a": 1}], exit_code=0, detail="", system_key=""))


_SAME = {"native_query": "FROM logs"}


def _gather(lead: str) -> Turn:
    return Turn(tool_calls=[("gather", {
        "lead_id": lead, "system": "elastic", "goal": "measure this lead",
        "what_to_summarize": ["auth events"]})])


def _copies_for(run_dir: Path, lead: str, n: int) -> None:
    rows = [r for r in map(json.loads, RunPaths(run_dir).executed_queries.read_text(
        encoding="utf-8").splitlines()) if r.get("lead_id") == "l-001"]
    with RunPaths(run_dir).executed_queries.open("a", encoding="utf-8") as fh:  # lint-jsonl-io: ok — adversary plant
        for _ in range(n):
            fh.write(json.dumps({**rows[0], "lead_id": lead}) + "\n")


# X4 — rows planted between two leads do not move the second lead's repeat guard.
def test_1235_rows_planted_between_leads_move_no_guard(tmp_path):
    holder: list[Path] = []
    main = PlantingReplay([_gather("l-001"), _gather("l-002"), Turn(text="done")],
                          at=1, plant=lambda: _copies_for(holder[0], "l-002", 2))
    gather = ReplayFn([q("elastic", "query", _SAME), DONE, q("elastic", "query", _SAME), DONE])
    rec = VerbRecorder()
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    holder.append(run_dir)
    drive(run_dir, run_id="k-x4", main=main, gather=gather, verbs=elastic_ok(rec))
    assert main.planted
    assert len(rec.calls) == 2, "rows planted before lead 2 refused its first request"


# X3b — rows planted before the run's first query are not loaded either.
def test_1235_rows_planted_before_the_first_query_move_no_guard(tmp_path):
    holder: list[Path] = []

    def plant() -> None:
        table = RunPaths(holder[0]).executed_queries
        row = {"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "query",
               "query_id": "elastic.query", "params": _SAME, "raw_command": "x",
               "payload_path": None, "exit_code": 0, "error_class": None,
               "payload_status": "ok", "payload_digest": "d", "payload_sha256": "s",
               "system_key": ""}
        with table.open("a", encoding="utf-8") as fh:  # lint-jsonl-io: ok — adversary plant
            for s in range(2):
                fh.write(json.dumps({**row, "seq": s}) + "\n")

    main = PlantingReplay([_gather("l-001"), Turn(text="done")], at=0, plant=plant)
    gather = ReplayFn([q("elastic", "query", _SAME), DONE])
    rec = VerbRecorder()
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    holder.append(run_dir)
    drive(run_dir, run_id="k-x3b", main=main, gather=gather, verbs=elastic_ok(rec))
    assert main.planted
    assert len(rec.calls) == 1, "rows planted before the first query refused it"


# X5 — a planted row cannot re-attribute a reducer failure to another system.
def test_1235_payload_attribution_reads_the_mirror(tmp_path):
    from defender.scripts.gather_tools import record_query as rq

    run_dir = tmp_path / "run"
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    rq.open_query_mirror(run_dir)
    row = rq.append_query_row(
        run_dir, lead_id="l-001", system="elastic", verb="query", query_id="elastic.q",
        params={"q": "a"}, raw_command="elastic query", payload_text="{}", exit_code=0,
        payload_status="ok", payload_digest="d", system_key="")
    RunPaths(run_dir).executed_queries.write_text(
        json.dumps({**row, "system": "cmdb"}) + "\n", encoding="utf-8")
    operand = run_dir / "gather_raw" / "l-001" / "0.json"
    assert rq.system_for_payload_operands(run_dir, [operand]) == "elastic"


# X6 — a planted spawn count neither refuses a gather (the spawn cap) ...
def test_1235_a_planted_spawn_count_refuses_no_gather(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENDER_BUDGET_ENFORCE", "true")
    holder: list[Path] = []

    def spend() -> None:
        (holder[0] / "budget.json").write_text(json.dumps({
            "run_id": "k-x6", "tool_calls": 0, "subagent_spawns": 10_000}), encoding="utf-8")

    rec = VerbRecorder()
    main = PlantingReplay([Turn(tool_calls=[("gather", {
        "lead_id": "l-001", "system": "cmdb", "goal": "g", "what_to_summarize": ["x"]})]),
        Turn(text="done")], at=0, plant=spend)
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    holder.append(run_dir)
    drive(run_dir, run_id="k-x6", main=main, gather=ReplayFn([_cmdb(1), DONE]),
          verbs=_registry(rec, cmdb_fails=False),
          limits={**DEFAULT_LIMITS, "max_subagent_spawns": 5})
    assert main.planted
    assert len(rec.calls) == 1, "a planted spawn count refused the gather"


# X8 — a breaker file planted before MAIN dispatches the lead does not refuse the dispatch.
def test_1235_a_planted_breaker_file_refuses_no_dispatch(tmp_path):
    holder: list[Path] = []

    def trip() -> None:
        (holder[0] / "circuit_breaker.json").write_text(json.dumps({
            "systems": {"cmdb": {"failures": 5, "tripped_at": "2026-01-01T00:00:00+00:00"}},
            "total_failures": 4}), encoding="utf-8")

    rec = VerbRecorder()
    main = PlantingReplay([Turn(tool_calls=[("gather", {
        "lead_id": "l-001", "system": "cmdb", "goal": "g", "what_to_summarize": ["x"]})]),
        Turn(text="done")], at=0, plant=trip)
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    holder.append(run_dir)
    drive(run_dir, run_id="k-x8", main=main, gather=ReplayFn([_cmdb(1), DONE]),
          verbs=_registry(rec, cmdb_fails=False))
    assert main.planted
    assert len(rec.calls) == 1, "a planted breaker file refused MAIN's dispatch"


# X7 — read_budget answers a copy; a gather at the cap changes nothing; the increment is
# atomic under real preemption.
def test_1235_read_budget_is_a_copy(tmp_path):
    from defender.hooks import budget_enforcer as be
    be.open_budget(tmp_path, "r")
    seen = be.read_budget(tmp_path)
    seen["tool_calls"] = 999
    assert be.read_budget(tmp_path)["tool_calls"] == 0


def test_1235_a_gather_at_the_cap_changes_nothing(tmp_path):
    from defender.hooks import budget_enforcer as be
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    be.open_budget(tmp_path, "r")
    be.account_call(tmp_path, "r", "bash", limits=limits, tier="core")
    be.account_call(tmp_path, "r", "gather", limits=limits, tier="core")
    assert be.read_budget(tmp_path)["subagent_spawns"] == 0


def test_1235_increments_survive_fine_grained_preemption(tmp_path):
    import sys
    import threading
    from defender.hooks import budget_enforcer as be
    be.open_budget(tmp_path, "r")
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 10**9}
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        def work():
            for _ in range(5000):
                be.account_call(tmp_path, "r", "bash", limits=limits, tier="core")
        ts = [threading.Thread(target=work) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    finally:
        sys.setswitchinterval(old)
    assert be.read_budget(tmp_path)["tool_calls"] == 8 * 5000
