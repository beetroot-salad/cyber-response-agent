"""#1165 O1/O2/O4/O6: durable operations use the passed Run in real flows."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic_ai import RunContext
from pydantic_ai.toolsets import FunctionToolset

from defender.investigation.tools import AgentDeps

from defender.knowledge._query_rules import PARAMS_NESTING_LIMIT, ParamsTooDeep
from defender.records import run_end
from defender.investigation.run_state import RunState
from defender.investigation import record_query as rq
from defender.tests.support.runtime.records._1165_flows import RecordIO, drive_run, run_handle
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.e2e._replay_harness import GOLDEN_AB3, FakeVerbs, ReplayFn, Turn, materialize


LEAD = "l-001"


def append(state, run, *, params=None, payload='{"hits": [1]}'):
    return rq.append_query_row(
        state, run=run, lead_id=LEAD, system="elastic", verb="query",
        query_id="elastic.probe", params=params if params is not None else {"q": "a"},
        raw_command="elastic query", payload_text=payload, exit_code=0,
        payload_status="ok", payload_digest=rq.payload_digest(payload, "", 0), system_key="")


def test_query_writer_uses_run_and_keeps_state_before_failed_view_append(tmp_path):
    """O6: payload precedes state, state precedes append, and a failed view spends seq."""
    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    state = RunState(run.run_dir, str(run.id))
    observed = []

    def before(root, relative, text, options):
        if relative == "executed_queries.jsonl":
            row = json.loads(text)
            observed.append((row["seq"], state.lead_rows(LEAD)[-1], state.lock._is_owned()))
            assert (run.run_dir / row["payload_path"]).read_bytes() == b'{"hits": [1]}'

    io.before_write = before
    assert append(state, run)["seq"] == 0
    io.fail = ("rooted_write", "executed_queries.jsonl")
    with pytest.raises((OSError, run_end.CallRecordWriteFailed)):
        append(state, run, params={"q": "failed view"})
    assert [r["seq"] for r in state.lead_rows(LEAD)] == [0, 1]
    assert [(seq, row["seq"], locked) for seq, row, locked in observed] == [(0, 0, True), (1, 1, True)]
    assert [json.loads(line)["seq"] for line in run.tables.queries.path.read_text().splitlines()] == [0]
    io.fail = None
    assert append(state, run, params={"q": "after"})["seq"] == 2
    assert io.names("rooted_write").count("executed_queries.jsonl") == 3
    assert "gather_raw/l-001/2.json" in io.names("rooted_write")


def test_query_params_validate_before_any_run_operation_and_payload_fault_is_best_effort(tmp_path):
    """O4/O6: params failure writes nothing; payload refusal leaves a null reference."""
    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    state = RunState(run.run_dir, str(run.id))
    deep = {}
    cursor = deep
    for _ in range(PARAMS_NESTING_LIMIT + 2):
        cursor["k"] = {}
        cursor = cursor["k"]
    with pytest.raises(ParamsTooDeep):
        append(state, run, params=deep)
    assert io.calls == []
    assert state.row_count(LEAD) == 0
    io.fail = ("rooted_write", "gather_raw/l-001/0.json")
    row = append(state, run)
    assert row["seq"] == 0
    assert row["payload_path"] is None
    assert state.lead_rows(LEAD)[-1] == json.loads(run.tables.queries.path.read_text())
    assert "gather_raw/l-001/0.json" in io.names("rooted_write")


def test_parallel_query_writers_keep_the_existing_state_lock_and_order(tmp_path):
    """O6: one state lock orders seq, payload, state row, and file append together."""
    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    state = RunState(run.run_dir, str(run.id))
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda n: append(state, run, params={"n": n}), range(12)))
    assert sorted(r["seq"] for r in rows) == list(range(12))
    disk = [json.loads(line) for line in run.tables.queries.path.read_text().splitlines()]
    assert disk == list(state.lead_rows(LEAD))
    assert [r["seq"] for r in disk] == list(range(12))


@pytest.mark.parametrize("fault", [False, True])
def test_actual_driver_gather_query_and_hooks_use_the_passed_run(tmp_path, fault):
    """O1/O2: MAIN → gather → query uses the repository handle, including its faults."""
    directory = materialize(tmp_path / "fixture", GOLDEN_AB3)
    io = RecordIO()
    run = run_handle(directory, io)
    state = RunState(directory, str(run.id))
    backend_calls = []
    deps_seen = []
    probes = FunctionToolset()

    @probes.tool
    def inspect_run(ctx: RunContext[AgentDeps]) -> str:
        deps_seen.append((ctx.deps.run, ctx.deps.run_state))
        return "observed run identity"

    def query(ctx, *, native_query: str) -> list[dict]:
        backend_calls.append(native_query)
        assert ctx.run_state is state
        return [{"marker": "forwarded"}]

    # Correlation's default script uses an undeclared verb; only MAIN's lead calls query.
    main = ReplayFn([
        Turn(tool_calls=[("inspect_run", {})]),
        Turn(tool_calls=[("gather", {"lead_id": LEAD, "system": "elastic", "goal": "g",
                                     "what_to_summarize": ["e"]})]), Turn(text="done")])
    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                    "params": {"native_query": "select marker"}})]),
        Turn(text="Summary with marker forwarded")])
    if fault:
        io.fail = ("rooted_write", "executed_queries.jsonl")
    def drive():
        return drive_run(run, main, gather=gather,
                         verbs=FakeVerbs({"elastic": {"query": query}}), state=state, toolset=probes)

    if fault:
        # #1235 keeps rows/charges in live state but preserves the append's own failure.
        # No summary or executed_queries recording cut is fabricated from a view failure.
        with pytest.raises(OSError):  # noqa: PT011 — preserve the backend refusal, including its errno
            drive()
    else:
        summary = drive()
    assert deps_seen == [(run, state)]
    if fault:
        assert not run.tables.queries.path.exists()
        assert state.row_count("l-00c") > 0 or state.row_count(LEAD) > 0
    else:
        assert summary["truncated_by"] is None
        assert backend_calls == ["select marker"]
        assert state.lead_rows(LEAD)[-1]["payload_path"] == "gather_raw/l-001/0.json"
        writes = io.names("rooted_write")
        assert "gather_raw/l-001.lead.json" in writes
        assert "gather_raw/l-001/0.json" in writes
        assert "gather_summaries/l-001.md" in writes
        assert "executed_queries.jsonl" in writes
        assert "wire_logs/llm_requests.jsonl" in writes
        assert state.budget_snapshot()["tool_calls"] > 0
    if not fault:
        # A completed run's host facts are rooted beside it, through the passed backend.
        sidecar = run.facts.run_end.path
        assert any(root == sidecar.parent and name == sidecar.name
                   for op, root, name, _mode in io.calls if op == "rooted_write")


def test_driver_refuses_missing_run_before_invoking_a_model(tmp_path):
    """O1: the driver has a required Run, so callers cannot reconstruct one from paths."""
    from defender.investigation import driver
    with pytest.raises(TypeError, match="'run'"):
        # Omit run deliberately; this must fail at the boundary before any setup.
        driver.run_investigation(alert_path=tmp_path / "alert.json", defender_dir=tmp_path,
                                 tenant=None)


def test_budget_and_breaker_decisions_keep_the_same_live_state_across_record_migration(tmp_path, monkeypatch):
    """O6: model-written retired state files cannot reopen the budget or reset the breaker."""
    from defender.hooks import budget_enforcer as budgets
    from defender.systems import circuit_breaker as breaker
    from defender.tests.e2e.test_1235_host_state_in_memory import PlantingReplay

    monkeypatch.setenv("DEFENDER_BUDGET_ENFORCE", "true")
    run = run_handle(materialize(tmp_path / "fixture", GOLDEN_AB3), RecordIO())
    state = RunState(run.run_dir, str(run.id))
    breaker.record_outcome(state, "elastic", 2)
    breaker.record_outcome(state, "elastic", 124)
    assert breaker.is_tripped(state, "elastic")
    before_breaker = state.breaker_snapshot()

    def plant():
        (run.run_dir / "budget.json").write_text('{"tool_calls": 0}')
        (run.run_dir / "circuit_breaker.json").write_text('{"systems": {}, "total_failures": 0}')

    main = PlantingReplay([
        Turn(tool_calls=[("bash", {"command": "echo ran-first"})]),
        Turn(tool_calls=[("bash", {"command": "echo ran-second"})]),
        Turn(tool_calls=[("bash", {"command": "echo forbidden-third"})]),
        Turn(text="done")], at=2, plant=plant)
    result = drive_run(run, main, state=state, limits={
        **budgets.DEFAULT_LIMITS, "max_tool_calls": 2,
        "wall_clock_timeout": 3600, "grace_seconds": 600})
    assert result["truncated_by"] is None
    assert main.planted
    assert state.budget_snapshot()["tool_calls"] == 2
    assert "ran-first" in main.seen[-1]
    assert "ran-second" in main.seen[-1]
    assert "forbidden-third" not in main.seen[-1]
    assert state.breaker_snapshot() == before_breaker
    assert breaker.is_tripped(state, "elastic")
    assert json.loads((run.run_dir / "budget.json").read_text())["tool_calls"] == 0


def test_live_query_reads_ignore_model_file_edits_and_payload_cap_is_preserved(tmp_path):
    """O4/O6: query guards read host rows; oversized payloads keep null references."""
    from defender._io import READ_LIMIT

    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    state = RunState(run.run_dir, str(run.id))
    first = append(state, run)
    planted = dict(first, seq=99, params={"q": "planted"})
    run.tables.queries.path.write_text(json.dumps(planted) + "\n")
    assert rq._next_seq(state, LEAD) == 1
    assert state.lead_rows(LEAD)[-1]["params"] == {"q": "a"}
    reads_before = list(io.calls)
    assert rq.repeat_note(state, LEAD, seq=1, system="elastic", verb="query",
                          params={"q": "a"}, payload_digest=first["payload_digest"],
                          payload_sha256=first["payload_sha256"]) is not None
    assert io.calls == reads_before
    row = append(state, run, payload="x" * (READ_LIMIT + 1))
    assert row["seq"] == 1
    assert row["payload_path"] is None
    assert not run.tables.payloads(LEAD, 1).path.exists()
    assert "gather_raw/l-001/1.json" not in io.names("rooted_write")


def test_lead_claim_uses_the_run_and_preserves_exclusive_statuses_and_exact_bytes(tmp_path):
    """O1/O4: real exclusive claims map collisions and backend faults to old statuses."""
    from defender.hooks.record_lead import ALREADY_CLAIMED, CLAIMED, NOT_CLAIMED, claim_lead

    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    dispatch = {"run_dir": str(run.run_dir), "lead_id": LEAD,
                "goal": "  check the source  ", "what_to_summarize": ["auth events"],
                "provenance": "harness"}
    expected = (json.dumps({"goal": "check the source", "what_to_summarize": ["auth events"],
                            "provenance": "harness"}, indent=2) + "\n").encode()
    assert claim_lead(dispatch, run=run) == CLAIMED
    record = run.tables.leads(LEAD)
    assert record.path.read_bytes() == expected
    assert "gather_raw/l-001.lead.json" in io.names("rooted_write")
    assert claim_lead(dict(dispatch, goal="changed"), run=run) == ALREADY_CLAIMED
    assert record.path.read_bytes() == expected
    io.fail = ("rooted_write", "gather_raw/l-002.lead.json")
    assert claim_lead(dict(dispatch, lead_id="l-002"), run=run) == NOT_CLAIMED
    assert "gather_raw/l-002.lead.json" in io.names("rooted_write")
    assert not run.tables.leads("l-002").path.exists()
    writes = list(io.calls)
    assert claim_lead(dict(dispatch, lead_id="../escape"), run=run) == NOT_CLAIMED
    assert io.calls == writes
