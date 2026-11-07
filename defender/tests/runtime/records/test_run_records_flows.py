"""#1165: durable operations use the passed Run in real flows.

#1165: fork reads belong to the opened source Run.

Scrub-verdict records use the handed run on every lifecycle exit.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

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
from defender.tests.support.shared._locations_1210 import location_path
from defender.investigation import branch
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.support.learning.branch._branch_947 import GOLDEN_INVESTIGATION, planted_source, spec_at
from defender.tests.support.storage._session_store_705 import runs_base
from defender.tests.e2e._replay_harness import ReplayFn, Turn
from defender import run as launch
from defender import box
from defender.box import _scrub as scan
from defender.tests.support.tenancy import _tenants1106 as tenants
from defender.tests.support.runtime.records._1165_flows import RecordIO, run_handle
from defender.tests.e2e._replay_harness import DEFENDER
from defender.tests.e2e.test_540_scrub_lifecycle import FakeDocker
from defender.tests.support.tenancy._host1214 import TEST_TENANT


LEAD = "l-001"


def append(state, run, *, params=None, payload='{"hits": [1]}'):
    return rq.append_query_row(
        state, run=run, lead_id=LEAD, system="elastic", verb="query",
        query_id="elastic.probe", params=params if params is not None else {"q": "a"},
        raw_command="elastic query", payload_text=payload, exit_code=0,
        payload_status="ok", payload_digest=rq.payload_digest(payload, "", 0), system_key="")


def test_query_writer_uses_run_and_keeps_state_before_failed_view_append(tmp_path):
    """Payload precedes state, state precedes append, and a failed view spends seq."""
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
    """Params failure writes nothing; payload refusal leaves a null reference."""
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
    """One state lock orders seq, payload, state row, and file append together."""
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
    """MAIN → gather → query uses the repository handle, including its faults."""
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
        # Rows and charges stay in live state (#1235) but the append's own failure propagates:
        # no summary or recording cut is fabricated from a view failure.
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
    """The driver has a required Run, so callers cannot reconstruct one from paths."""
    from defender.investigation import driver
    with pytest.raises(TypeError, match="'run'"):
        # Omit run deliberately; this must fail at the boundary before any setup.
        driver.run_investigation(alert_path=tmp_path / "alert.json", defender_dir=tmp_path,
                                 tenant=None)


def test_budget_and_breaker_decisions_keep_the_same_live_state_across_record_migration(tmp_path, monkeypatch):
    """Model-written retired state files cannot reopen the budget or reset the breaker."""
    from defender.hooks import budget_enforcer as budgets
    from defender.systems import circuit_breaker as breaker
    from defender.tests.e2e.test_run_state_in_memory import PlantingReplay

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
    """Query guards read host rows; oversized payloads keep null references."""
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
    """Real exclusive claims map collisions and backend faults to the existing statuses."""
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


#: The source's run folder name — `planted_source`'s, passed to it explicitly so `plant` can be
#: handed the same folder before the source is built.
SOURCE_RUN = fixture_uuid("run-source-001")


def source_and_sibling(tmp_path, *, document=None, plant=None):
    """The planted source, its sibling, and the spec the sibling forks the source by."""
    text = document if document is not None else GOLDEN_INVESTIGATION.read_text(encoding="utf-8")
    source_io, target_io = RecordIO(), RecordIO()
    source = run_handle(runs_base(tmp_path) / SOURCE_RUN, source_io)
    if plant is not None:
        plant(source)
    store, directory, _session, ids = planted_source(tmp_path, investigation=text, name=SOURCE_RUN)
    assert directory == source.run_dir, (directory, source.run_dir)
    target = run_handle(directory.parent / fixture_uuid("run-sibling"), target_io)
    spec = spec_at(store, directory, ids[-1])
    state = RunState(target.run_dir, str(target.id))
    return store, spec, source, target, state, source_io, target_io


def seed(store, spec, source, target, state):
    snapshot = branch.snapshot_at(store, spec, source_run=source)
    assert snapshot is not None
    snapshot.verify(source)
    branch.restore_run_folder(snapshot, state, run=target, source_run=source)


def test_fork_retains_current_alert_bytes_for_the_same_id_and_inherits_verified_fallback(tmp_path):
    store, spec, source, target, state, _source_io, _target_io = source_and_sibling(tmp_path)
    # Same alert identifier, changed content: seeding must not compare digest and overwrite it.
    source_bytes = b'{"id":"same-alert","generation":"source"}\n'
    target_bytes = b'{"id":"same-alert","generation":"current"}\n'
    plant_alert(source.run_dir, source_bytes)
    plant_alert(target.run_dir, target_bytes)
    target_record = target.facts.alert_record.path.read_bytes()
    seed(store, spec, source, target, state)
    assert target.facts.alert.path.read_bytes() == target_bytes
    assert target.facts.alert_record.path.read_bytes() == target_record
    fallback = run_handle(target.run_dir.parent / fixture_uuid("run-fallback"))
    seed(store, spec, source, fallback, RunState(fallback.run_dir, str(fallback.id)))
    assert fallback.facts.alert.path.read_bytes() == source_bytes
    assert fallback.facts.alert_record.path.read_bytes() == source.facts.alert_record.path.read_bytes()


def test_missing_alert_fallback_replaces_a_stale_record_through_target_run(tmp_path):
    """The missing-alert fallback replaces an existing stale input record."""
    store, spec, source, target, state, _source_io, target_io = source_and_sibling(tmp_path)
    plant_alert(source.run_dir, b'{"id":"source"}\n')
    plant_alert(target.run_dir, b'{"id":"stale"}\n')
    target.facts.alert.path.unlink()
    seed(store, spec, source, target, state)
    assert target.facts.alert.path.read_bytes() == source.facts.alert.path.read_bytes()
    assert target.facts.alert_record.path.read_bytes() == source.facts.alert_record.path.read_bytes()
    name = str(target.facts.alert_record.path.relative_to(target.run_dir))
    assert any(op == "rooted_write" and relative == name and mode == "replace"
               for op, _root, relative, mode in target_io.calls)


def test_fork_copies_only_canonical_owner_names_as_opaque_bytes(tmp_path):
    canonical = {
        "gather_raw/l-001/0.json": b'\xff\x00payload\xfe',
        "gather_raw/l-001/12.json": b'opaque 12',
        "gather_raw/l-001.lead.json": b'\xfeclaim\xff',
        "gather_summaries/l-001.md": b'\xffsummary\xfe',
    }
    # Unknown shapes point outside, so even trying to read/copy them is observably wrong.
    outside = tmp_path / "outside"
    unexpected = [
        "gather_raw/l-001/01.json", "gather_raw/l-001/+1.json",
        "gather_raw/l-001/-1.json", "gather_raw/l-001/notes.txt",
        "gather_raw/l-001/0.json.bak", "gather_raw/l-001.extra.json",
        "gather_raw/l-001.evil", "gather_summaries/l-001.md.bak",
        "gather_summaries/l-001.extra", "gather_raw/l-001/unknown-dir",
    ]

    def plant(source):
        for name, data in canonical.items():
            path = source.run_dir / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        outside.mkdir()
        (outside / "secret").write_bytes(b"must never inherit")
        for name in unexpected:
            (source.run_dir / name).symlink_to(outside, target_is_directory=True)

    store, spec, source, target, state, source_io, target_io = source_and_sibling(
        tmp_path, plant=plant)
    seed(store, spec, source, target, state)
    for name, data in canonical.items():
        assert (target.run_dir / name).read_bytes() == data
        assert any(op.startswith("rooted_") and relative == name
                   for op, _root, relative, _mode in source_io.calls), name
        assert name in target_io.names("rooted_write"), name
    for name in unexpected:
        assert not (target.run_dir / name).exists()
        assert all(relative != name for _op, _root, relative, _mode in source_io.calls)
    assert (outside / "secret").read_bytes() == b"must never inherit"


@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_recognized_source_payload_refusal_still_fails_fork(tmp_path, kind):

    def plant(source):
        path = source.tables.payloads("l-001", 0).path
        path.parent.mkdir(parents=True)
        if kind == "symlink":
            outside = tmp_path / "secret"
            outside.write_bytes(b"outside")
            path.symlink_to(outside)
        else:
            path.mkdir()

    store, spec, source, target, state, _source_io, _target_io = source_and_sibling(
        tmp_path, plant=plant)
    with pytest.raises(branch.BranchError):
        seed(store, spec, source, target, state)
    assert not target.tables.payloads("l-001", 0).path.exists()


def test_source_store_factory_uses_the_opened_source_record_and_cannot_bypass_its_fault(tmp_path):
    """The driver store factory reads the source session pointer through the source Run."""
    store, spec, source, _target, _state, source_io, _target_io = source_and_sibling(tmp_path)
    factory = branch.store_factory_for(spec, source_run=source)
    with factory("ignored", tmp_path / "ignored") as opened:
        assert opened.path == store.path
    pointer = source.observability.session_pointer.path
    relative = str(pointer.relative_to(location_path(source.runs_base)))
    assert any(name == relative for _op, _root, name, _mode in source_io.calls)
    source_io.fail_reads = True
    with pytest.raises(branch.BranchError):
        factory("ignored", tmp_path / "ignored")
    source_io.fail_reads = False
    saved = pointer.read_bytes()
    pointer.unlink()
    outside = tmp_path / "pointer-copy"
    outside.write_bytes(saved)
    pointer.symlink_to(outside)
    with pytest.raises(branch.BranchError):
        factory("ignored", tmp_path / "ignored")


@pytest.mark.parametrize("fault", [False, True])
def test_resumed_driver_threads_source_run_through_validation_seeding_and_lookup(tmp_path, fault):
    from defender.records import RunPaths
    from defender.tests.support.runtime.state import _1255_snapshot as S

    driven = S.drive_source(tmp_path, (S.append(S.chunks(3)[0]), S.echo("x"), S.done()))
    spec = S.spec_for(driven, S.tool_calling_responses(driven.store)[1])
    store_path = driven.store.path
    driven.store.connection.close()
    source_io, target_io = RecordIO(), RecordIO()
    source = run_handle(driven.run_dir, source_io)
    target = run_handle(tmp_path / "sibling" / fixture_uuid("run-sibling"), target_io)
    plant_alert(target.run_dir, RunPaths(driven.run_dir).alert.read_bytes())
    state = RunState(target.run_dir, str(target.id))
    model = ReplayFn([Turn(text="Resumed from held evidence")])
    source_io.fail_reads = fault
    summary = drive_run(target, model, state=state, resume=spec, source_run=source)
    if fault:
        assert summary["truncated_by"] == "store"
        assert model.calls == 0
        assert state.lead_rows("l-00c") == ()
        assert not target.documents.investigation.path.exists()
        return
    assert summary["truncated_by"] is None, summary
    assert str(summary["store_path"]) == str(store_path)
    reads = {relative for op, _root, relative, _mode in source_io.calls if "read" in op}
    assert "executed_queries.jsonl" in reads
    assert source.observability.session_pointer.path.name in reads
    assert list(state.lead_rows("l-00c"))
    assert "investigation.md" in target_io.names("rooted_write")
    assert "executed_queries.jsonl" in target_io.names("rooted_write")


def callbacks(run):
    record = run.facts.scrub_verdict

    def write(doc):
        record.write(json.dumps(doc))

    return record.read, write


@pytest.mark.parametrize("fault", [False, True])
def test_scrub_verdict_write_uses_the_injected_record_even_when_it_fails(tmp_path, fault):
    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    _read, write = callbacks(run)
    record = run.facts.scrub_verdict
    if fault:
        io.fail = ("rooted_write", record.path.name)
    scan.scrub(run.run_dir, write_verdict=write)
    assert record.path.name in io.names("rooted_write")
    if fault:
        assert not record.path.exists(), "a failed handle write was bypassed by a path write"
    else:
        assert json.loads(record.path.read_text()) == {"ran": True, "reason": "walk completed"}


@pytest.mark.parametrize("in_flight", [False, True])
def test_failed_teardown_records_the_skipped_scan_via_the_run(tmp_path, in_flight):
    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    read, write = callbacks(run)
    scanned = []

    def stop(_box):
        raise box.BoxFault("teardown refused")

    def invoke():
        box.stop_and_scrub(SimpleNamespace(sandboxed=True), run.run_dir,
                           stop_box=stop, scrub_tree=scanned.append, in_flight=in_flight,
                           read_verdict=read, write_verdict=write)

    if in_flight:
        invoke()
    else:
        with pytest.raises(box.BoxFault, match="teardown refused"):
            invoke()
    assert scanned == []
    record = run.facts.scrub_verdict
    doc = json.loads(record.path.read_text())
    assert doc["ran"] is False
    assert "teardown refused" in doc["reason"]
    assert record.path.name in io.names("rooted_write")


def test_unsandboxed_marking_reads_and_writes_through_the_run(tmp_path):
    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    read, write = callbacks(run)

    def scrub(tree):
        scan.scrub(tree, write_verdict=write)

    box.stop_and_scrub(SimpleNamespace(sandboxed=False), run.run_dir,
                       stop_box=lambda _: None, scrub_tree=scrub, in_flight=False,
                       read_verdict=read, write_verdict=write)
    record = run.facts.scrub_verdict
    assert json.loads(record.path.read_text()) == {"ran": True, "reason": "walk completed", "sandboxed": False}
    assert io.names("rooted_write").count(record.path.name) == 2
    assert record.path.name in io.names("rooted_read")


def test_launch_binds_the_run_verdict_writer_before_startup_can_fail(tmp_path):
    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    reached = []
    tenant = SimpleNamespace(agent=Path("tenant-agent"), tenant_id=tenants.fixture_tenant().id)

    def start(tree, _defender, *, tenant_agent, tenant_id, write_verdict):
        assert tree == run.run_dir
        assert tenant_agent == tenant.agent
        assert tenant_id == tenant.tenant_id
        write_verdict({"ran": False, "reason": "startup refused"})
        raise box.BoxFault("startup refused")

    with pytest.raises(box.BoxFault, match="startup refused"):
        launch._run_investigation_lifecycle(
            run=run, model="test", model_override=None, defender_dir=Path("defender"),
            tenant=tenant,
            start_box=start, investigate=lambda **kw: reached.append(kw))
    assert reached == []
    record = run.facts.scrub_verdict
    assert json.loads(record.path.read_text())["reason"] == "startup refused"
    assert record.path.name in io.names("rooted_write")


@pytest.mark.parametrize("phase", ["existing", "image", "create", "probe"])
@pytest.mark.parametrize("fault", [False, True])
def test_real_box_startup_refusals_use_the_handed_verdict_backend(tmp_path, monkeypatch, phase, fault):
    """The real `start_box` threads the callback through every startup refusal arm."""
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    plant_alert(run.run_dir, {"id": "alert-1165"})
    record = run.facts.scrub_verdict
    _read, write = callbacks(run)
    if fault:
        io.fail = ("rooted_write", record.path.name)

    def reply(verb):
        refused = {"image": "image", "create": "create", "probe": "exec"}.get(phase)
        return (1, "", f"{phase} refused") if verb == refused else (0, "", "")

    docker = FakeDocker(reply, existing="unknown-state" if phase == "existing" else None)
    with pytest.raises(box.BoxFault):
        box.start_box(run.run_dir, DEFENDER, docker=docker, write_verdict=write, tenant_id=TEST_TENANT)
    assert record.path.name in io.names("rooted_write")
    if fault:
        assert not record.path.exists(), "startup bypassed its refused record backend"
    else:
        doc = json.loads(record.path.read_text())
        assert doc["ran"] is False
        assert doc["reason"]


def test_launch_forwards_the_same_run_and_binds_both_teardown_callbacks(tmp_path):
    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    seen = []
    tenant = SimpleNamespace(agent=Path("tenant-agent"), tenant_id=tenants.fixture_tenant().id)

    def start(tree, _defender, *, tenant_agent, tenant_id, write_verdict):
        assert tree == run.run_dir
        assert tenant_agent == tenant.agent
        assert tenant_id == tenant.tenant_id
        assert callable(write_verdict)
        return SimpleNamespace(sandboxed=False)

    def investigate(**kw):
        seen.append(kw["run"])
        return {"output": "done"}

    result = launch._run_investigation_lifecycle(
        run=run, model="test", model_override=None, defender_dir=Path("defender"),
        tenant=tenant, start_box=start,
        investigate=investigate, stop_box=lambda _: None)
    assert result == {"output": "done"}
    assert seen == [run]
    record = run.facts.scrub_verdict
    assert json.loads(record.path.read_text()) == {"ran": True, "reason": "walk completed", "sandboxed": False}
    assert io.names("rooted_write").count(record.path.name) == 2
    assert record.path.name in io.names("rooted_read")
