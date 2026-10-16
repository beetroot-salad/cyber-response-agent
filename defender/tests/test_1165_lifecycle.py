"""O1/O4: verdict records use the handed run on every lifecycle exit."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from defender import run as launch
from defender.runtime import box
from defender.runtime import scrub as scan
from defender.tests import _tenants1106 as tenants
from defender.tests._1165_flows import RecordIO, run_handle
from defender.tests._alert_plant import plant_alert
from defender.tests._fixture_uuid import fixture_uuid
from defender.tests.e2e._replay_harness import DEFENDER
from defender.tests.e2e.test_540_scrub_lifecycle import FakeDocker


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
    """O1/O4: real start_box threads the callback through every startup refusal arm."""
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    io = RecordIO()
    run = run_handle(tmp_path / fixture_uuid("run"), io)
    plant_alert(run.run_dir, {"id": "alert-1165"})
    record = run.facts.scrub_verdict
    _read, write = callbacks(run)
    if fault:
        io.fail = ("rooted_write", record.path.name)

    def reply(verb):
        refused = {"image": "image", "create": "run", "probe": "exec"}.get(phase)
        return (1, "", f"{phase} refused") if verb == refused else (0, "", "")

    docker = FakeDocker(reply, existing="unknown-state" if phase == "existing" else None)
    with pytest.raises(box.BoxFault):
        box.start_box(run.run_dir, DEFENDER, docker=docker, write_verdict=write)
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
