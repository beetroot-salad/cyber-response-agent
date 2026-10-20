"""#1165 O1/O4/O7: fork reads belong to the opened source Run."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid


import pytest

from defender.runtime import branch
from defender.runtime.run_state import RunState
from defender.tests.support.runtime.records._1165_flows import RecordIO, drive_run, run_handle
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.support.learning.branch._branch_947 import GOLDEN_INVESTIGATION, planted_source, spec_at
from defender.tests.support.storage._session_store_705 import runs_base
from defender.tests.e2e._replay_harness import ReplayFn, Turn


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
    """O2/O7: legacy missing-alert fallback replaces an existing stale input record."""
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
    """O1: the driver store factory reads the source session pointer through source Run."""
    store, spec, source, _target, _state, source_io, _target_io = source_and_sibling(tmp_path)
    store.close()
    factory = branch.store_factory_for(spec, source_run=source)
    opened = factory("ignored", tmp_path / "ignored")
    assert opened.path == store.path
    opened.close()
    pointer = source.observability.session_pointer.path
    relative = str(pointer.relative_to(source.runs_base))
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
    from defender.run_repository import RunPaths
    from defender.tests.support.runtime.state import _1255_snapshot as S

    driven = S.drive_source(tmp_path, (S.append(S.chunks(3)[0]), S.echo("x"), S.done()))
    spec = S.spec_for(driven, S.tool_calling_responses(driven.store)[1])
    store_path = driven.store.path
    driven.store.close()
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
