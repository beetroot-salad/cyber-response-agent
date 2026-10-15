"""#1165 O1/O4/O7: fork reads belong to the opened source Run."""
from __future__ import annotations


import pytest

from defender.runtime import branch
from defender.runtime.run_state import RunState
from defender.tests._1165_flows import RecordIO, drive_run, run_handle
from defender.tests._alert_plant import plant_alert
from defender.tests._branch_947 import GOLDEN_INVESTIGATION, planted_source, spec_at
from defender.tests.e2e._replay_harness import ReplayFn, Turn


def source_and_sibling(tmp_path, *, document=None):
    text = document if document is not None else GOLDEN_INVESTIGATION.read_text(encoding="utf-8")
    store, directory, _session, ids = planted_source(tmp_path, investigation=text)
    source_io, target_io = RecordIO(), RecordIO()
    source, target = run_handle(directory, source_io), run_handle(directory.parent / "run-sibling", target_io)
    spec = spec_at(store, directory, ids[-1])
    state = RunState(target.run_dir, str(target.id))
    return store, spec, source, target, state, source_io, target_io


def seed(store, spec, source, target, state):
    return branch.seed_investigation(store, spec, state, run=target, source_run=source)


def test_fork_retains_current_alert_bytes_for_the_same_id_and_inherits_verified_fallback(tmp_path):
    """O7: a materialized current alert wins; a sibling lacking one gets verified source bytes."""
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

    fallback = run_handle(target.run_dir.parent / "run-fallback")
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
    """O7: canonical payload/claim/summary bytes survive even when they are not UTF-8."""
    store, spec, source, target, state, source_io, target_io = source_and_sibling(tmp_path)
    canonical = {
        "gather_raw/l-001/0.json": b'\xff\x00payload\xfe',
        "gather_raw/l-001/12.json": b'opaque 12',
        "gather_raw/l-001.lead.json": b'\xfeclaim\xff',
        "gather_summaries/l-001.md": b'\xffsummary\xfe',
    }
    for name, data in canonical.items():
        path = source.run_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    # Unknown shapes point outside, so even trying to read/copy them is observably wrong.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"must never inherit")
    unexpected = [
        "gather_raw/l-001/01.json", "gather_raw/l-001/+1.json",
        "gather_raw/l-001/-1.json", "gather_raw/l-001/notes.txt",
        "gather_raw/l-001/0.json.bak", "gather_raw/l-001.extra.json",
        "gather_raw/l-001.evil", "gather_summaries/l-001.md.bak",
        "gather_summaries/l-001.extra", "gather_raw/l-001/unknown-dir",
    ]
    for name in unexpected:
        (source.run_dir / name).symlink_to(outside, target_is_directory=True)
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
    """O4/O7: selecting a recognized artifact never turns a refused read into absence."""
    store, spec, source, target, state, _source_io, _target_io = source_and_sibling(tmp_path)
    path = source.tables.payloads("l-001", 0).path
    path.parent.mkdir(parents=True)
    if kind == "symlink":
        outside = tmp_path / "secret"
        outside.write_bytes(b"outside")
        path.symlink_to(outside)
    else:
        path.mkdir()
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
    """O1: real resumed driver uses separate source Run for every selected durable read.

    #1255: re-fixtured onto a DRIVEN source branched at a D1 branch point (a MAIN response that
    called tools). The hand-planted `legal_source` this used to branch has no fork snapshot (N4)
    and its branch point was a tool RETURN, which D1 no longer admits. The read set no longer
    names `investigation.md`: the document is restored from the snapshot's recorded CONTENT
    (P2), so whether the restore reads the source's file at all is the implementation's.

    Regression over the new branch point (D1): it passes once D1 lands, fork snapshot or not,
    so it is not evidence for the snapshot (P2)."""
    from defender.run_repository import RunPaths
    from defender.tests import _1255_snapshot as S

    driven = S.drive_source(tmp_path, (S.append(S.chunks(3)[0]), S.echo("x"), S.done()))
    spec = S.spec_for(driven, S.tool_calling_responses(driven.store)[1])
    store_path = driven.store.path
    driven.store.close()
    source_io, target_io = RecordIO(), RecordIO()
    source = run_handle(driven.run_dir, source_io)
    target = run_handle(tmp_path / "sibling" / "run-sibling", target_io)
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


# RETIRED AT #1255 (P2 replaces the per-file cut rules; D1 moves the branch point):
#
# - `test_query_seed_replaces_the_snapshot_before_state_inheritance`,
#   `test_query_seed_failure_preserves_the_original_view_and_empty_live_state`,
#   `test_open_main_session_accepts_a_zero_byte_query_scaffold` and
#   `test_selected_empty_evidence_directories_retain_their_presence` pinned LEAD SELECTION —
#   which leads' rows and folders an arm inherits. The fork snapshot replaces it: the queries
#   table is cut to its recorded length and write-once evidence is checked by hash
#   (tests/e2e/test_1255_snapshot_restore.py::test_p2_append_only_and_write_once_files_are_
#   restored_up_to_the_cut, which also asks that the run state holds the restored rows).
# - `test_seed_validates_against_itself_and_remains_writable`,
#   `test_source_investigation_refusal_seeds_empty_only_at_an_empty_prefix` and
#   `test_fork_seed_keeps_document_global_schema_validation` pinned the FENCE-BOUNDARY seed
#   (a prefix cut by fence count, then validated). The document is now restored by content
#   (test_1255_snapshot_restore.py::test_p2_the_investigation_document_is_restored_by_content).
#   Their fresh-sibling refusal is kept, on a driven source:
#   tests/e2e/test_1255_snapshot_legality.py::test_an_arm_folder_already_holding_work_is_
#   refused_before_anything_forks.
# - `test_open_main_session_refuses_occupied_queries_before_fork` -> the same e2e test
#   (an occupied and a linked queries table).
#
# STILL HAND-PLANTED (kept, reported): the alert, opaque-bytes, payload-refusal and store-
# factory tests above branch `_branch_947.planted_source` (not the N4 fixture) at a tool RETURN.
# After #1255 they need the implementer's fixture-only snapshot planting on that source, and a
# D1 branch point (`LEGACY_BRANCH_CALL`) once the restore's entry point replaces
# `seed_investigation`.
