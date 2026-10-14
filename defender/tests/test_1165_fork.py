"""#1165 O1/O4/O7: fork reads belong to the opened source Run."""
from __future__ import annotations

import json

import pytest

from defender.runtime import branch
from defender.runtime.run_state import RunState
from defender.tests._1165_flows import RecordIO, drive_run, run_handle
from defender.tests._alert_plant import plant_alert
from defender.tests._branch_947 import GOLDEN_INVESTIGATION, legal_source, spec_at
from defender.tests.e2e._replay_harness import ReplayFn, Turn


def source_and_sibling(tmp_path, *, document=None):
    text = document if document is not None else GOLDEN_INVESTIGATION.read_text(encoding="utf-8")
    store, directory, _session, ids = legal_source(tmp_path, investigation=text)
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


def test_query_seed_is_created_before_state_inheritance_and_malformed_rows_stay_tolerated(tmp_path):
    """O4/O6: seed parsing keeps old JSONL tolerance and records rows after create succeeds."""
    store, spec, source, target, state, source_io, target_io = source_and_sibling(tmp_path)
    first = {"lead_id": "l-001", "seq": 0, "params": {"tuple": [1, 2]}}
    later = {"lead_id": "l-002", "seq": 9, "query_id": "other.later"}
    # A later dispatch exists in the source transcript, past the selected branch point.
    # Its query must remain outside the inherited prefix, despite being in the source table.
    from defender.runtime import session_store
    from defender.tests._session_store_705 import tool_call_response, tool_return_request

    session = session_store.main_session_id(store)
    store.append(session, [tool_call_response("gather", {"lead_id": "l-002"}, tool_call_id="late")],
                 agent_id="main")
    store.append(session, [tool_return_request("gather", "later summary", tool_call_id="late")],
                 agent_id="main")
    source.tables.queries.path.write_text(json.dumps(first) + "\n{broken\n[]\n" + json.dumps(later) + "\n")
    seen = []

    def before(root, relative, data, options):
        if relative == "executed_queries.jsonl":
            seen.append((list(state.lead_rows("l-001")), options["mode"], data))

    target_io.before_write = before
    seed(store, spec, source, target, state)
    assert seen
    assert seen[0][0] == []
    assert seen[0][1] == "create"
    disk = [json.loads(line) for line in target.tables.queries.path.read_text().splitlines()]
    assert first in disk
    assert later not in disk
    assert list(state.lead_rows("l-001")) == [first]
    assert state.lead_rows("l-002") == ()
    assert any(relative == "executed_queries.jsonl" for _op, _root, relative, _mode in source_io.calls)


def test_query_seed_failure_leaves_live_rows_empty(tmp_path):
    """O6: a query seed that cannot land must not populate live state."""
    store, spec, source, target, state, _source_io, target_io = source_and_sibling(tmp_path)
    target_io.fail = ("rooted_write", "executed_queries.jsonl")
    with pytest.raises((OSError, branch.BranchError)):
        seed(store, spec, source, target, state)
    assert state.lead_rows("l-001") == ()
    assert "executed_queries.jsonl" in target_io.names("rooted_write")
    assert not target.tables.queries.path.exists()


def test_seed_validates_against_itself_and_remains_writable(tmp_path):
    """O4: inherited unfenced text is baseline, while global validation still applies."""
    # The old writer explicitly permits a source prefix's existing prose as its own baseline.
    document = "# Existing source heading\n\n" + GOLDEN_INVESTIGATION.read_text(encoding="utf-8")
    store, spec, source, target, state, _source_io, target_io = source_and_sibling(tmp_path, document=document)
    fences = seed(store, spec, source, target, state)
    assert fences > 0
    seeded = target.documents.investigation.read()
    assert seeded.startswith("# Existing source heading\n")
    assert "investigation.md" in target_io.names("rooted_write")
    # Fresh sibling refusal stays in force: do not overwrite a seed on a retry.
    with pytest.raises(branch.BranchError, match="fresh sibling|already holds"):
        seed(store, spec, source, target, state)
    assert target.documents.investigation.read() == seeded


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
    """O1: real resumed driver uses separate source Run for every selected durable read."""
    store, spec, source, target, state, source_io, target_io = source_and_sibling(tmp_path)
    store.close()
    model = ReplayFn([Turn(text="Resumed from held evidence")])
    source_io.fail_reads = fault
    summary = drive_run(target, model, state=state, resume=spec, source_run=source)
    if fault:
        assert summary["truncated_by"] == "store"
        assert model.calls == 0
        assert state.lead_rows("l-001") == ()
        assert not target.documents.investigation.path.exists()
        return
    assert summary["truncated_by"] is None
    assert str(summary["store_path"]) == str(store.path)
    reads = {relative for op, _root, relative, _mode in source_io.calls if "read" in op}
    assert "investigation.md" in reads
    assert "executed_queries.jsonl" in reads
    assert source.observability.session_pointer.path.name in reads
    assert list(state.lead_rows("l-001"))
    assert "investigation.md" in target_io.names("rooted_write")
    assert "executed_queries.jsonl" in target_io.names("rooted_write")


def test_source_investigation_refusal_seeds_empty_only_at_an_empty_prefix(tmp_path):
    """O4: missing/refused documents retain the current zero-prefix fallback semantics."""
    store, spec, source, target, state, source_io, _target_io = source_and_sibling(tmp_path)
    from defender.runtime import session_store

    source_session = session_store.main_session_id(store)
    ids = session_store.path_row_ids(store, source_session)
    # Before the recorded append_block pair, this source prefix accounts for no fences.
    spec = spec_at(store, source.run_dir, ids[2])
    document = source.documents.investigation.path
    outside = tmp_path / "outside-document"
    outside.write_bytes(document.read_bytes())
    document.unlink()
    document.symlink_to(outside)
    assert seed(store, spec, source, target, state) == 0
    assert target.documents.investigation.path.read_bytes() == b""
    assert any(name == "investigation.md" for _op, _root, name, _mode in source_io.calls)
    assert outside.read_bytes()


def test_fork_seed_keeps_document_global_schema_validation(tmp_path):
    """O4: using a seed as its own baseline never bypasses document-wide size gates."""
    from defender._artifact_schema import INVESTIGATION_FILE_MAX

    document = "x" * (INVESTIGATION_FILE_MAX + 1) + "\n```invlang\n:V prologue.vertices\n```\n"
    store, spec, source, target, state, _source_io, _target_io = source_and_sibling(tmp_path, document=document)
    with pytest.raises((ValueError, branch.BranchError), match="limit|validation"):
        seed(store, spec, source, target, state)
    assert not target.documents.investigation.path.exists()
    assert state.lead_rows("l-001") == ()
