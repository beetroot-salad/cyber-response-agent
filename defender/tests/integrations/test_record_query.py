"""record_query.derive_system and the QueryCapture seq/append integrity and RunState row recording."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run


from defender.tests.support.shared.contracts._by_path import DEFENDER, load_module
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import pytest

pytest.importorskip("pydantic_ai")

ge = load_module(DEFENDER / "investigation" / "record_query.py")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.systems.verbs import VerbContext  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import DONE, LEAD, q  # noqa: E402


def test_derive_system_from_defender_shim():
    assert ge.derive_system(["defender-elastic", "query", "x"]) == "elastic"
    assert ge.derive_system(["defender-change-mgmt", "list-changes"]) == "change-mgmt"
    assert ge.derive_system(["defender-host-state", "container-inspect", "c1"]) == "host-state"


def test_derive_system_from_cli_path():
    assert ge.derive_system(["python3", "/x/cmdb_adapter.py", "host-lookup", "web-1"]) == "cmdb"


def test_derive_system_skips_non_adapter_and_unknown():
    assert ge.derive_system(["defender-invlang", "--tags"]) is None
    assert ge.derive_system(["echo", "hi"]) is None


def _row(seq, *, params, payload, lead="l-001"):
    """One prior queries row, its digest AND its content hash derived from the PAYLOAD TEXT."""
    return {
        "lead_id": lead, "seq": seq, "system": "elastic", "verb": "query",
        "query_id": "elastic.probe", "params": params, "exit_code": 0,
        **_result_of(payload),
    }


def _result_of(payload: str) -> dict:
    """The two result-identity fields a caller hands `repeat_note`, over one payload text."""
    return {
        "payload_digest": ge.payload_digest(payload, "", 0),
        "payload_sha256": ge.payload_sha256(payload),
    }


def _write_rows(tmp_path, rows):
    """A run that starts holding `rows` — a branch sibling's inherited prefix, handed to the
    run's state the way seeding hands it (`RunState.inherit_rows`, #1235 round 2). Returns the
    state: `repeat_note` reads it, never `executed_queries.jsonl`."""
    from defender.investigation.run_state import RunState

    state = RunState(tmp_path, "rq")
    state.inherit_rows(rows)
    return state


#: One recorded payload text, and a second of the SAME serialized length holding other bytes.
_PAYLOAD = '{"total": 2, "hits": ["web-1", "web-2"]}'
_SAME_LENGTH = '{"total": 2, "hits": ["db-01", "db-02"]}'


def test_repeat_note_is_silent_on_the_first_call(tmp_path):
    state = _write_rows(tmp_path, [_row(0, params={"q": "a"}, payload=_PAYLOAD)])
    assert ge.repeat_note(
        state, "l-001", seq=0, system="elastic", verb="query",
        params={"q": "a"}, **_result_of(_PAYLOAD),
    ) is None


def test_repeat_note_names_the_identical_earlier_request(tmp_path):
    state = _write_rows(tmp_path, [
        _row(0, params={"q": "a"}, payload=_PAYLOAD),
        _row(1, params={"q": "b"}, payload=_PAYLOAD),
        _row(2, params={"q": "b"}, payload=_PAYLOAD),
    ])
    note = ge.repeat_note(
        state, "l-001", seq=2, system="elastic", verb="query",
        params={"q": "b"}, **_result_of(_PAYLOAD),
    )
    assert note is not None
    assert "REPEAT" in note
    assert "seq 1" in note


def test_repeat_note_flags_a_changed_request_that_moved_nothing(tmp_path):
    """l-001's real turn 2: a narrowing filter was added and `total` did not move."""
    state = _write_rows(tmp_path, [
        _row(0, params={"q": "host:db-1"}, payload=_PAYLOAD),
        _row(1, params={"q": 'host:db-1 AND message: *"Accepted"*'}, payload=_PAYLOAD),
    ])
    note = ge.repeat_note(
        state, "l-001", seq=1, system="elastic", verb="query",
        params={"q": 'host:db-1 AND message: *"Accepted"*'}, **_result_of(_PAYLOAD),
    )
    assert note is not None
    assert "NO-OP" in note
    assert "seq 0" in note


def test_a_different_payload_of_the_same_length_is_not_a_no_op(tmp_path):
    """#877 F-9 — THE regression."""
    assert len(_PAYLOAD) == len(_SAME_LENGTH), "the fixture stopped exercising the defect"
    state = _write_rows(tmp_path, [
        _row(0, params={"host": "web-1"}, payload=_PAYLOAD),
        _row(1, params={"host": "db-01"}, payload=_SAME_LENGTH),
    ])
    assert ge.repeat_note(
        state, "l-001", seq=1, system="elastic", verb="query",
        params={"host": "db-01"}, **_result_of(_SAME_LENGTH),
    ) is None


def test_a_row_with_no_recorded_hash_evidences_no_byte_identity(tmp_path):
    """A table written before the hash column existed states no content fact, and the note is a
    statement OF that fact. Silence, not a digest-shaped guess."""
    row = _row(0, params={"q": "a"}, payload=_PAYLOAD)
    del row["payload_sha256"]
    state = _write_rows(tmp_path, [row, _row(1, params={"q": "b"}, payload=_PAYLOAD)])
    assert ge.repeat_note(
        state, "l-001", seq=1, system="elastic", verb="query",
        params={"q": "b"}, **_result_of(_PAYLOAD),
    ) is None


def test_repeat_note_ignores_other_leads_and_later_rows(tmp_path):
    state = _write_rows(tmp_path, [
        _row(0, params={"q": "a"}, payload=_PAYLOAD, lead="l-002"),
        _row(0, params={"q": "a"}, payload=_SAME_LENGTH),
        _row(1, params={"q": "a"}, payload=_PAYLOAD),
    ])
    assert ge.repeat_note(
        state, "l-001", seq=0, system="elastic", verb="query",
        params={"q": "a"}, **_result_of(_SAME_LENGTH),
    ) is None


def test_seq_stays_monotonic_when_a_payload_write_fails(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='rq-seq')
    (run_dir / "gather_raw" / LEAD / "0.json").mkdir(parents=True)

    rec = VerbRecorder()

    def query(ctx: VerbContext, *, native_query: str) -> list[dict]:
        rec.record("query", ctx, {"native_query": native_query})
        return [{"n": native_query}]

    verbs = FakeVerbs({"elastic": {"query": query}})
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "elastic", "goal": "g", "what_to_summarize": ["e"]})]),
        Turn(text="done"),
    ])
    gather = ReplayFn([
        q("elastic", "query", {"native_query": "a"}),
        q("elastic", "query", {"native_query": "b"}),
        DONE,
    ])
    state = drive(run_dir, run_id="rq-seq", main=main, gather=gather, verbs=verbs)["run_state"]

    rows = [r for r in read_jsonl_rows(run_dir / "executed_queries.jsonl") if r["lead_id"] == LEAD]
    assert [r["seq"] for r in rows] == [0, 1]
    assert rows[0]["payload_path"] is None
    assert rows[1]["payload_path"] == f"gather_raw/{LEAD}/1.json"
    # #1235 round 3: the state records the row as its line reads — a failed sidecar write is a
    # row with no payload in both, not a path the state names and the view does not.
    assert list(state.lead_rows(LEAD)) == rows


def test_the_content_hash_never_folds_two_payloads_together(tmp_path):
    """`payload_sha256` is the one field whose contract is that different bytes hash"""
    a, b = "\ud800", "\ud801"
    assert ge.payload_sha256(a) != ge.payload_sha256(b), \
        "two different payloads share one content hash"
    assert ge.payload_sha256("héllo") == ge.payload_sha256("héllo")


def _live():
    from defender.investigation import record_query as rq

    return rq


def _bare_run(tmp_path, name: str = "run"):
    """A run folder and a fresh state for it, as `run_investigation` starts one."""
    from defender.records import RunPaths
    from defender.investigation.run_state import RunState

    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    run_dir = tmp_path / fixture_uuid(name)
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    return run_dir, RunState(run_dir, run_dir.name)


def _append(rq, state, *, params, payload=_PAYLOAD, lead=LEAD):
    """One executed row through the production writer, its digest derived from `payload`."""
    return rq.append_query_row(
        state, run=fixture_run(state.run_dir), lead_id=lead, system="elastic", verb="query", query_id="elastic.probe",
        params=params, raw_command="elastic query", payload_text=payload, exit_code=0,
        payload_status="ok", payload_digest=rq.payload_digest(payload, "", 0), system_key="",
    )


def _table_rows(run_dir, lead=LEAD):
    from defender.records import RunPaths

    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == lead]


def _write_table(run_dir, rows):
    import json
    from defender.records import RunPaths

    table = RunPaths(run_dir).executed_queries
    table.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return table


def test_the_live_readers_answer_from_the_rows_the_host_recorded_not_from_the_file(tmp_path):
    """A run-folder file cannot move a live decision (#1235 O1, at the reader): overwriting"""
    rq = _live()
    run_dir, state = _bare_run(tmp_path)
    assert [_append(rq, state, params={"q": "a"})["seq"] for _ in range(2)] == [0, 1]

    planted = [_row(s, params={"q": "z"}, payload=_SAME_LENGTH) for s in range(5)]
    _write_table(run_dir, planted)
    assert [r["seq"] for r in _table_rows(run_dir)] == [0, 1, 2, 3, 4], \
        "the plant did not land, so nothing below is observed"
    assert [r["params"] for r in state.lead_rows(LEAD)] == [{"q": "a"}] * 2
    assert rq._next_seq(state, LEAD) == 2, "the planted rows moved the next seq"
    assert rq.repeat_note(state, LEAD, seq=2, system="elastic", verb="query",
                          params={"q": "z"}, **_result_of(_SAME_LENGTH)) is None, \
        "a planted row made a repeat the host never recorded"

    _write_table(run_dir, [])
    assert _table_rows(run_dir) == []
    assert rq._next_seq(state, LEAD) == 2, "truncating the table reset the next seq"
    note = rq.repeat_note(state, LEAD, seq=2, system="elastic", verb="query",
                          params={"q": "a"}, **_result_of(_PAYLOAD))
    assert note is not None, "truncating the table erased a repeat the host recorded"
    assert "REPEAT" in note, "truncating the table erased a repeat the host recorded"
    assert "seq 0" in note, "truncating the table erased a repeat the host recorded"

    z = _append(rq, state, params={"q": "z"}, payload=_SAME_LENGTH)
    assert z["seq"] == 2
    note = rq.repeat_note(state, LEAD, seq=3, system="elastic", verb="query",
                          params={"q": "z"}, **_result_of(_SAME_LENGTH))
    assert note is not None, "the control: a request the host recorded does make the note fire"
    assert "REPEAT" in note, "the control: a request the host recorded does make the note fire"
    assert "seq 2" in note, "the control: a request the host recorded does make the note fire"


def test_state_rows_are_the_lines_written_not_the_dicts_the_writer_built(tmp_path):
    """Each row the state holds is `json.loads` of the line `append_query_row` wrote — the same"""
    import json

    rq = _live()
    run_dir, state = _bare_run(tmp_path)
    built = _append(rq, state, params={"n": 1.5, "tags": ["x", "y"], "nested": {"k": "v"}})
    _append(rq, state, params={"q": "b"})

    on_disk = _table_rows(run_dir)
    assert len(on_disk) == 2
    assert json.dumps(state.lead_rows(LEAD)) == json.dumps(on_disk), \
        "the state holds something other than the lines the table carries"

    built["params"]["nested"]["k"] = "edited after the write"
    built["seq"] = 99
    assert json.dumps(state.lead_rows(LEAD)) == json.dumps(on_disk), \
        "the state aliases the writer's dict: an edit after the write reached the guards"


def _plant_at(path, kind: str, outside) -> None:
    """Squat `path` with what `write_guarded` refuses under any uid (a chmod would not bind
    root): a symlink to a file outside the run, or a directory."""
    path.unlink(missing_ok=True)
    if kind == "symlink":
        path.symlink_to(outside)
    else:
        path.mkdir()


def _unplant(path, kind: str, saved: bytes) -> None:
    if kind == "symlink":
        path.unlink()
    else:
        path.rmdir()
    path.write_bytes(saved)


@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_a_row_whose_view_write_failed_is_in_the_state_with_its_seq_spent(tmp_path, kind):
    """R3, round 3 (#1235): the run's state is the record of what the run did, and `executed_queries.jsonl` is the model's view of it."""
    from defender.knowledge._query_rules import PARAMS_NESTING_LIMIT, ParamsTooDeep
    from defender.records import RunPaths

    rq = _live()
    run_dir, state = _bare_run(tmp_path)
    assert _append(rq, state, params={"q": "a"})["seq"] == 0

    table = RunPaths(run_dir).executed_queries
    saved = table.read_bytes()
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b"")
    _plant_at(table, kind, outside)
    with pytest.raises(OSError):  # noqa: PT011 — the symlink and the directory refuse in their own words
        _append(rq, state, params={"q": "unviewed"})
    assert [(r["seq"], r["params"]) for r in state.lead_rows(LEAD)] == \
        [(0, {"q": "a"}), (1, {"q": "unviewed"})], \
        "a row whose view write failed did not reach the state"
    assert rq._next_seq(state, LEAD) == 2, "the recorded row's seq was not spent"
    assert outside.read_bytes() == b"", "the append followed the planted link"

    _unplant(table, kind, saved)
    deep: dict = {}
    cursor = deep
    for _ in range(PARAMS_NESTING_LIMIT + 2):
        cursor["k"] = {}
        cursor = cursor["k"]
    with pytest.raises(ParamsTooDeep):
        _append(rq, state, params=deep)
    assert state.row_count(LEAD) == 2, "refused params reached the state"
    assert rq._next_seq(state, LEAD) == 2, "refused params spent a seq"
    assert table.read_bytes() == saved, "refused params wrote a line"

    assert _append(rq, state, params={"q": "c"})["seq"] == 2
    assert [(r["seq"], r["params"]) for r in state.lead_rows(LEAD)] == \
        [(0, {"q": "a"}), (1, {"q": "unviewed"}), (2, {"q": "c"})]
    assert [r["seq"] for r in _table_rows(run_dir)] == [0, 2], \
        "the view holds a line the refused write never landed, or lost one that did"
    assert [r for r in state.lead_rows(LEAD) if r["seq"] != 1] == _table_rows(run_dir), \
        "the rows that did land disagree between the state and the view"
