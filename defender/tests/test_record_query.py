"""Tests for the SURVIVING half of record_query.py after #611.

record_query is no longer a CLI: `capture` / `main` / `parse_params` / `_derive_verb` /
`payload_status` were DELETED with the bash capture layer they served. The queries row is now
written by `runtime/query_tool.py`'s `QueryCapture` capability, and its contract — params keyed
by the verb's REAL param names (never `arg0`/`arg1`), `verb` holding the real verb, payload
by-ref, payload_status/error_class classification, the truncated model view — is specced in the
frozen `tests/e2e/test_query_tool_611.py` (row contract, payload-by-ref, empty/error status,
seq collision). This file keeps ONLY the functions that outlived the CLI, because live code
still imports them:

  - `derive_system` — the generic system-from-argv derivation (no per-system table);
  - and, re-pointed at `QueryCapture`, the seq→write→append INTEGRITY property (a failed
    payload write must not reuse a `(lead_id, seq)`), which the frozen suite does not exercise;
  - and #1235's queries rows on the run's `RunState` (round 2, comment 6117481676): the live
    readers (`repeat_note`, `_next_seq`, the writer's seq, `system_for_payload_operands`) take
    the state and read the rows it recorded, never `executed_queries.jsonl`; since round 3 the
    state is the record and the file the model's view of it, so a row enters the state before
    its line is written and stays there when that write fails.

The model-visible view left with #832: `build_truncated_view` / `PASSTHROUGH_SAMPLE_COUNT` /
`_passthrough_max_bytes` are gone, and `payload_view.py` (specced by `test_payload_view.py`)
renders the payload now — this module records the query, that one renders its result.

`payload_digest` / `LEAD_ID_RE` survival is pinned by
`test_query_tool_611.py::test_record_query_module_survives_its_cli`; the lead-id claim-side
guard by `test_record_lead.py`.
"""
from __future__ import annotations


from defender.tests._by_path import DEFENDER, load_module

import pytest

pytest.importorskip("pydantic_ai")

ge = load_module(DEFENDER / "scripts" / "gather_tools" / "record_query.py")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
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


def test_derive_system_multiword_cli_path_normalizes_underscore():
    assert ge.derive_system(["python3", "/x/host_state_adapter.py", "inspect", "c1"]) == "host-state"
    assert ge.derive_system(["/x/change_mgmt_adapter.py", "list"]) == "change-mgmt"
    assert ge.derive_system(["python3", "/x/threat_intel_adapter.py", "lookup"]) == "threat-intel"


def test_derive_system_ignores_stray_tokens_before_shim():
    assert ge.derive_system(["--out", "defender-runs/x", "defender-cmdb", "q"]) == "cmdb"
    assert ge.derive_system(["FOO=/x/elastic_adapter.py", "defender-cmdb", "q"]) == "cmdb"


def test_derive_system_skips_non_adapter_and_unknown():
    assert ge.derive_system(["defender-invlang", "--tags"]) is None
    assert ge.derive_system(["echo", "hi"]) is None



# The field-shape sampler that used to live here moved to `payload_view.py` with #832, and
# its tests to `test_payload_view.py`. One of them —
# `test_build_truncated_view_complete_envelope_is_not_flagged_sampled` — pinned the DEFECT:
# it asserted that a complete 3-of-3 envelope still reads "FIELD-SHAPE sample". Measured over
# the recorded corpus that wording reached 41 of 62 elastic payloads whose every record was
# already in context, telling the lead not to count what it could see in full.


def _row(seq, *, params, payload, lead="l-001"):
    """One prior queries row, its digest AND its content hash derived from the PAYLOAD TEXT.

    Both are derived rather than passed (#877 F-9): a fixture free to state a digest and a hash
    that disagree could pin `repeat_note` against a table the writers cannot produce, which is
    how the defect survived — the old helper took a digest string alone, so "same digest" and
    "same payload" were indistinguishable in the tests exactly as they were in the code."""
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
    from defender.runtime.run_state import RunState

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
    """l-001's real turn 2: a narrowing filter was added and `total` did not move.

    The filter was a wildcard-phrase clause the query language silently ignores, so the
    payload came back byte-identical. Nothing in the loop compared the two, and the lead
    spent its remaining 35 turns varying a filter that was never applied.
    """
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
    """#877 F-9 — THE regression. The NO-OP arm tells the lead "the payload is byte-identical",
    and it used to establish that from `payload_digest`: `f"{len(text)} bytes, 1 line(s)"`, a
    serialized LENGTH (`json.dumps` escapes every newline, so the line count is always 1).

    Fixed-schema enumeration produces same-length payloads by construction, so this fired
    constantly on genuinely different results — 55 false NO-OPs against 41 true ones across the
    recorded runs, the sharpest being a `fim-checksum` of `/etc/passwd` and one of `/etc/shadow`
    at 160 bytes each: the lead was told the checksum of shadow was the checksum of passwd."""
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


def test_repeat_note_is_silent_on_a_run_with_no_rows(tmp_path):
    # A run that recorded nothing (and has no table on disk) has no earlier call to name.
    from defender.runtime.run_state import RunState

    assert ge.repeat_note(
        RunState(tmp_path, "rq"), "l-001", seq=3, system="elastic", verb="query",
        params={"q": "a"}, **_result_of(_PAYLOAD),
    ) is None


def test_seq_stays_monotonic_when_a_payload_write_fails(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN_AB3)
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

    # lead-0 (#808) resolves against GOLDEN_AB3 ahead of MAIN's own turn and writes its
    # own (l-000) row(s) into this same table — scope to `LEAD`'s own rows, which is
    # what seq-monotonicity-within-a-lead actually means here.
    rows = [r for r in read_jsonl_rows(run_dir / "executed_queries.jsonl") if r["lead_id"] == LEAD]
    assert [r["seq"] for r in rows] == [0, 1]
    assert rows[0]["payload_path"] is None
    assert rows[1]["payload_path"] == f"gather_raw/{LEAD}/1.json"
    # #1235 round 3: the state records the row as its line reads — a failed sidecar write is a
    # row with no payload in both, not a path the state names and the view does not.
    assert list(state.lead_rows(LEAD)) == rows


def test_the_content_hash_never_folds_two_payloads_together(tmp_path):
    """`payload_sha256` is the one field whose contract is that different bytes hash
    differently, so its error handler may not be `replace`: U+FFFD is one character and every
    unencodable codepoint would map onto it, colliding two distinct payloads under the very
    claim the column exists to license ("byte-identical"). Moot for today's writers — both hand
    it `json.dumps(..., ensure_ascii=True)` output, which is pure ASCII — and pinned anyway,
    because #834's compact encoding is a live proposal to turn `ensure_ascii` off."""
    a, b = "\ud800", "\ud801"
    assert ge.payload_sha256(a) != ge.payload_sha256(b), \
        "two different payloads share one content hash"
    assert ge.payload_sha256("héllo") == ge.payload_sha256("héllo")


# ── #1235: the queries table's live reads come from the run's state ─────────────────────────
#
# `executed_queries.jsonl` stays the model's view and the learning loop's input, written
# exactly as before; the DECISIONS read from it live (the repeat guard, the rejection budget,
# the repeat note, the next seq, a reducer failure's system) take the run's `RunState` (#1235
# round 2) and read the rows it recorded. No file is ever read into it, and since round 3 a
# row is recorded there before its line is written: the state is the record.


def _live():
    from defender.scripts.gather_tools import record_query as rq

    return rq


def _bare_run(tmp_path, name: str = "run"):
    """A run folder and a fresh state for it, as `run_investigation` starts one."""
    from defender.run_repository import RunPaths
    from defender.runtime.run_state import RunState

    run_dir = tmp_path / name
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    return run_dir, RunState(run_dir, name)


def _append(rq, state, *, params, payload=_PAYLOAD, lead=LEAD):
    """One executed row through the production writer, its digest derived from `payload`."""
    return rq.append_query_row(
        state, lead_id=lead, system="elastic", verb="query", query_id="elastic.probe",
        params=params, raw_command="elastic query", payload_text=payload, exit_code=0,
        payload_status="ok", payload_digest=rq.payload_digest(payload, "", 0), system_key="",
    )


def _table_rows(run_dir, lead=LEAD):
    from defender.run_repository import RunPaths

    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == lead]


def _write_table(run_dir, rows):
    import json
    from defender.run_repository import RunPaths

    table = RunPaths(run_dir).executed_queries
    table.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return table


def test_the_live_readers_answer_from_the_rows_the_host_recorded_not_from_the_file(tmp_path):
    """A run-folder file cannot move a live decision (#1235 O1, at the reader): overwriting
    `executed_queries.jsonl` with planted rows, or truncating it, changes nothing the live
    readers answer from the run's state. Planted rows neither feed the next seq nor make a
    repeat; a truncated table does not reset one.

    Positive controls: a reader of the FILE does see each plant, so the plant landed; and the
    planted request, once the host itself records it, does make the note fire."""
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
    """Each row the state holds is `json.loads` of the line `append_query_row` wrote — the same
    value a reader of the file gets back — not the dict the host assembled: the live readers and
    the record agree byte for byte, and an edit to the writer's returned dict after the write
    does not reach what the guards read."""
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
    """R3, round 3 (#1235): the run's state is the record of what the run did, and
    `executed_queries.jsonl` is the model's view of it. An append validates first, then takes
    the seq and records the row in the state, and only then writes the view. The table squatted
    mid-run (a planted symlink, or a directory): the append raises the write's `OSError`, the row
    IS in the state with the next seq — the call it records was made — and the following append
    takes the seq after it. The view holds only the lines that landed, and the symlink's target
    outside the run is untouched.

    Params too deep to store are refused before anything: no row, no seq, no line — the control
    that validation still comes first.

    Positive control: the rows before and after the fault are in both the state and the view.

    Observed failing by: round 2's ordering (write the line, then record), under which a
    refused view write leaves an executed call out of every live decision."""
    from defender._query_rules import PARAMS_NESTING_LIMIT, ParamsTooDeep
    from defender.run_repository import RunPaths

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
