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
  - and #1235's in-memory queries mirror (`open_query_mirror`, `live_lead_rows`): the live
    readers (`repeat_note`, `_next_seq`, the writer's seq, `system_for_payload_operands`) read
    the rows this process recorded, never `executed_queries.jsonl`, which stays the record.

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
    """The table as a run starts with it: `rows` on disk, then the host's mirror opened over
    them (#1235) — `repeat_note` reads the mirror, never the file, and a folder whose mirror was
    never opened is a programming error it refuses."""
    import json
    from defender.run_repository import RunPaths
    log = RunPaths(tmp_path).executed_queries
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    ge.open_query_mirror(tmp_path)
    return tmp_path


#: One recorded payload text, and a second of the SAME serialized length holding other bytes.
_PAYLOAD = '{"total": 2, "hits": ["web-1", "web-2"]}'
_SAME_LENGTH = '{"total": 2, "hits": ["db-01", "db-02"]}'


def test_repeat_note_is_silent_on_the_first_call(tmp_path):
    _write_rows(tmp_path, [_row(0, params={"q": "a"}, payload=_PAYLOAD)])
    assert ge.repeat_note(
        tmp_path, "l-001", seq=0, system="elastic", verb="query",
        params={"q": "a"}, **_result_of(_PAYLOAD),
    ) is None


def test_repeat_note_names_the_identical_earlier_request(tmp_path):
    _write_rows(tmp_path, [
        _row(0, params={"q": "a"}, payload=_PAYLOAD),
        _row(1, params={"q": "b"}, payload=_PAYLOAD),
        _row(2, params={"q": "b"}, payload=_PAYLOAD),
    ])
    note = ge.repeat_note(
        tmp_path, "l-001", seq=2, system="elastic", verb="query",
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
    _write_rows(tmp_path, [
        _row(0, params={"q": "host:db-1"}, payload=_PAYLOAD),
        _row(1, params={"q": 'host:db-1 AND message: *"Accepted"*'}, payload=_PAYLOAD),
    ])
    note = ge.repeat_note(
        tmp_path, "l-001", seq=1, system="elastic", verb="query",
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
    _write_rows(tmp_path, [
        _row(0, params={"host": "web-1"}, payload=_PAYLOAD),
        _row(1, params={"host": "db-01"}, payload=_SAME_LENGTH),
    ])
    assert ge.repeat_note(
        tmp_path, "l-001", seq=1, system="elastic", verb="query",
        params={"host": "db-01"}, **_result_of(_SAME_LENGTH),
    ) is None


def test_a_row_with_no_recorded_hash_evidences_no_byte_identity(tmp_path):
    """A table written before the hash column existed states no content fact, and the note is a
    statement OF that fact. Silence, not a digest-shaped guess."""
    row = _row(0, params={"q": "a"}, payload=_PAYLOAD)
    del row["payload_sha256"]
    _write_rows(tmp_path, [row, _row(1, params={"q": "b"}, payload=_PAYLOAD)])
    assert ge.repeat_note(
        tmp_path, "l-001", seq=1, system="elastic", verb="query",
        params={"q": "b"}, **_result_of(_PAYLOAD),
    ) is None


def test_repeat_note_ignores_other_leads_and_later_rows(tmp_path):
    _write_rows(tmp_path, [
        _row(0, params={"q": "a"}, payload=_PAYLOAD, lead="l-002"),
        _row(0, params={"q": "a"}, payload=_SAME_LENGTH),
        _row(1, params={"q": "a"}, payload=_PAYLOAD),
    ])
    assert ge.repeat_note(
        tmp_path, "l-001", seq=0, system="elastic", verb="query",
        params={"q": "a"}, **_result_of(_SAME_LENGTH),
    ) is None


def test_repeat_note_survives_a_missing_table(tmp_path):
    # An absent table opens as no rows (#1235): the mirror is opened, the file is not there.
    ge.open_query_mirror(tmp_path)
    assert ge.repeat_note(
        tmp_path, "l-001", seq=3, system="elastic", verb="query",
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
    drive(run_dir, run_id="rq-seq", main=main, gather=gather, verbs=verbs)

    # lead-0 (#808) resolves against GOLDEN_AB3 ahead of MAIN's own turn and writes its
    # own (l-000) row(s) into this same table — scope to `LEAD`'s own rows, which is
    # what seq-monotonicity-within-a-lead actually means here.
    rows = [r for r in read_jsonl_rows(run_dir / "executed_queries.jsonl") if r["lead_id"] == LEAD]
    assert [r["seq"] for r in rows] == [0, 1]
    assert rows[0]["payload_path"] is None
    assert rows[1]["payload_path"] == f"gather_raw/{LEAD}/1.json"


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


# ── #1235: the queries table's live reads come from the host's own mirror ─────────────────────
#
# `executed_queries.jsonl` stays the model's view and the learning loop's record, written
# exactly as before; the DECISIONS read from it live (the repeat guard, the rejection budget,
# the repeat note, the next seq, a reducer failure's system) read the rows this process
# recorded, held in memory, keyed by the run folder. `lead_rows` stays the FILE reader.
# The new names are imported per test (they do not exist before the implementation), from the
# module's real import path, so `open_query_mirror` and the readers share one registry.


def _live():
    from defender.scripts.gather_tools import record_query as rq

    return rq


def _bare_run(tmp_path, name: str = "run"):
    """A run folder that went through no driver: nothing has opened its mirror."""
    from defender.run_repository import RunPaths

    run_dir = tmp_path / name
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    return run_dir


def _append(rq, run_dir, *, params, payload=_PAYLOAD, lead=LEAD):
    """One executed row through the production writer, its digest derived from `payload`."""
    return rq.append_query_row(
        run_dir, lead_id=lead, system="elastic", verb="query", query_id="elastic.probe",
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


def test_a_live_reader_on_a_folder_whose_mirror_was_never_opened_raises(tmp_path):
    """No lazy load (#1235, `docs/principles.md` §2): every live reader of the queries table,
    asked about a run folder whose mirror this process never opened, raises `LookupError` —
    even with a table on disk it could have read. The writer is one of them (it takes its seq
    from the mirror) and refuses before appending anything.

    Positive control, on the same folder: once `open_query_mirror` has loaded the table, the
    same calls answer from it — the file's row, seq 1, no note, and a write at seq 1."""
    rq = _live()
    run_dir = _bare_run(tmp_path)
    table = _write_table(run_dir, [_row(0, params={"q": "a"}, payload=_PAYLOAD)])
    before = table.read_bytes()

    with pytest.raises(LookupError):
        rq.live_lead_rows(run_dir, LEAD)
    with pytest.raises(LookupError):
        rq._next_seq(run_dir, LEAD)
    with pytest.raises(LookupError):
        rq.repeat_note(run_dir, LEAD, seq=1, system="elastic", verb="query",
                       params={"q": "a"}, **_result_of(_PAYLOAD))
    with pytest.raises(LookupError):
        _append(rq, run_dir, params={"q": "b"})
    assert table.read_bytes() == before, "the refused write still appended a row"
    with pytest.raises(LookupError):
        rq.system_for_payload_operands(run_dir, [run_dir / "gather_raw" / LEAD / "0.json"])
    # It reads the table only when an operand IS a run payload; one that is not asks nothing.
    assert rq.system_for_payload_operands(run_dir, [tmp_path / "elsewhere.json"]) == ""

    rq.open_query_mirror(run_dir)
    assert [r["seq"] for r in rq.live_lead_rows(run_dir, LEAD)] == [0]
    assert rq._next_seq(run_dir, LEAD) == 1
    assert rq.repeat_note(run_dir, LEAD, seq=1, system="elastic", verb="query",
                          params={"q": "b"}, **_result_of(_SAME_LENGTH)) is None
    assert rq.system_for_payload_operands(
        run_dir, [run_dir / "gather_raw" / LEAD / "0.json"]) == "elastic"
    assert _append(rq, run_dir, params={"q": "b"})["seq"] == 1


def test_the_live_readers_answer_from_the_rows_the_host_recorded_not_from_the_file(tmp_path):
    """A run-folder file cannot move a live decision (#1235 O1, at the reader): once the
    run's mirror is open, overwriting `executed_queries.jsonl` with planted rows, or truncating
    it, changes nothing the live readers answer. Planted rows neither feed the next seq nor
    make a repeat; a truncated table does not reset one.

    Positive controls: the FILE reader (`lead_rows`) does see each plant, so the plant landed;
    and the planted request, once the host itself records it, does make the note fire."""
    rq = _live()
    run_dir = _bare_run(tmp_path)
    rq.open_query_mirror(run_dir)
    assert [_append(rq, run_dir, params={"q": "a"})["seq"] for _ in range(2)] == [0, 1]

    planted = [_row(s, params={"q": "z"}, payload=_SAME_LENGTH) for s in range(5)]
    _write_table(run_dir, planted)
    assert [r["seq"] for r in rq.lead_rows(run_dir, LEAD)] == [0, 1, 2, 3, 4], \
        "the plant did not land, so nothing below is observed"
    assert [r["params"] for r in rq.live_lead_rows(run_dir, LEAD)] == [{"q": "a"}] * 2
    assert rq._next_seq(run_dir, LEAD) == 2, "the planted rows moved the next seq"
    assert rq.repeat_note(run_dir, LEAD, seq=2, system="elastic", verb="query",
                          params={"q": "z"}, **_result_of(_SAME_LENGTH)) is None, \
        "a planted row made a repeat the host never recorded"

    _write_table(run_dir, [])
    assert rq.lead_rows(run_dir, LEAD) == []
    assert rq._next_seq(run_dir, LEAD) == 2, "truncating the table reset the next seq"
    note = rq.repeat_note(run_dir, LEAD, seq=2, system="elastic", verb="query",
                          params={"q": "a"}, **_result_of(_PAYLOAD))
    assert note is not None and "REPEAT" in note and "seq 0" in note, \
        "truncating the table erased a repeat the host recorded"

    z = _append(rq, run_dir, params={"q": "z"}, payload=_SAME_LENGTH)
    assert z["seq"] == 2
    note = rq.repeat_note(run_dir, LEAD, seq=3, system="elastic", verb="query",
                          params={"q": "z"}, **_result_of(_SAME_LENGTH))
    assert note is not None and "REPEAT" in note and "seq 2" in note, \
        "the control: a request the host recorded does make the note fire"


def test_mirror_rows_are_the_lines_written_not_the_dicts_the_writer_built(tmp_path):
    """Each mirror row is `json.loads` of the line `append_query_row` wrote — the same value a
    reader of the file gets back — not the dict the host assembled: the live readers and the
    record agree byte for byte, and an edit to the writer's returned dict after the write does
    not reach what the guards read."""
    import json

    rq = _live()
    run_dir = _bare_run(tmp_path)
    rq.open_query_mirror(run_dir)
    built = _append(rq, run_dir, params={"n": 1.5, "tags": ["x", "y"], "nested": {"k": "v"}})
    _append(rq, run_dir, params={"q": "b"})

    on_disk = _table_rows(run_dir)
    assert len(on_disk) == 2
    live = rq.live_lead_rows(run_dir, LEAD)
    assert json.dumps(live) == json.dumps(on_disk), \
        "the mirror holds something other than the lines the table carries"

    built["params"]["nested"]["k"] = "edited after the write"
    built["seq"] = 99
    assert json.dumps(rq.live_lead_rows(run_dir, LEAD)) == json.dumps(on_disk), \
        "the mirror aliases the writer's dict: an edit after the write reached the guards"


def test_a_row_whose_write_failed_neither_enters_the_mirror_nor_spends_a_seq(tmp_path):
    """A row enters the mirror only after its line was written. The table is squatted by a
    directory mid-run (which `write_guarded` refuses under any uid — a chmod would not bind
    root): the write raises, the mirror keeps only the rows the file holds, and the next seq is
    the one the failed row would have taken. Once the table is writable again the next row
    takes that seq, and the mirror and the file agree.

    Positive control: the row written before the fault, and the one after it, are both in."""
    rq = _live()
    run_dir = _bare_run(tmp_path)
    rq.open_query_mirror(run_dir)
    assert _append(rq, run_dir, params={"q": "a"})["seq"] == 0

    from defender.run_repository import RunPaths

    table = RunPaths(run_dir).executed_queries
    saved = table.read_bytes()
    table.unlink()
    table.mkdir()
    with pytest.raises(OSError):
        _append(rq, run_dir, params={"q": "lost"})
    assert [r["params"] for r in rq.live_lead_rows(run_dir, LEAD)] == [{"q": "a"}], \
        "a row whose line was never written entered the mirror"
    assert rq._next_seq(run_dir, LEAD) == 1, "the failed write spent a seq"

    table.rmdir()
    table.write_bytes(saved)
    assert _append(rq, run_dir, params={"q": "c"})["seq"] == 1
    assert [(r["seq"], r["params"]) for r in rq.live_lead_rows(run_dir, LEAD)] == \
        [(0, {"q": "a"}), (1, {"q": "c"})]
    assert rq.live_lead_rows(run_dir, LEAD) == _table_rows(run_dir)


def test_open_query_mirror_loads_a_damaged_table_the_way_the_guard_used_to_read_it(tmp_path):
    """`open_query_mirror` is where the table's damage is met now (#1235: the repeat guard's
    fail-open read of the file moved to this loader). It drops a torn trailing line, keeps a
    foreign row with no `lead_id` out of every lead, survives a stored `params` that is not a
    dict and invalid UTF-8, and opens an absent table as no rows.

    It (re)loads: rows added to the file after an open are not in the mirror until the next
    open, which replaces what the previous one loaded."""
    from defender._io import append_jsonl, write_guarded
    from defender.run_repository import RunPaths

    rq = _live()
    damaged = _bare_run(tmp_path, "damaged")
    table = RunPaths(damaged).executed_queries
    append_jsonl(table, [
        _row(0, params={"q": "a"}, payload=_PAYLOAD),
        {"seq": 1, "system": "elastic", "verb": "query", "params": {}},
        {**_row(2, params={}, payload=_PAYLOAD), "params": "not-a-dict"},
        _row(3, params={"q": "a"}, payload=_PAYLOAD),
    ])
    write_guarded(table, '{"lead_id": "l-001", "seq": 4, "sys', mode="append")
    rq.open_query_mirror(damaged)
    assert [r["seq"] for r in rq.live_lead_rows(damaged, LEAD)] == [0, 2, 3], \
        "a torn line, a foreign row or a non-dict params field was not survived"
    assert rq._next_seq(damaged, LEAD) == 3

    bad_utf8 = _bare_run(tmp_path, "utf8")
    RunPaths(bad_utf8).executed_queries.write_bytes(
        b'{"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "query", '
        b'"params": {"q": "\xff\xfeFROM logs"}}\n'
    )
    rq.open_query_mirror(bad_utf8)
    assert len(rq.live_lead_rows(bad_utf8, LEAD)) == 1, "invalid UTF-8 was not survived"

    absent = _bare_run(tmp_path, "absent")
    rq.open_query_mirror(absent)
    assert rq.live_lead_rows(absent, LEAD) == []
    assert rq._next_seq(absent, LEAD) == 0

    append_jsonl(RunPaths(absent).executed_queries, [_row(0, params={"q": "a"}, payload=_PAYLOAD)])
    assert rq.live_lead_rows(absent, LEAD) == [], "the mirror re-read the file without an open"
    rq.open_query_mirror(absent)
    assert [r["seq"] for r in rq.live_lead_rows(absent, LEAD)] == [0], \
        "a second open did not load the table as it now stands"
