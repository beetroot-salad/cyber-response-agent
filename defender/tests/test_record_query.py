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
    payload write must not reuse a `(lead_id, seq)`), which the frozen suite does not exercise.

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
from defender.tests.e2e.test_query_tool_611 import DONE, LEAD, SALT, q  # noqa: E402



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
    import json
    from defender._run_paths import RunPaths
    log = RunPaths(tmp_path).executed_queries
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
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
    drive(run_dir, run_id="rq-seq", salt=SALT, main=main, gather=gather, verbs=verbs)

    # lead-0 (#808) resolves against GOLDEN_AB3 ahead of MAIN's own turn and writes its
    # own (l-000) row(s) into this same table — scope to `LEAD`'s own rows, which is
    # what seq-monotonicity-within-a-lead actually means here.
    rows = [r for r in read_jsonl_rows(run_dir / "executed_queries.jsonl") if r["lead_id"] == LEAD]
    assert [r["seq"] for r in rows] == [0, 1]
    assert rows[0]["payload_path"] is None
    assert rows[1]["payload_path"] == f"gather_raw/{LEAD}/1.json"
