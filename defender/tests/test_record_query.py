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
  - `build_truncated_view` / `PASSTHROUGH_SAMPLE_COUNT` — the field-shape sampler the query
    tool's model view is built from;
  - and, re-pointed at `QueryCapture`, the seq→write→append INTEGRITY property (a failed
    payload write must not reuse a `(lead_id, seq)`), which the frozen suite does not exercise.

`_passthrough_max_bytes` / `payload_digest` / `LEAD_ID_RE` survival is pinned by
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



def _big_hits_payload(n: int) -> str:
    import json
    return json.dumps({"hits": [{"i": i, "message": f"event {i}", "pad": "x" * 50} for i in range(n)]})


def test_build_truncated_view_samples_records(tmp_path):
    payload = _big_hits_payload(200)
    view = ge.build_truncated_view(payload, "gather_raw/l-001/0.json", tmp_path)
    assert "200 records" in view
    assert view.count("sample[") == ge.PASSTHROUGH_SAMPLE_COUNT
    assert "defender-sql" in view
    assert "jq" not in view
    assert str(tmp_path / "gather_raw/l-001/0.json") in view


def test_build_truncated_view_non_json_falls_back_to_chars(tmp_path):
    view = ge.build_truncated_view("x" * 5000, "gather_raw/l-001/0.json", tmp_path)
    assert "bytes — pass-through truncated" in view
    assert "sample[" not in view


def test_build_truncated_view_capped_envelope_points_counts_at_total(tmp_path):
    import json
    payload = json.dumps({
        "index": "logs-*", "total": 2471, "returned": 20, "truncated": True,
        "hits": [{"i": i, "message": f"event {i}"} for i in range(20)],
    })
    view = ge.build_truncated_view(payload, "gather_raw/l-001/0.json", tmp_path)
    assert "2471 total matches (EXACT" in view
    assert "20-doc SAMPLE" in view
    assert "| length" not in view
    assert view.count("sample[") == ge.PASSTHROUGH_SAMPLE_COUNT


def test_build_truncated_view_complete_envelope_is_not_flagged_sampled(tmp_path):
    import json
    payload = json.dumps({
        "total": 3, "returned": 3, "truncated": False,
        "hits": [{"i": i} for i in range(3)],
    })
    view = ge.build_truncated_view(payload, "gather_raw/l-001/0.json", tmp_path)
    assert "FIELD-SHAPE sample" in view
    assert "total matches (EXACT" not in view



def _capped(hits, total=142):
    import json
    return json.dumps({
        "index": "logs-*", "total": total, "returned": len(hits),
        "truncated": True, "hits": hits,
    })


def test_capped_view_states_the_span_the_returned_docs_actually_cover(tmp_path):
    """A capped payload is ONE slice, and the envelope never says which.

    The adapter sorts `@timestamp` desc and takes the first 20, so a lead bracketing an alert
    at 11:40 with a ±15m window gets the window's last six minutes and none of the events it
    came for. `total`/`returned` cannot express that; the span can.
    """
    hits = [
        {"@timestamp": f"2026-08-07T11:5{i // 10}:0{i % 10}.000Z", "message": f"e{i}"}
        for i in range(20)
    ]
    view = ge.build_truncated_view(_capped(hits), "gather_raw/l-001/0.json", tmp_path)
    assert "2026-08-07T11:50:00.000Z … 2026-08-07T11:51:09.000Z" in view
    assert "ONE slice of the 142" in view
    assert "other 122" in view


def test_span_line_is_omitted_when_records_carry_no_timestamp(tmp_path):
    view = ge.build_truncated_view(
        _capped([{"i": i} for i in range(20)]), "gather_raw/l-001/0.json", tmp_path
    )
    assert "142 total matches (EXACT" in view
    assert "ONE slice" not in view


def _row(seq, *, params, digest, lead="l-001"):
    return {
        "lead_id": lead, "seq": seq, "system": "elastic", "verb": "query",
        "query_id": "elastic.probe", "params": params, "payload_digest": digest,
    }


def _write_rows(tmp_path, rows):
    import json
    from defender._run_paths import RunPaths
    log = RunPaths(tmp_path).executed_queries
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return tmp_path


def test_repeat_note_is_silent_on_the_first_call(tmp_path):
    _write_rows(tmp_path, [_row(0, params={"q": "a"}, digest="25904 bytes, 1 line(s)")])
    assert ge.repeat_note(
        tmp_path, "l-001", seq=0, system="elastic", verb="query",
        params={"q": "a"}, payload_digest="25904 bytes, 1 line(s)",
    ) is None


def test_repeat_note_names_the_identical_earlier_request(tmp_path):
    d = "25904 bytes, 1 line(s)"
    _write_rows(tmp_path, [
        _row(0, params={"q": "a"}, digest=d),
        _row(1, params={"q": "b"}, digest=d),
        _row(2, params={"q": "b"}, digest=d),
    ])
    note = ge.repeat_note(
        tmp_path, "l-001", seq=2, system="elastic", verb="query",
        params={"q": "b"}, payload_digest=d,
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
    d = "25904 bytes, 1 line(s)"
    _write_rows(tmp_path, [
        _row(0, params={"q": "host:db-1"}, digest=d),
        _row(1, params={"q": 'host:db-1 AND message: *"Accepted"*'}, digest=d),
    ])
    note = ge.repeat_note(
        tmp_path, "l-001", seq=1, system="elastic", verb="query",
        params={"q": 'host:db-1 AND message: *"Accepted"*'}, payload_digest=d,
    )
    assert note is not None
    assert "NO-OP" in note
    assert "seq 0" in note


def test_repeat_note_ignores_other_leads_and_later_rows(tmp_path):
    d = "25904 bytes, 1 line(s)"
    _write_rows(tmp_path, [
        _row(0, params={"q": "a"}, digest=d, lead="l-002"),
        _row(0, params={"q": "a"}, digest="404 bytes, 1 line(s)"),
        _row(1, params={"q": "a"}, digest=d),
    ])
    assert ge.repeat_note(
        tmp_path, "l-001", seq=0, system="elastic", verb="query",
        params={"q": "a"}, payload_digest="404 bytes, 1 line(s)",
    ) is None


def test_repeat_note_survives_a_missing_table(tmp_path):
    assert ge.repeat_note(
        tmp_path, "l-001", seq=3, system="elastic", verb="query",
        params={"q": "a"}, payload_digest="1 bytes, 1 line(s)",
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
