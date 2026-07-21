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

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

_RQ_PATH = Path(__file__).resolve().parents[1] / "scripts" / "gather_tools" / "record_query.py"
_spec = importlib.util.spec_from_file_location("record_query", _RQ_PATH)
ge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ge)

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

    rows = read_jsonl_rows(run_dir / "executed_queries.jsonl")
    assert [r["seq"] for r in rows] == [0, 1]
    assert rows[0]["payload_path"] is None
    assert rows[1]["payload_path"] == f"gather_raw/{LEAD}/1.json"
