"""Pure unit tests for the gather capture core + lead claim (no model, CI).

`record_query.capture()` is the harness capability behind gather's data-source
access (the in-process replacement for the `defender-record-query` wrapper): run
an adapter, persist its payload, append the queries-table row. `record_lead.
claim_lead()` is the atomic lead-id claim the `gather` dispatch tool calls.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_DEFENDER = Path(__file__).resolve().parents[1]
for _p in (_DEFENDER, _DEFENDER / "hooks", _DEFENDER / "scripts" / "tools"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from defender.scripts.tools.record_query import capture  # noqa: E402
from record_lead import claim_lead  # noqa: E402

# A stub adapter named like an adapter CLI so derive_system → "elastic".
# argv[1] selects the mode (ok / empty / error).
_STUB = """#!/usr/bin/env python3
import sys
mode = sys.argv[1] if len(sys.argv) > 1 else "ok"
if mode == "error":
    sys.stderr.write("connection refused\\n"); sys.exit(2)
if mode == "empty":
    sys.exit(0)
sys.stdout.write('{"hits": [{"id": 1}, {"id": 2}]}')
"""


@pytest.fixture
def stub(tmp_path):
    p = tmp_path / "elastic_cli.py"
    p.write_text(_STUB)
    return p


def _argv(stub, mode):
    return [sys.executable, str(stub), mode]


def test_capture_ok_writes_row_and_payload(tmp_path, stub):
    passthrough, stderr, record = capture(tmp_path, "l-001", _argv(stub, "ok"))

    # The queries-table row carries the full schema the lead-author reads.
    assert record["lead_id"] == "l-001"
    assert record["seq"] == 0
    assert record["system"] == "elastic"
    assert record["verb"] == "ok"
    assert record["query_id"] == "elastic.ok"      # derived {system}.{verb}
    assert record["params"] == {}
    assert "elastic_cli.py" in record["raw_command"]
    assert record["payload_path"] == "gather_raw/l-001/0.json"
    assert record["exit_code"] == 0
    assert record["payload_status"] == "ok"
    assert record["payload_digest"]

    # The payload is persisted by-ref, verbatim; the row is appended to the table.
    payload = (tmp_path / record["payload_path"]).read_text()
    assert json.loads(payload) == {"hits": [{"id": 1}, {"id": 2}]}
    rows = (tmp_path / "executed_queries.jsonl").read_text().splitlines()
    assert len(rows) == 1 and json.loads(rows[0])["seq"] == 0
    assert passthrough == payload  # small payload → passthrough is verbatim


def test_capture_seq_is_monotonic_per_lead(tmp_path, stub):
    capture(tmp_path, "l-001", _argv(stub, "ok"))
    _, _, r2 = capture(tmp_path, "l-001", _argv(stub, "ok"))
    assert r2["seq"] == 1
    assert r2["payload_path"] == "gather_raw/l-001/1.json"
    # A different lead sequences independently.
    _, _, r_other = capture(tmp_path, "l-002", _argv(stub, "ok"))
    assert r_other["seq"] == 0


def test_capture_error_status(tmp_path, stub):
    _, stderr, record = capture(tmp_path, "l-001", _argv(stub, "error"))
    assert record["exit_code"] == 2
    assert record["payload_status"] == "error"
    assert "connection refused" in stderr
    # A failed query still appends a row (so seq stays monotonic).
    assert (tmp_path / "executed_queries.jsonl").read_text().strip()


def test_capture_empty_status(tmp_path, stub):
    _, _, record = capture(tmp_path, "l-001", _argv(stub, "empty"))
    assert record["exit_code"] == 0
    assert record["payload_status"] == "empty"


def test_capture_rejects_bad_lead(tmp_path, stub):
    with pytest.raises(ValueError):
        capture(tmp_path, "../escape", _argv(stub, "ok"))


def test_capture_rejects_undetectable_system(tmp_path):
    # No defender-<system> shim / <system>_cli.py token → system can't be derived.
    with pytest.raises(ValueError):
        capture(tmp_path, "l-001", ["echo", "hi"])


def test_claim_lead_claims_then_rejects_reuse(tmp_path):
    dispatch = {
        "run_dir": str(tmp_path), "lead_id": "l-001",
        "goal": "did the IP resolve?", "what_to_summarize": ["a", "b"],
    }
    assert claim_lead(dispatch) == 0
    sidecar = tmp_path / "gather_raw" / "l-001.lead.json"
    assert json.loads(sidecar.read_text()) == {
        "goal": "did the IP resolve?", "what_to_summarize": ["a", "b"]}
    # A reused id is rejected (the gather tool maps this to ModelRetry).
    assert claim_lead(dispatch) == 2
