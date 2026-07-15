"""Pure unit tests for the gather lead claim + the payload-view core (no model, CI).

`record_lead.claim_lead()` is the atomic lead-id claim the `gather` dispatch tool calls.

**What used to live here.** This file was the unit suite for `record_query.capture()` — the
subprocess wrapper that ran an adapter, persisted its stdout and appended the queries row. #611
deleted that function: a data-source call is the typed `query` tool now, and the row + by-ref
payload are written in-process by its capture capability. Every capture assertion this file made
(the twelve-key row, per-lead `seq` monotonicity, the error/empty statuses, the traversal-
`query_id` rejection, the `adapter | defender-sql` aggregation) is re-made END-TO-END against the
real tool in `tests/e2e/test_query_tool_611.py`, one layer up and through the real gate — so they
are not lost, they moved to where the behaviour now is. What remains here is the part that was
never about the process boundary: the lead claim, and the payload VIEW helpers `record_query`
still owns (`_next_seq` and the truncated in-context view), which the `read_file` tool shares.
"""
from __future__ import annotations

import json

from defender._io import append_jsonl
from defender.hooks.record_lead import claim_lead
from defender.scripts.gather_tools.record_query import _next_seq, build_truncated_view


def test_next_seq_counts_rows_not_files(tmp_path):
    # seq is the number of ROWS already recorded for the lead, not the payload files on disk.
    # That is what keeps it monotonic when a payload WRITE failed: that query still appends a
    # row with `payload_path: null`, so the next query cannot reuse the seq and collide on the
    # `(lead_id, seq)` key the whole learning loop joins on.
    assert _next_seq(tmp_path, "l-001") == 0
    append_jsonl(tmp_path / "executed_queries.jsonl", [
        {"lead_id": "l-001", "seq": 0, "payload_path": None},   # payload write failed
        {"lead_id": "l-002", "seq": 0, "payload_path": "gather_raw/l-002/0.json"},
    ])
    assert _next_seq(tmp_path, "l-001") == 1     # counted the row, not the missing file
    assert _next_seq(tmp_path, "l-002") == 1     # a different lead sequences independently


def test_truncated_view_samples_the_field_shape(tmp_path):
    # The in-context view of a record-list payload is a count + a few sample records + a disk
    # pointer — never the dump. The agent writes its filters from the SHAPE and computes every
    # value over the persisted file; the reduced view is also what stops a multi-MB payload
    # re-entering the subagent's context on every subsequent request.
    payload = json.dumps({"hits": [{"id": 1}, {"id": 2}]})
    view = build_truncated_view(payload, "gather_raw/l-001/0.json", tmp_path)

    assert "2 records" in view
    assert "FIELD-SHAPE sample" in view
    assert "sample[0]" in view
    assert str(tmp_path / "gather_raw/l-001/0.json") in view   # the pointer is ABSOLUTE
    assert payload not in view                                  # the dump itself never appears


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
