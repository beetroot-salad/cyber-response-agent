"""Pure unit tests for the gather lead claim + the payload-view core (no model, CI).

`record_lead.claim_lead()` is the atomic lead-id claim the `gather` dispatch tool calls.

**What used to live here.** This file was the unit suite for `record_query.capture()` — the
subprocess wrapper that ran an adapter, persisted its stdout and appended the queries row. #611
deleted that function: a data-source call is the typed `query` tool now, and the row + by-ref
payload are written in-process by its capture capability. Every capture assertion this file made
(the frozen queries row, per-lead `seq` monotonicity, the error/empty statuses, the traversal-
`query_id` rejection, the `adapter | defender-sql` aggregation) is re-made END-TO-END against the
real tool in `tests/e2e/test_query_tool_611.py`, one layer up and through the real gate — so they
are not lost, they moved to where the behaviour now is. What remains here is the part that was
never about the process boundary: the lead claim, and the payload VIEW helpers `record_query`
still owns (`_next_seq` and the truncated in-context view), which the `read_file` tool shares.
"""
from __future__ import annotations

import json

from defender.hooks.record_lead import ALREADY_CLAIMED, CLAIMED, claim_lead
from defender.runtime.payload_view import render
from defender.scripts.gather_tools.record_query import _next_seq


def test_next_seq_counts_rows_not_files(tmp_path):
    """The next seq counts the lead's table ROWS — not the payload files under `gather_raw/` —
    as the run's state holds them (#1235): a row counts once it is on the state (here a branch
    sibling's inherited prefix, the one way a run starts holding rows, round 2), whether or not
    a payload file backs it, and a payload file with no row counts nothing."""
    from defender.runtime.run_state import RunState

    state = RunState(tmp_path, "r-next-seq")
    assert _next_seq(state, "l-001") == 0
    state.inherit_rows([
        {"lead_id": "l-001", "seq": 0, "payload_path": None},
        {"lead_id": "l-002", "seq": 0, "payload_path": "gather_raw/l-002/0.json"},
    ])
    assert _next_seq(state, "l-001") == 1
    assert _next_seq(state, "l-002") == 1
    orphan = tmp_path / "gather_raw" / "l-003" / "0.json"
    orphan.parent.mkdir(parents=True)
    orphan.write_text("[]", encoding="utf-8")
    assert _next_seq(state, "l-003") == 0, "a payload file with no row was counted as a row"


def test_a_small_payload_reaches_the_lead_whole(tmp_path):
    """This asserted the opposite until #832: a 30-byte two-record payload came back as a
    "FIELD-SHAPE sample" — the records replaced by a notice and a disk path — because the key
    happened to be spelled `hits`. The same two records under any other name rode through
    untouched. Size decides now, and 30 bytes is not a context problem."""
    payload = json.dumps({"hits": [{"id": 1}, {"id": 2}]})
    assert render(payload, "gather_raw/l-001/0.json", tmp_path) == payload


def test_claim_lead_claims_then_rejects_reuse(tmp_path):
    dispatch = {
        "run_dir": str(tmp_path), "lead_id": "l-001",
        "goal": "did the IP resolve?", "what_to_summarize": ["a", "b"],
    }
    assert claim_lead(dispatch) == CLAIMED
    sidecar = tmp_path / "gather_raw" / "l-001.lead.json"
    assert json.loads(sidecar.read_text()) == {
        "goal": "did the IP resolve?", "what_to_summarize": ["a", "b"]}
    assert claim_lead(dispatch) == ALREADY_CLAIMED
