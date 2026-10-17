"""Unit tests for the gather lead claim and the payload-view core."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run

import json

from defender.hooks.record_lead import ALREADY_CLAIMED, CLAIMED, claim_lead
from defender.runtime.payload_view import render
from defender.scripts.gather_tools.record_query import _next_seq


def test_next_seq_counts_rows_not_files(tmp_path):
    """The next seq counts the lead's table ROWS — not the payload files under `gather_raw/` — as
    the run's state holds them (#1235): a row counts once it is on the state (here a branch
    sibling's inherited prefix, the one way a run starts holding rows, round 2), whether or not a
    payload file backs it, and a payload file with no row counts nothing."""
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
    """This asserted the opposite until #832: a 30-byte two-record payload came back as a "FIELD-
    SHAPE sample" — the records replaced by a notice and a disk path — because the key happened
    to be spelled `hits`."""
    payload = json.dumps({"hits": [{"id": 1}, {"id": 2}]})
    assert render(payload, "gather_raw/l-001/0.json", tmp_path) == payload


def test_claim_lead_claims_then_rejects_reuse(tmp_path):
    dispatch = {
        "run_dir": str(tmp_path), "lead_id": "l-001",
        "goal": "did the IP resolve?", "what_to_summarize": ["a", "b"],
    }
    assert claim_lead(dispatch, run=fixture_run(tmp_path)) == CLAIMED
    sidecar = tmp_path / "gather_raw" / "l-001.lead.json"
    assert json.loads(sidecar.read_text()) == {
        "goal": "did the IP resolve?", "what_to_summarize": ["a", "b"]}
    assert claim_lead(dispatch, run=fixture_run(tmp_path)) == ALREADY_CLAIMED
