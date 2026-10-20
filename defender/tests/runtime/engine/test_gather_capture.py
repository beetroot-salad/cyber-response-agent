"""Unit tests for the gather lead claim and the payload-view core."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.support.shared.contracts._spec1077 import fixture_run

import json

from defender.hooks.record_lead import ALREADY_CLAIMED, CLAIMED, claim_lead
from defender.runtime.payload_view import render
from defender.runtime.record_query import _next_seq


def test_next_seq_counts_rows_not_files(tmp_path):
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
    payload = json.dumps({"hits": [{"id": 1}, {"id": 2}]})
    assert render(payload, "gather_raw/l-001/0.json", tmp_path) == payload


def test_claim_lead_claims_then_rejects_reuse(tmp_path):
    run_dir = tmp_path / fixture_uuid("run")
    run_dir.mkdir()
    dispatch = {
        "run_dir": str(run_dir), "lead_id": "l-001",
        "goal": "did the IP resolve?", "what_to_summarize": ["a", "b"],
    }
    assert claim_lead(dispatch, run=fixture_run(run_dir)) == CLAIMED
    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert json.loads(sidecar.read_text()) == {
        "goal": "did the IP resolve?", "what_to_summarize": ["a", "b"]}
    assert claim_lead(dispatch, run=fixture_run(run_dir)) == ALREADY_CLAIMED
