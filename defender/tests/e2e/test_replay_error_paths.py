"""Error-path + edge-case e2e scripts — the driver's OWN error handling and the
gate-as-feedback recovery loop.

The golden replays (test_replay_skeleton.py) prove the HAPPY path; these prove
the paths an organic golden never hits, because a well-behaved model doesn't loop
forever, exhaust every data source, or write invalid invlang. Each drives the
REAL driver/tools/gate end-to-end; only the model (and, where a data source is
touched, the adapter subprocess) is faked. `ReplayFn.seen` lets each script
assert the deny/abort reason bounced back to the model as retry feedback — the
wiring the pure decide_* unit tests can't observe.

Machinery (ReplayFn/drive/materialize/the model + subprocess fakes) lives in
`_replay_harness.py`; this module is just the scripts.
"""
from __future__ import annotations

import json

import pytest

from defender.tests.e2e._replay_harness import (
    GOLDEN_AB3,
    FailingAdapterSubprocess,
    NeverEndsModel,
    ReplayFn,
    Turn,
    drive,
    materialize,
)
from defender.runtime import circuit_breaker, driver
from defender.scripts.gather_tools import record_query
from defender.skills.invlang.validate import validate_companion

pytestmark = pytest.mark.e2e


def test_request_limit_writes_partial_trace(tmp_path):
    """Driver terminal path #1 — the request limit. The agent loop never stops on
    its own, so `agent.iter` raises UsageLimitExceeded at DEFAULT_REQUEST_LIMIT.
    The driver must treat it as an expected terminator (not a crash): catch it,
    still project the partial trace, and report no output (no End node)."""
    run_id, salt = "limit", "ccddeeff00112233"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id, salt=salt)

    model = NeverEndsModel(run_dir)
    result = drive(run_dir, run_id=run_id, salt=salt, main=model)

    # The loop ran EXACTLY to the request limit (the (limit+1)th request is the
    # one refused), then the driver caught the overflow and returned cleanly.
    assert model.calls == driver.DEFAULT_REQUEST_LIMIT
    assert result["output"] is None
    assert result["requests"] == driver.DEFAULT_REQUEST_LIMIT
    # Partial trace + live request log written despite the run never ending.
    assert (run_dir / "tool_trace.jsonl").is_file()
    assert (run_dir / "llm_requests.jsonl").is_file()


def test_circuit_breaker_kill_switch_aborts_run(tmp_path, monkeypatch):
    """Driver terminal path #2 — the run-wide circuit breaker. A nested gather
    keeps hitting connectivity failures (adapter exit 2) across distinct systems;
    the RUN_FAIL_KILL_LIMIT-th raises RunAborted from circuit_breaker, deep inside
    the nested gather's capture path. It must propagate up through the gather
    subagent AND the main agent.iter loop to the driver, which catches it and
    writes the partial trace — same contract as the request-limit path. (No unit
    test spans this chain; the breaker unit test stops at record_outcome.)"""
    run_id, salt = "kill-switch", "0011223344550000"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id, salt=salt)
    monkeypatch.setattr(  # lint-monkeypatch: ok — boundary: adapter subprocess IO
        record_query, "subprocess", FailingAdapterSubprocess,
    )

    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic",
            "goal": "probe every source", "what_to_summarize": ["x"]})]),
        Turn(text="should not be reached — gather aborts the run first"),
    ])
    # Five adapter calls to five DISTINCT systems: each is a system's FIRST failure
    # (so none trips the per-system breaker at 2), but the run total reaches
    # RUN_FAIL_KILL_LIMIT on the fifth → RunAborted.
    systems = ("elastic", "identity", "cmdb", "ticket", "host-state")
    assert len(systems) == circuit_breaker.RUN_FAIL_KILL_LIMIT  # the test is pinned to the limit
    gather = ReplayFn(
        [Turn(tool_calls=[("bash", {"command": f"defender-{s} query probe"})]) for s in systems]
        + [Turn(text="never reached")]
    )

    result = drive(run_dir, run_id=run_id, salt=salt, main=main, gather=gather)

    # The run did not crash: the driver caught RunAborted and returned cleanly with
    # no output, exactly like the request-limit terminator.
    assert result["output"] is None
    # Main stopped at the dispatch; the 5th gather adapter call raised before the
    # gather's own stop turn.
    assert main.calls == 1
    assert gather.calls == circuit_breaker.RUN_FAIL_KILL_LIMIT
    # Circuit-breaker state crossed the run-wide kill threshold.
    cb = json.loads((run_dir / "circuit_breaker.json").read_text())
    assert cb["total_failures"] == circuit_breaker.RUN_FAIL_KILL_LIMIT
    # Every failing adapter call was still captured (the row is written BEFORE the
    # breaker raises) — the audit trail survives the abort.
    qlines = (run_dir / "executed_queries.jsonl").read_text().splitlines()
    assert len(qlines) == circuit_breaker.RUN_FAIL_KILL_LIMIT
    assert all(json.loads(q)["exit_code"] == 2 for q in qlines)
    # Partial trace written despite the abort.
    assert (run_dir / "tool_trace.jsonl").is_file()


def test_invlang_deny_bounces_then_recovers(tmp_path):
    """Gate-as-feedback recovery: an investigation.md write that fails invlang
    validation is denied (ModelRetry), the validator's errors come back to the
    model, and a corrected rewrite then commits. The in-process twin of the old
    hook's exit-2 → fix → retry loop, proven end-to-end through the driver — the
    decide_write unit test sees the deny, never the bounce-and-recover."""
    run_id, salt = "invlang-recover", "1234123412341234"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id, salt=salt)
    good = (GOLDEN_AB3 / "investigation.md").read_text()
    inv_path = str(run_dir / "investigation.md")

    main = ReplayFn([
        # A bare ```yaml fence fails the invlang surface check (Rule 0).
        Turn(tool_calls=[("write_file", {"path": inv_path, "content": "```yaml\nfoo: bar\n```\n"})]),
        Turn(tool_calls=[("write_file", {"path": inv_path, "content": good})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=main)

    assert main.calls == 3
    # The validator's deny reached the model as retry feedback after the bad write.
    assert any("invlang validation" in s for s in main.seen)
    # The corrected content committed and is independently invlang-valid.
    produced = (run_dir / "investigation.md").read_text()
    assert produced == good
    assert validate_companion(produced, None) == []


def test_tripped_system_dispatch_returns_down_message(tmp_path, monkeypatch):
    """Circuit-breaker dispatch + in-gather adapter gates, end-to-end. One gather
    run fails `elastic` twice (tripping its per-system breaker) and is then denied
    a third `elastic` call IN-GATHER (the _tripped_message gate — a down-message
    return, not a captured query). A SECOND dispatch of the now-tripped system
    short-circuits at the DISPATCH gate: the nested gather is never spawned and the
    main loop gets the transparent 'system down' summary instead."""
    run_id, salt = "tripped", "55aa55aa55aa55aa"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id, salt=salt)
    monkeypatch.setattr(  # lint-monkeypatch: ok — boundary: adapter subprocess IO
        record_query, "subprocess", FailingAdapterSubprocess,
    )

    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),
        Turn(tool_calls=[("gather", {"lead_id": "l-002", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),
        Turn(text="done"),
    ])
    gather = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "defender-elastic query a"})]),  # fail 1
        Turn(tool_calls=[("bash", {"command": "defender-elastic query b"})]),  # fail 2 → trips
        Turn(tool_calls=[("bash", {"command": "defender-elastic query c"})]),  # gated in-gather
        Turn(text="gather l-001 incomplete"),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=main, gather=gather)

    # Main dispatched twice then ended; gather ran ONLY for l-001 (4 turns). The
    # l-002 dispatch did NOT respawn the nested agent — the dispatch gate caught it.
    assert main.calls == 3
    assert gather.calls == 4
    # elastic tripped at exactly the per-system limit (the 3rd call was gated, so
    # it did not advance the counter).
    cb = json.loads((run_dir / "circuit_breaker.json").read_text())
    assert cb["systems"]["elastic"]["failures"] == circuit_breaker.PER_SYSTEM_FAIL_LIMIT
    # Only the two pre-trip calls were captured; the 3rd (in-gather gate) was not.
    qlines = (run_dir / "executed_queries.jsonl").read_text().splitlines()
    assert len(qlines) == circuit_breaker.PER_SYSTEM_FAIL_LIMIT
    # Both leads were CLAIMED (the dispatch gate fires AFTER the claim), so l-002
    # shows in the leads table as planned-but-unmeasured.
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()
    # The transparent down-message reached the main loop for the tripped re-dispatch.
    assert "DOWN for this run" in main.seen[-1]


def test_gather_lead_guards_bounce_then_recover(tmp_path):
    """Gather dispatch guards as retry feedback: an invalid lead_id and a reused
    lead_id each bounce the main loop (ModelRetry) WITHOUT spawning the nested
    agent; a fresh, well-formed lead then dispatches normally. No data source is
    touched — the nested gather returns a text summary immediately."""
    run_id, salt = "lead-guards", "9988776655443322"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id, salt=salt)

    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),    # ok
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),    # reuse → bounce
        Turn(tool_calls=[("gather", {"lead_id": "not a lead", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),    # invalid → bounce
        Turn(tool_calls=[("gather", {"lead_id": "l-002", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),    # ok
        Turn(text="done"),
    ])
    gather = ReplayFn([Turn(text="summary l-001"), Turn(text="summary l-002")])
    drive(run_dir, run_id=run_id, salt=salt, main=main, gather=gather)

    assert main.calls == 5
    # Only the two well-formed leads spawned the nested agent; reuse + invalid
    # bounced before the spawn.
    assert gather.calls == 2
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()
    seen = "\n".join(main.seen)
    assert "already dispatched" in seen   # reuse retry reason
    assert "invalid lead_id" in seen      # malformed-id retry reason


def test_edit_file_guards_bounce_then_recover(tmp_path):
    """edit_file's create-only / not-found / non-unique guards as retry feedback,
    end-to-end: each bad edit bounces the model (ModelRetry); a unique edit then
    commits. Mirrors Claude Code's Edit semantics through the real tool + gate."""
    run_id, salt = "edit-guards", "abcdabcdabcdabcd"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id, salt=salt)
    notes = str(run_dir / "notes.md")  # a run-dir file (not investigation.md → no invlang)

    main = ReplayFn([
        Turn(tool_calls=[("write_file", {"path": notes, "content": "alpha\nbeta\nalpha\n"})]),
        Turn(tool_calls=[("edit_file", {"path": notes, "old_string": "", "new_string": "x"})]),        # clobber guard
        Turn(tool_calls=[("edit_file", {"path": notes, "old_string": "zzz", "new_string": "x"})]),      # not found
        Turn(tool_calls=[("edit_file", {"path": notes, "old_string": "alpha", "new_string": "A"})]),    # non-unique
        Turn(tool_calls=[("edit_file", {"path": notes, "old_string": "beta", "new_string": "BETA"})]),  # unique → ok
        Turn(text="done"),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=main)

    assert main.calls == 6
    assert (run_dir / "notes.md").read_text() == "alpha\nBETA\nalpha\n"
    seen = "\n".join(main.seen)
    assert "would overwrite it" in seen   # empty old_string on an existing file
    assert "old_string not found" in seen
    assert "is not unique" in seen


def test_read_file_not_found_bounces_then_recovers(tmp_path):
    """read_file's not-found guard as retry feedback: a missing run-dir file
    bounces (ModelRetry), then a real read (the untrusted alert) succeeds and comes
    back salt-wrapped — the recovery proves the bounce didn't wedge the loop."""
    run_id, salt = "read-missing", "f0f0f0f0f0f0f0f0"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id, salt=salt)

    main = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "nope.txt")})]),
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=main)

    assert main.calls == 3
    assert any("file not found" in s for s in main.seen)
    # The recovered read returned the alert, salt-wrapped as untrusted data.
    assert salt in main.seen[-1]
