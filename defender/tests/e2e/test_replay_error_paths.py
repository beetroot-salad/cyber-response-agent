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
    FakeVerbs,
    NeverEndsModel,
    ReplayFn,
    Turn,
    drive,
    materialize,
)
from defender.runtime import circuit_breaker, driver
from defender.scripts.adapters.faults import TransportFault
from defender.skills.invlang.validate import validate_companion

pytestmark = pytest.mark.e2e


def _down(*systems: str) -> FakeVerbs:
    def probe(ctx, *, q: str = "probe") -> list[dict]:
        raise TransportFault("connection refused")

    return FakeVerbs({s: {"probe": probe} for s in systems})


def _q(system: str) -> Turn:
    return Turn(tool_calls=[("query", {"system": system, "verb": "probe", "params": {}})])


def test_request_limit_writes_partial_trace(tmp_path):
    """Driver terminal path #1 — the request limit. The agent loop never stops on
    its own, so `agent.iter` raises UsageLimitExceeded at DEFAULT_REQUEST_LIMIT.
    The driver must treat it as an expected terminator (not a crash): catch it,
    still project the partial trace, and report no output (no End node)."""
    run_id, salt = "limit", "ccddeeff00112233"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    model = NeverEndsModel(run_dir)
    result = drive(run_dir, run_id=run_id, salt=salt, main=model)

    assert model.calls == driver.DEFAULT_REQUEST_LIMIT
    assert result["output"] is None
    assert result["requests"] == driver.DEFAULT_REQUEST_LIMIT
    assert (run_dir / "tool_trace.jsonl").is_file()
    assert (run_dir / "llm_requests.jsonl").is_file()


def test_circuit_breaker_kill_switch_aborts_run(tmp_path):
    """Driver terminal path #2 — the run-wide circuit breaker. A nested gather
    keeps hitting connectivity failures (adapter exit 2) across distinct systems;
    the RUN_FAIL_KILL_LIMIT-th raises RunAborted from circuit_breaker, deep inside
    the nested gather's capture path. It must propagate up through the gather
    subagent AND the main agent.iter loop to the driver, which catches it and
    writes the partial trace — same contract as the request-limit path. (No unit
    test spans this chain; the breaker unit test stops at record_outcome.)

    Since #611 the capture path is the `query` tool's capability, and `RunAborted` has to
    survive its catch-all: the broad `except BaseException` that stops a transport fault from
    unwinding the run is exactly what would swallow the kill switch, because `RunAborted` is a
    plain `Exception` subclass. This test is what says it does not."""
    run_id, salt = "kill-switch", "0011223344550000"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic",
            "goal": "probe every source", "what_to_summarize": ["x"]})]),
        Turn(text="should not be reached — gather aborts the run first"),
    ])
    systems = ("elastic", "identity", "cmdb", "ticket", "host-state")
    assert len(systems) == circuit_breaker.RUN_FAIL_KILL_LIMIT
    gather = ReplayFn([_q(s) for s in systems] + [Turn(text="never reached")])

    result = drive(run_dir, run_id=run_id, salt=salt, main=main, gather=gather,
                   verbs=_down(*systems))

    assert result["output"] is None
    assert main.calls == 1
    assert gather.calls == circuit_breaker.RUN_FAIL_KILL_LIMIT
    cb = json.loads((run_dir / "circuit_breaker.json").read_text())
    assert cb["total_failures"] == circuit_breaker.RUN_FAIL_KILL_LIMIT
    qlines = (run_dir / "executed_queries.jsonl").read_text().splitlines()
    assert len(qlines) == circuit_breaker.RUN_FAIL_KILL_LIMIT
    assert all(json.loads(q)["exit_code"] == 2 for q in qlines)
    assert (run_dir / "tool_trace.jsonl").is_file()


def test_invlang_deny_bounces_then_recovers(tmp_path):
    """Gate-as-feedback recovery: an investigation.md write that fails invlang
    validation is denied (ModelRetry), the validator's errors come back to the
    model, and a corrected rewrite then commits. The in-process twin of the old
    hook's exit-2 → fix → retry loop, proven end-to-end through the driver — the
    decide_write unit test sees the deny, never the bounce-and-recover."""
    run_id, salt = "invlang-recover", "1234123412341234"
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    good = (GOLDEN_AB3 / "investigation.md").read_text()
    inv_path = str(run_dir / "investigation.md")

    main = ReplayFn([
        Turn(tool_calls=[("write_file", {"path": inv_path, "content": "```yaml\nfoo: bar\n```\n"})]),
        Turn(tool_calls=[("write_file", {"path": inv_path, "content": good})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=main)

    assert main.calls == 3
    assert any("invlang validation" in s for s in main.seen)
    produced = (run_dir / "investigation.md").read_text()
    assert produced == good
    assert validate_companion(produced, None) == []


def test_tripped_system_dispatch_returns_down_message(tmp_path):
    """Circuit-breaker dispatch + in-gather adapter gates, end-to-end. One gather
    run fails `elastic` twice (tripping its per-system breaker) and is then denied
    a third `elastic` call IN-GATHER (the _tripped_message gate — a down-message
    return, not a captured query). A SECOND dispatch of the now-tripped system
    short-circuits at the DISPATCH gate: the nested gather is never spawned and the
    main loop gets the transparent 'system down' summary instead."""
    run_id, salt = "tripped", "55aa55aa55aa55aa"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),
        Turn(tool_calls=[("gather", {"lead_id": "l-002", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),
        Turn(text="done"),
    ])
    gather = ReplayFn([
        _q("elastic"),
        _q("elastic"),
        _q("elastic"),
        Turn(text="gather l-001 incomplete"),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=main, gather=gather, verbs=_down("elastic"))

    assert main.calls == 3
    assert gather.calls == 4
    cb = json.loads((run_dir / "circuit_breaker.json").read_text())
    assert cb["systems"]["elastic"]["failures"] == circuit_breaker.PER_SYSTEM_FAIL_LIMIT
    qlines = (run_dir / "executed_queries.jsonl").read_text().splitlines()
    assert len(qlines) == circuit_breaker.PER_SYSTEM_FAIL_LIMIT
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()
    assert "DOWN for this run" in main.seen[-1]


def test_gather_lead_guards_bounce_then_recover(tmp_path):
    """Gather dispatch guards as retry feedback: an invalid lead_id and a reused
    lead_id each bounce the main loop (ModelRetry) WITHOUT spawning the nested
    agent; a fresh, well-formed lead then dispatches normally. No data source is
    touched — the nested gather returns a text summary immediately."""
    run_id, salt = "lead-guards", "9988776655443322"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),
        Turn(tool_calls=[("gather", {"lead_id": "not a lead", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),
        Turn(tool_calls=[("gather", {"lead_id": "l-002", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["x"]})]),
        Turn(text="done"),
    ])
    gather = ReplayFn([Turn(text="summary l-001"), Turn(text="summary l-002")])
    drive(run_dir, run_id=run_id, salt=salt, main=main, gather=gather)

    assert main.calls == 5
    assert gather.calls == 2
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()
    seen = "\n".join(main.seen)
    assert "already dispatched" in seen
    assert "invalid lead_id" in seen


def test_edit_file_guards_bounce_then_recover(tmp_path):
    """edit_file's create-only / not-found / non-unique guards as retry feedback,
    end-to-end: each bad edit bounces the model (ModelRetry); a unique edit then
    commits. Mirrors Claude Code's Edit semantics through the real tool + gate."""
    run_id, salt = "edit-guards", "abcdabcdabcdabcd"
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    notes = str(run_dir / "report.md")
    fm = "---\ndisposition: benign\n---\n"

    main = ReplayFn([
        Turn(tool_calls=[("write_file", {"path": notes, "content": fm + "alpha\nbeta\nalpha\n"})]),
        Turn(tool_calls=[("edit_file", {"path": notes, "old_string": "", "new_string": "x"})]),
        Turn(tool_calls=[("edit_file", {"path": notes, "old_string": "zzz", "new_string": "x"})]),
        Turn(tool_calls=[("edit_file", {"path": notes, "old_string": "alpha", "new_string": "A"})]),
        Turn(tool_calls=[("edit_file", {"path": notes, "old_string": "beta", "new_string": "BETA"})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=main)

    assert main.calls == 6
    assert (run_dir / "report.md").read_text() == fm + "alpha\nBETA\nalpha\n"
    seen = "\n".join(main.seen)
    assert "would overwrite it" in seen
    assert "old_string not found" in seen
    assert "is not unique" in seen


def test_read_file_not_found_bounces_then_recovers(tmp_path):
    """read_file's not-found guard as retry feedback: a missing run-dir file
    bounces (ModelRetry), then a real read (the untrusted alert) succeeds and comes
    back salt-wrapped — the recovery proves the bounce didn't wedge the loop."""
    run_id, salt = "read-missing", "f0f0f0f0f0f0f0f0"
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    main = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "nope.txt")})]),
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=main)

    assert main.calls == 3
    assert any("file not found" in s for s in main.seen)
    assert salt in main.seen[-1]
