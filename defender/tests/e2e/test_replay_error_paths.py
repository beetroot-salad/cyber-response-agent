"""Error-path + edge-case e2e scripts — the driver's OWN error handling and the
gate-as-feedback recovery loop."""
from __future__ import annotations

import re

import json
from pathlib import Path

import pytest
from pydantic_ai import ModelRetry

from defender.tests.e2e._replay_harness import (
    GOLDEN_AB3,
    FakeVerbs,
    NeverEndsModel,
    ReplayFn,
    Turn,
    drive,
    materialize,
)
from defender.run_repository import RunPaths
from defender.agents import MAIN_DEF
from defender.runtime import circuit_breaker, tools as runtime_tools
from defender.runtime.agent_definition import bind
from defender.runtime.lead_zero import RESERVED_LEAD_IDS
from defender.scripts.adapters.faults import TransportFault
from defender.skills.invlang.validate import validate_companion

pytestmark = pytest.mark.e2e


def _own_qlines(run_dir: Path) -> list[str]:
    """The run's own queries-table lines, EXCLUDING lead-0's (#808) reserved rows —
    lead-0 resolves against every alert this suite drives (`verbs` is always injected),
    contributing rows of its own the scripted scenario never anticipated."""
    lines = (run_dir / "executed_queries.jsonl").read_text().splitlines()
    return [q for q in lines if json.loads(q).get("lead_id") not in RESERVED_LEAD_IDS]


def _down(*systems: str) -> FakeVerbs:
    def probe(ctx, *, q: str = "probe") -> list[dict]:
        raise TransportFault("connection refused")

    return FakeVerbs({s: {"probe": probe} for s in systems})


def _q(system: str) -> Turn:
    return Turn(tool_calls=[("query", {"system": system, "verb": "probe", "params": {}})])


def test_request_limit_writes_partial_trace(tmp_path):
    """Driver terminal path #1 — the request limit. The agent loop never stops on
    its own, so `agent.iter` raises UsageLimitExceeded at DEFAULT_REQUEST_LIMIT.
    The driver must treat it as an expected terminator (not a crash): catch it."""
    run_id = "limit"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)

    model = NeverEndsModel(run_dir)
    result = drive(run_dir, run_id=run_id, main=model)

    from defender.runtime import challenge_gate

    raised_limit = challenge_gate.raised_request_limit(challenge_gate.default_bounds())
    assert model.calls == raised_limit  # #774/RS7: the ceiling is raised by the gate's cap
    assert result["output"] is None
    assert result["requests"] == raised_limit
    assert (run_dir / "tool_trace.jsonl").is_file()
    assert RunPaths(run_dir).wire_log.is_file()


def test_circuit_breaker_kill_switch_aborts_run(tmp_path):
    """Driver terminal path #2 — the run-wide circuit breaker. A nested gather
    keeps hitting connectivity failures (adapter exit 2) across distinct systems;
    the RUN_FAIL_KILL_LIMIT-th raises RunAborted from circuit_breaker, deep inside"""
    run_id = "kill-switch"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)

    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic",
            "goal": "probe every source", "what_to_summarize": ["x"]})]),
        Turn(text="should not be reached — gather aborts the run first"),
    ])
    systems = ("elastic", "identity", "cmdb", "ticket", "host-state")
    assert len(systems) == circuit_breaker.RUN_FAIL_KILL_LIMIT
    gather = ReplayFn([_q(s) for s in systems] + [Turn(text="never reached")])

    result = drive(run_dir, run_id=run_id, main=main, gather=gather,
                   verbs=_down(*systems))

    assert result["output"] is None
    assert main.calls == 1
    assert gather.calls == circuit_breaker.RUN_FAIL_KILL_LIMIT
    # The breaker's counts live on the run's `RunState` (#1235), handed back in the summary.
    cb = result["run_state"].breaker_snapshot()
    assert cb["total_failures"] == circuit_breaker.RUN_FAIL_KILL_LIMIT
    qlines = _own_qlines(run_dir)
    assert len(qlines) == circuit_breaker.RUN_FAIL_KILL_LIMIT
    assert all(json.loads(q)["exit_code"] == 2 for q in qlines)
    assert (run_dir / "tool_trace.jsonl").is_file()


def test_invlang_deny_bounces_then_recovers(tmp_path):
    """Gate-as-feedback recovery: an investigation.md append that fails invlang
    validation is denied (ModelRetry), the validator's errors come back to the
    model, and a corrected append then commits. The in-process twin of the old"""
    run_id = "invlang-recover"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)
    good = (GOLDEN_AB3 / "investigation.md").read_text()
    inv = run_dir / "investigation.md"

    main = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": "```yaml\nfoo: bar\n```\n"})]),
        Turn(tool_calls=[("append_block", {"text": good})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id=run_id, main=main)

    assert main.calls == 3
    assert any("invlang validation" in s for s in main.seen)
    assert any("No changes were made" in s for s in main.seen), (
        "the refusal did not tell the model the file was left unchanged"
    )
    produced = inv.read_text()
    # The refused block left NO residue: the document is exactly the good append, not the
    # good append concatenated onto the yaml fence that was denied.
    assert produced == good
    assert validate_companion(produced, None) == []


def test_tripped_system_dispatch_returns_down_message(tmp_path):
    """Circuit-breaker dispatch + in-gather adapter gates, end-to-end. One gather
    run fails `elastic` twice (tripping its per-system breaker) and is then denied
    a third `elastic` call IN-GATHER (the _tripped_message gate — a down-message"""
    run_id = "tripped"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)

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
    result = drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=_down("elastic"))

    assert main.calls == 3
    assert gather.calls == 4
    cb = result["run_state"].breaker_snapshot()
    assert cb["systems"]["elastic"]["failures"] == circuit_breaker.PER_SYSTEM_FAIL_LIMIT
    qlines = _own_qlines(run_dir)
    assert len(qlines) == circuit_breaker.PER_SYSTEM_FAIL_LIMIT
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()
    assert "DOWN for this run" in main.seen[-1]


def test_gather_lead_guards_bounce_then_recover(tmp_path):
    """Gather dispatch guards as retry feedback: an invalid lead_id and a reused
    lead_id each bounce the main loop (ModelRetry) WITHOUT spawning the nested
    agent; a fresh, well-formed lead then dispatches normally. No data source is"""
    run_id = "lead-guards"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)

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
    drive(run_dir, run_id=run_id, main=main, gather=gather)

    assert main.calls == 5
    assert gather.calls == 2
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()
    seen = "\n".join(main.seen)
    assert "already dispatched" in seen
    assert "invalid lead_id" in seen


def test_edit_file_guards_bounce_then_recover(tmp_path):
    """edit_file's create-only / not-found / non-unique guards as retry feedback: each
    bad edit raises ModelRetry with its own reason; a unique edit then commits."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    notes = run_dir / "investigation.md"
    deps = bind(MAIN_DEF, run_dir,
                defender_dir=Path(__file__).resolve().parents[2])

    runtime_tools._tool_write_file(deps, str(notes), "alpha\nbeta\nalpha\n")

    reasons = []
    for old, new in (("", "x"), ("zzz", "x"), ("alpha", "A")):
        with pytest.raises(ModelRetry) as exc:
            runtime_tools._tool_edit_file(deps, str(notes), old, new)
        reasons.append(str(exc.value))

    runtime_tools._tool_edit_file(deps, str(notes), "beta", "BETA")

    assert notes.read_text() == "alpha\nBETA\nalpha\n"
    seen = "\n".join(reasons)
    assert "would overwrite it" in seen
    assert "old_string not found" in seen
    assert "is not unique" in seen


def test_read_file_not_found_bounces_then_recovers(tmp_path):
    """read_file's not-found guard as retry feedback: a missing run-dir file
    bounces (ModelRetry), then a real read (the untrusted alert) succeeds and comes
    back salt-wrapped — the recovery proves the bounce didn't wedge the loop."""
    run_id = "read-missing"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)

    main = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "nope.txt")})]),
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id=run_id, main=main)

    assert main.calls == 3
    assert any("file not found" in s for s in main.seen)
    assert re.search(r"<run-[0-9a-f]+-untrusted>", main.seen[-1]), \
        "the retry context carries no framed content at all"
