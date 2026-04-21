"""Tests for the Python state-machine orchestrator skeleton.

Uses stub handlers to verify that scripts/orchestrate.py drives phase
transitions correctly, persists state.json, enforces the loop cap, and rejects
illegal moves. Real subagent-dispatching handlers are layered on later.
"""

import json
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import MAX_LOOPS, Phase  # noqa: E402
from scripts.orchestrate import (  # noqa: E402
    Context,
    OrchestrationError,
    PhaseResult,
    run,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_ctx(tmp_path: Path, run_id: str = "run-test") -> Context:
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    return Context(
        run_dir=run_dir,
        signature_id="wazuh-rule-5710",
        ticket_id="alert-1",
        alert={"id": "alert-1"},
    )


def const_handler(next_phase: Phase, payload: dict | None = None):
    """Handler that always transitions to a fixed next_phase."""
    def handler(_ctx):
        return PhaseResult(next_phase=next_phase, payload=payload or {})
    return handler


def scripted_handler(*next_phases: Phase):
    """Handler that returns each next_phase in order across successive calls.

    Lets one handler be reused for multi-loop tests (e.g. ANALYZE → HYPOTHESIZE
    on loop 1, ANALYZE → CONCLUDE on loop 2).
    """
    it = iter(next_phases)

    def handler(_ctx):
        try:
            return PhaseResult(next_phase=next(it))
        except StopIteration:
            raise AssertionError("scripted_handler called more times than expected")

    return handler


# ---------------------------------------------------------------------------
# Happy-path shapes
# ---------------------------------------------------------------------------


def test_screen_match_path(tmp_path):
    """CONTEXTUALIZE -> SCREEN -> CONCLUDE — the fast path."""
    ctx = make_ctx(tmp_path)
    handlers = {
        Phase.CONTEXTUALIZE: const_handler(Phase.SCREEN),
        Phase.SCREEN: const_handler(Phase.CONCLUDE),
    }
    result = run(ctx, handlers)
    assert result["status"] == "complete"
    assert result["history"] == ["CONTEXTUALIZE", "SCREEN", "CONCLUDE"]


def test_full_loop_single_cycle(tmp_path):
    """C -> HYPOTHESIZE -> GATHER -> ANALYZE -> CONCLUDE."""
    ctx = make_ctx(tmp_path)
    handlers = {
        Phase.CONTEXTUALIZE: const_handler(Phase.HYPOTHESIZE),
        Phase.HYPOTHESIZE: const_handler(Phase.GATHER),
        Phase.GATHER: const_handler(Phase.ANALYZE),
        Phase.ANALYZE: const_handler(Phase.CONCLUDE),
    }
    result = run(ctx, handlers)
    assert result["status"] == "complete"
    assert result["history"] == [
        "CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE",
    ]


def test_full_loop_two_cycles(tmp_path):
    """Two HYPOTHESIZE/GATHER/ANALYZE cycles before CONCLUDE."""
    ctx = make_ctx(tmp_path)
    handlers = {
        Phase.CONTEXTUALIZE: const_handler(Phase.HYPOTHESIZE),
        Phase.HYPOTHESIZE: const_handler(Phase.GATHER),
        Phase.GATHER: const_handler(Phase.ANALYZE),
        Phase.ANALYZE: scripted_handler(Phase.HYPOTHESIZE, Phase.CONCLUDE),
    }
    result = run(ctx, handlers)
    assert result["history"] == [
        "CONTEXTUALIZE",
        "HYPOTHESIZE", "GATHER", "ANALYZE",
        "HYPOTHESIZE", "GATHER", "ANALYZE",
        "CONCLUDE",
    ]


def test_contextualize_to_conclude_direct(tmp_path):
    """CONTEXTUALIZE -> CONCLUDE remains a legal transition in the TRANSITIONS
    table so orchestrator mechanics support future short-circuits. The live
    dedup fast-path that used this edge is retired (see
    tasks/dedup-fast-path.md); the structural test stays to catch regressions
    in the state machine itself."""
    ctx = make_ctx(tmp_path)
    handlers = {
        Phase.CONTEXTUALIZE: const_handler(Phase.CONCLUDE, payload={"dedup": False}),
    }
    result = run(ctx, handlers)
    assert result["status"] == "complete"
    assert result["history"] == ["CONTEXTUALIZE", "CONCLUDE"]
    assert result["outputs"]["CONTEXTUALIZE"] == {"dedup": False}


def test_gather_to_hypothesize_reentry(tmp_path):
    """GATHER -> HYPOTHESIZE is legal (mid-lead fork realization)."""
    ctx = make_ctx(tmp_path)
    handlers = {
        Phase.CONTEXTUALIZE: const_handler(Phase.HYPOTHESIZE),
        Phase.HYPOTHESIZE: const_handler(Phase.GATHER),
        # First GATHER realizes a new fork; jump back to HYPOTHESIZE.
        Phase.GATHER: scripted_handler(Phase.HYPOTHESIZE, Phase.ANALYZE),
        Phase.ANALYZE: const_handler(Phase.CONCLUDE),
    }
    result = run(ctx, handlers)
    assert result["history"] == [
        "CONTEXTUALIZE",
        "HYPOTHESIZE", "GATHER",
        "HYPOTHESIZE", "GATHER", "ANALYZE",
        "CONCLUDE",
    ]


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_illegal_transition_rejected(tmp_path):
    """SCREEN -> GATHER is not in the transition table."""
    ctx = make_ctx(tmp_path)
    handlers = {
        Phase.CONTEXTUALIZE: const_handler(Phase.SCREEN),
        Phase.SCREEN: const_handler(Phase.GATHER),  # illegal
    }
    with pytest.raises(OrchestrationError, match="illegal transition SCREEN -> GATHER"):
        run(ctx, handlers)


def test_missing_handler_raises(tmp_path):
    """Orchestrator must fail loudly if a phase has no handler."""
    ctx = make_ctx(tmp_path)
    handlers = {
        Phase.CONTEXTUALIZE: const_handler(Phase.HYPOTHESIZE),
        # No HYPOTHESIZE handler registered
    }
    with pytest.raises(OrchestrationError, match="no handler registered for phase HYPOTHESIZE"):
        run(ctx, handlers)


def test_loop_cap_forces_conclude(tmp_path):
    """After MAX_LOOPS HYPOTHESIZE/ANALYZE entries the orchestrator forces CONCLUDE."""
    ctx = make_ctx(tmp_path)
    # Build a handler set that would loop forever without the cap:
    # C -> H -> G -> A -> H -> G -> A -> ...
    handlers = {
        Phase.CONTEXTUALIZE: const_handler(Phase.HYPOTHESIZE),
        Phase.HYPOTHESIZE: const_handler(Phase.GATHER),
        Phase.GATHER: const_handler(Phase.ANALYZE),
        Phase.ANALYZE: const_handler(Phase.HYPOTHESIZE),  # never concludes on its own
    }
    result = run(ctx, handlers)
    assert result["status"] == "forced_conclude"
    # History ends with CONCLUDE
    assert result["history"][-1] == "CONCLUDE"
    # Loop cap: count of H or A entries in history before the forced CONCLUDE
    # should be >= MAX_LOOPS.
    ha_count = sum(1 for p in result["history"] if p in {"HYPOTHESIZE", "ANALYZE"})
    assert ha_count >= MAX_LOOPS


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


def test_state_json_is_persisted_every_transition(tmp_path):
    """After each phase entry, state.json reflects the current phase + history."""
    ctx = make_ctx(tmp_path)
    state_path = ctx.run_dir / "state.json"

    recorded = []

    def recorder(next_phase):
        def handler(_ctx):
            recorded.append(json.loads(state_path.read_text()))
            return PhaseResult(next_phase=next_phase)
        return handler

    handlers = {
        Phase.CONTEXTUALIZE: recorder(Phase.HYPOTHESIZE),
        Phase.HYPOTHESIZE: recorder(Phase.GATHER),
        Phase.GATHER: recorder(Phase.ANALYZE),
        Phase.ANALYZE: recorder(Phase.CONCLUDE),
    }

    run(ctx, handlers)

    # At handler-call time, state.json reflects the phase that was just entered.
    phases_seen = [s["phase"] for s in recorded]
    assert phases_seen == ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE"]

    # History grows monotonically.
    histories = [s["history"] for s in recorded]
    assert histories[0] == ["CONTEXTUALIZE"]
    assert histories[-1] == ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE"]

    # Final state.json after CONCLUDE
    final = json.loads(state_path.read_text())
    assert final["phase"] == "CONCLUDE"
    assert final["history"][-1] == "CONCLUDE"


def test_payload_propagates_into_outputs(tmp_path):
    """Each handler's payload is stashed in outputs keyed by the phase that produced it."""
    ctx = make_ctx(tmp_path)
    handlers = {
        Phase.CONTEXTUALIZE: const_handler(Phase.SCREEN, payload={"entities": ["a", "b"]}),
        Phase.SCREEN: const_handler(Phase.CONCLUDE, payload={"screen_result": "match"}),
    }
    result = run(ctx, handlers)
    assert result["outputs"]["CONTEXTUALIZE"] == {"entities": ["a", "b"]}
    assert result["outputs"]["SCREEN"] == {"screen_result": "match"}
