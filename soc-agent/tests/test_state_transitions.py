"""Tests for investigation state machine transitions.

Tests the state.py schema and write_state.py logic.
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import (
    MAX_LOOPS,
    TRANSITIONS,
    Phase,
    count_loops,
    make_state,
    validate_transition,
)


# --- validate_transition ---


class TestValidateTransition:
    def test_initial_must_be_contextualize(self):
        valid, _ = validate_transition(None, "CONTEXTUALIZE")
        assert valid

    def test_initial_cannot_be_hypothesize(self):
        valid, error = validate_transition(None, "HYPOTHESIZE")
        assert not valid
        assert "initial phase" in error

    def test_initial_cannot_be_conclude(self):
        valid, _ = validate_transition(None, "CONCLUDE")
        assert not valid

    def test_all_legal_transitions(self):
        legal = [
            ("CONTEXTUALIZE", "HYPOTHESIZE"),
            ("HYPOTHESIZE", "GATHER"),
            ("GATHER", "ANALYZE"),
            ("ANALYZE", "HYPOTHESIZE"),  # loop back
            ("ANALYZE", "CONCLUDE"),  # finish
        ]
        for current, proposed in legal:
            valid, error = validate_transition(current, proposed)
            assert valid, f"{current} -> {proposed} should be legal: {error}"

    def test_all_illegal_transitions(self):
        illegal = [
            ("CONTEXTUALIZE", "GATHER"),
            ("CONTEXTUALIZE", "ANALYZE"),
            ("CONTEXTUALIZE", "CONCLUDE"),
            ("HYPOTHESIZE", "CONTEXTUALIZE"),
            ("HYPOTHESIZE", "ANALYZE"),
            ("HYPOTHESIZE", "CONCLUDE"),
            ("GATHER", "CONTEXTUALIZE"),
            ("GATHER", "HYPOTHESIZE"),
            ("GATHER", "CONCLUDE"),
            ("ANALYZE", "CONTEXTUALIZE"),
            ("ANALYZE", "GATHER"),
            ("CONCLUDE", "CONTEXTUALIZE"),
            ("CONCLUDE", "HYPOTHESIZE"),
            ("CONCLUDE", "GATHER"),
            ("CONCLUDE", "ANALYZE"),
        ]
        for current, proposed in illegal:
            valid, error = validate_transition(current, proposed)
            assert not valid, f"{current} -> {proposed} should be illegal"
            assert "illegal transition" in error or "none - terminal" in error

    def test_unknown_phase(self):
        valid, error = validate_transition(None, "INVALID_PHASE")
        assert not valid
        assert "unknown phase" in error

    def test_unknown_current_phase(self):
        valid, error = validate_transition("INVALID", "HYPOTHESIZE")
        assert not valid
        assert "unknown current phase" in error


# --- count_loops ---


class TestCountLoops:
    def test_no_loops(self):
        assert count_loops(["CONTEXTUALIZE"]) == 0

    def test_one_loop(self):
        history = ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE"]
        assert count_loops(history) == 1

    def test_two_loops(self):
        history = [
            "CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE",
            "HYPOTHESIZE", "GATHER", "ANALYZE",
        ]
        assert count_loops(history) == 2

    def test_max_loops(self):
        history = ["CONTEXTUALIZE"]
        for _ in range(MAX_LOOPS):
            history.extend(["HYPOTHESIZE", "GATHER", "ANALYZE"])
        assert count_loops(history) == MAX_LOOPS


# --- make_state ---


class TestMakeState:
    def test_creates_state_dict(self):
        state = make_state(
            phase="CONTEXTUALIZE",
            run_id="run-001",
            ticket_id="SEC-001",
            signature_id="wazuh-rule-5710",
            history=["CONTEXTUALIZE"],
        )
        assert state["phase"] == "CONTEXTUALIZE"
        assert state["run_id"] == "run-001"
        assert state["ticket_id"] == "SEC-001"
        assert state["history"] == ["CONTEXTUALIZE"]
        assert "updated_at" in state

    def test_default_history(self):
        state = make_state(phase="CONTEXTUALIZE", run_id="run-001")
        assert state["history"] == []


# --- Full transition sequence ---


class TestTransitionSequence:
    def test_complete_investigation(self):
        """Simulate a full C->H->G->A->CONCLUDE sequence."""
        phases = ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_investigation_with_loop(self):
        """Simulate C->H->G->A->H->G->A->CONCLUDE (one loop)."""
        phases = [
            "CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE",
            "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE",
        ]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_conclude_is_terminal(self):
        """Cannot transition out of CONCLUDE."""
        for phase in Phase:
            valid, _ = validate_transition("CONCLUDE", phase.value)
            assert not valid


# --- write_state.py integration ---


class TestWriteStateScript:
    def test_write_state_creates_file(self, tmp_path):
        """Test the write_state.py script creates state.json."""
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        result = subprocess.run(
            [sys.executable, str(script), str(run_dir), "CONTEXTUALIZE", "SEC-001", "wazuh-rule-5710"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"

        state_file = run_dir / "state.json"
        assert state_file.exists()
        state = json.loads(state_file.read_text())
        assert state["phase"] == "CONTEXTUALIZE"
        assert state["ticket_id"] == "SEC-001"

    def test_write_state_rejects_illegal(self, tmp_path):
        """Test that illegal transitions are rejected."""
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        # First write valid initial state
        subprocess.run(
            [sys.executable, str(script), str(run_dir), "CONTEXTUALIZE"],
            capture_output=True,
        )

        # Try illegal transition
        result = subprocess.run(
            [sys.executable, str(script), str(run_dir), "CONCLUDE"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "Illegal" in result.stderr

    def test_write_state_sequence(self, tmp_path):
        """Test a full valid sequence through the script."""
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        phases = ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
        for phase in phases:
            result = subprocess.run(
                [sys.executable, str(script), str(run_dir), phase],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, f"Failed at {phase}: {result.stderr}"

        state = json.loads((run_dir / "state.json").read_text())
        assert state["phase"] == "CONCLUDE"
        assert state["history"] == phases
