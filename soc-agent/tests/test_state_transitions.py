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
            ("CONTEXTUALIZE", "SCREEN"),      # screen if playbook has it
            ("CONTEXTUALIZE", "HYPOTHESIZE"),  # skip screen
            ("CONTEXTUALIZE", "CONCLUDE"),     # ticket-context fast-resolve
            ("SCREEN", "HYPOTHESIZE"),         # screen fall-through
            ("SCREEN", "CONCLUDE"),            # screen resolved
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
            ("SCREEN", "CONTEXTUALIZE"),
            ("SCREEN", "GATHER"),
            ("SCREEN", "ANALYZE"),
            ("SCREEN", "SCREEN"),
            ("HYPOTHESIZE", "CONTEXTUALIZE"),
            ("HYPOTHESIZE", "SCREEN"),
            ("HYPOTHESIZE", "ANALYZE"),
            ("HYPOTHESIZE", "CONCLUDE"),
            ("GATHER", "CONTEXTUALIZE"),
            ("GATHER", "SCREEN"),
            ("GATHER", "HYPOTHESIZE"),
            ("GATHER", "CONCLUDE"),
            ("ANALYZE", "CONTEXTUALIZE"),
            ("ANALYZE", "SCREEN"),
            ("ANALYZE", "GATHER"),
            ("CONCLUDE", "CONTEXTUALIZE"),
            ("CONCLUDE", "SCREEN"),
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

    def test_screen_does_not_count_as_loop(self):
        history = ["CONTEXTUALIZE", "SCREEN", "HYPOTHESIZE", "GATHER", "ANALYZE"]
        assert count_loops(history) == 1


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

    def test_screen_resolve_sequence(self):
        """C -> SCREEN -> CONCLUDE is valid (screen resolved)."""
        phases = ["CONTEXTUALIZE", "SCREEN", "CONCLUDE"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_screen_fallthrough_sequence(self):
        """C -> SCREEN -> H -> G -> A -> CONCLUDE (screen didn't resolve)."""
        phases = ["CONTEXTUALIZE", "SCREEN", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_ticket_context_fast_resolve_sequence(self):
        """C -> CONCLUDE is valid (ticket-context fast-resolve for repeat alerts)."""
        phases = ["CONTEXTUALIZE", "CONCLUDE"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_skip_screen_sequence(self):
        """C -> H -> G -> A -> CONCLUDE (no screen section in playbook)."""
        phases = ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
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

        # Try illegal transition (CONTEXTUALIZE -> GATHER is not allowed)
        result = subprocess.run(
            [sys.executable, str(script), str(run_dir), "GATHER"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "Illegal" in result.stderr

    def test_write_state_enforces_max_loops(self, tmp_path):
        """Test that write_state.py rejects transitions beyond MAX_LOOPS."""
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        # Run CONTEXTUALIZE
        subprocess.run(
            [sys.executable, str(script), str(run_dir), "CONTEXTUALIZE"],
            capture_output=True,
        )

        # Run MAX_LOOPS full cycles (H->G->A)
        for _ in range(MAX_LOOPS):
            for phase in ["HYPOTHESIZE", "GATHER", "ANALYZE"]:
                result = subprocess.run(
                    [sys.executable, str(script), str(run_dir), phase],
                    capture_output=True,
                    text=True,
                )
                assert result.returncode == 0, f"Failed at {phase}: {result.stderr}"

        # The (MAX_LOOPS+1)th HYPOTHESIZE should be rejected
        result = subprocess.run(
            [sys.executable, str(script), str(run_dir), "HYPOTHESIZE"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "Maximum" in result.stderr

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

    def test_write_state_ticket_context_fast_resolve(self, tmp_path):
        """Test C -> CONCLUDE via the script (ticket-context fast-resolve)."""
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        phases = ["CONTEXTUALIZE", "CONCLUDE"]
        for phase in phases:
            args = [sys.executable, str(script), str(run_dir), phase]
            if phase == "CONTEXTUALIZE":
                args.extend(["SEC-001", "wazuh-rule-5710"])
            result = subprocess.run(args, capture_output=True, text=True)
            assert result.returncode == 0, f"Phase {phase} failed: {result.stderr}"

        state = json.loads((run_dir / "state.json").read_text())
        assert state["phase"] == "CONCLUDE"
        assert state["history"] == phases

    def test_write_state_screen_resolve_sequence(self, tmp_path):
        """Test C -> SCREEN -> CONCLUDE via the script."""
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        phases = ["CONTEXTUALIZE", "SCREEN", "CONCLUDE"]
        for phase in phases:
            args = [sys.executable, str(script), str(run_dir), phase]
            if phase == "CONTEXTUALIZE":
                args.extend(["SEC-001", "wazuh-rule-5710"])
            result = subprocess.run(args, capture_output=True, text=True)
            assert result.returncode == 0, f"Phase {phase} failed: {result.stderr}"

        state = json.loads((run_dir / "state.json").read_text())
        assert state["phase"] == "CONCLUDE"
        assert state["history"] == phases

    def test_write_state_screen_fallthrough_sequence(self, tmp_path):
        """Test C -> SCREEN -> H -> G -> A -> CONCLUDE via the script."""
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        phases = ["CONTEXTUALIZE", "SCREEN", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
        for phase in phases:
            args = [sys.executable, str(script), str(run_dir), phase]
            if phase == "CONTEXTUALIZE":
                args.extend(["SEC-001", "wazuh-rule-5710"])
            result = subprocess.run(args, capture_output=True, text=True)
            assert result.returncode == 0, f"Phase {phase} failed: {result.stderr}"

        state = json.loads((run_dir / "state.json").read_text())
        assert state["phase"] == "CONCLUDE"
        assert state["history"] == phases
