"""Tests for investigation state machine transitions.

Tests the state.py schema, write_state.py logic, and infer_state_pre.py hook.
"""

import json
import subprocess
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
        valid, error = validate_transition(None, "PREDICT")
        assert not valid
        assert "initial phase" in error

    def test_initial_cannot_be_conclude(self):
        valid, _ = validate_transition(None, "REPORT")
        assert not valid

    def test_all_legal_transitions(self):
        legal = [
            ("CONTEXTUALIZE", "SCREEN"),       # screen if playbook has it
            ("CONTEXTUALIZE", "PREDICT"),  # branching-first case
            ("CONTEXTUALIZE", "GATHER"),       # pure-gathering first lead (no/no cell)
            ("CONTEXTUALIZE", "REPORT"),     # ticket-context fast-resolve
            ("SCREEN", "PREDICT"),         # screen fall-through
            ("SCREEN", "REPORT"),            # screen resolved
            ("PREDICT", "GATHER"),
            ("GATHER", "ANALYZE"),
            ("GATHER", "PREDICT"),         # mid-lead fork discovery
            ("ANALYZE", "PREDICT"),        # loop back
            ("ANALYZE", "REPORT"),           # finish
        ]
        for current, proposed in legal:
            valid, error = validate_transition(current, proposed)
            assert valid, f"{current} -> {proposed} should be legal: {error}"

    def test_all_illegal_transitions(self):
        illegal = [
            ("CONTEXTUALIZE", "ANALYZE"),
            ("SCREEN", "CONTEXTUALIZE"),
            ("SCREEN", "GATHER"),
            ("SCREEN", "ANALYZE"),
            ("SCREEN", "SCREEN"),
            ("PREDICT", "CONTEXTUALIZE"),
            ("PREDICT", "SCREEN"),
            ("PREDICT", "ANALYZE"),
            ("PREDICT", "REPORT"),
            ("GATHER", "CONTEXTUALIZE"),
            ("GATHER", "SCREEN"),
            ("GATHER", "REPORT"),
            ("ANALYZE", "CONTEXTUALIZE"),
            ("ANALYZE", "SCREEN"),
            ("ANALYZE", "GATHER"),
            ("REPORT", "CONTEXTUALIZE"),
            ("REPORT", "SCREEN"),
            ("REPORT", "PREDICT"),
            ("REPORT", "GATHER"),
            ("REPORT", "ANALYZE"),
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
        valid, error = validate_transition("INVALID", "PREDICT")
        assert not valid
        assert "unknown current phase" in error


# --- count_loops ---


class TestCountLoops:
    # A cycle = any PREDICT or ANALYZE entry. One full H→G→A cycle yields 2.
    def test_no_loops(self):
        assert count_loops(["CONTEXTUALIZE"]) == 0

    def test_one_cycle_counts_two(self):
        history = ["CONTEXTUALIZE", "PREDICT", "GATHER", "ANALYZE"]
        assert count_loops(history) == 2

    def test_two_cycles_count_four(self):
        history = [
            "CONTEXTUALIZE", "PREDICT", "GATHER", "ANALYZE",
            "PREDICT", "GATHER", "ANALYZE",
        ]
        assert count_loops(history) == 4

    def test_gather_analyze_without_rehypothesis_still_counts(self):
        # Under on-demand PREDICT, a GATHER→ANALYZE cycle with no
        # re-entry to PREDICT still advances the loop counter.
        history = [
            "CONTEXTUALIZE", "PREDICT", "GATHER", "ANALYZE",
            "GATHER", "ANALYZE",  # no new PREDICT
        ]
        assert count_loops(history) == 3  # 1 H + 2 A

    def test_screen_does_not_count_as_loop(self):
        history = ["CONTEXTUALIZE", "SCREEN", "PREDICT", "GATHER", "ANALYZE"]
        assert count_loops(history) == 2  # 1 H + 1 A


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
        """Simulate a full C->H->G->A->REPORT sequence."""
        phases = ["CONTEXTUALIZE", "PREDICT", "GATHER", "ANALYZE", "REPORT"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_investigation_with_loop(self):
        """Simulate C->H->G->A->H->G->A->REPORT (one loop)."""
        phases = [
            "CONTEXTUALIZE", "PREDICT", "GATHER", "ANALYZE",
            "PREDICT", "GATHER", "ANALYZE", "REPORT",
        ]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_screen_resolve_sequence(self):
        """C -> SCREEN -> REPORT is valid (screen resolved)."""
        phases = ["CONTEXTUALIZE", "SCREEN", "REPORT"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_screen_fallthrough_sequence(self):
        """C -> SCREEN -> H -> G -> A -> REPORT (screen didn't resolve)."""
        phases = ["CONTEXTUALIZE", "SCREEN", "PREDICT", "GATHER", "ANALYZE", "REPORT"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_ticket_context_fast_resolve_sequence(self):
        """C -> REPORT is valid (ticket-context fast-resolve for repeat alerts)."""
        phases = ["CONTEXTUALIZE", "REPORT"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_skip_screen_sequence(self):
        """C -> H -> G -> A -> REPORT (no screen section in playbook)."""
        phases = ["CONTEXTUALIZE", "PREDICT", "GATHER", "ANALYZE", "REPORT"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"Failed at {current} -> {phase}: {error}"
            current = phase

    def test_conclude_is_terminal(self):
        """Cannot transition out of REPORT."""
        for phase in Phase:
            valid, _ = validate_transition("REPORT", phase.value)
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

        # Try illegal transition (CONTEXTUALIZE -> ANALYZE is not allowed)
        result = subprocess.run(
            [sys.executable, str(script), str(run_dir), "ANALYZE"],
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

        # Each H->G->A cycle adds 2 to count_loops (one H + one A). Run the
        # maximum number of full cycles that still fits under the cap.
        full_cycles = MAX_LOOPS // 2
        for _ in range(full_cycles):
            for phase in ["PREDICT", "GATHER", "ANALYZE"]:
                result = subprocess.run(
                    [sys.executable, str(script), str(run_dir), phase],
                    capture_output=True,
                    text=True,
                )
                assert result.returncode == 0, f"Failed at {phase}: {result.stderr}"

        # Next PREDICT would push count past MAX_LOOPS → rejected.
        result = subprocess.run(
            [sys.executable, str(script), str(run_dir), "PREDICT"],
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

        phases = ["CONTEXTUALIZE", "PREDICT", "GATHER", "ANALYZE", "REPORT"]
        for phase in phases:
            result = subprocess.run(
                [sys.executable, str(script), str(run_dir), phase],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, f"Failed at {phase}: {result.stderr}"

        state = json.loads((run_dir / "state.json").read_text())
        assert state["phase"] == "REPORT"
        assert state["history"] == phases

    def test_write_state_ticket_context_fast_resolve(self, tmp_path):
        """Test C -> REPORT via the script (ticket-context fast-resolve)."""
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        phases = ["CONTEXTUALIZE", "REPORT"]
        for phase in phases:
            args = [sys.executable, str(script), str(run_dir), phase]
            if phase == "CONTEXTUALIZE":
                args.extend(["SEC-001", "wazuh-rule-5710"])
            result = subprocess.run(args, capture_output=True, text=True)
            assert result.returncode == 0, f"Phase {phase} failed: {result.stderr}"

        state = json.loads((run_dir / "state.json").read_text())
        assert state["phase"] == "REPORT"
        assert state["history"] == phases

    def test_write_state_screen_resolve_sequence(self, tmp_path):
        """Test C -> SCREEN -> REPORT via the script."""
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        phases = ["CONTEXTUALIZE", "SCREEN", "REPORT"]
        for phase in phases:
            args = [sys.executable, str(script), str(run_dir), phase]
            if phase == "CONTEXTUALIZE":
                args.extend(["SEC-001", "wazuh-rule-5710"])
            result = subprocess.run(args, capture_output=True, text=True)
            assert result.returncode == 0, f"Phase {phase} failed: {result.stderr}"

        state = json.loads((run_dir / "state.json").read_text())
        assert state["phase"] == "REPORT"
        assert state["history"] == phases

    def test_write_state_screen_fallthrough_sequence(self, tmp_path):
        """Test C -> SCREEN -> H -> G -> A -> REPORT via the script."""
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        phases = ["CONTEXTUALIZE", "SCREEN", "PREDICT", "GATHER", "ANALYZE", "REPORT"]
        for phase in phases:
            args = [sys.executable, str(script), str(run_dir), phase]
            if phase == "CONTEXTUALIZE":
                args.extend(["SEC-001", "wazuh-rule-5710"])
            result = subprocess.run(args, capture_output=True, text=True)
            assert result.returncode == 0, f"Phase {phase} failed: {result.stderr}"

        state = json.loads((run_dir / "state.json").read_text())
        assert state["phase"] == "REPORT"
        assert state["history"] == phases


# --- infer_state_pre.py PreToolUse hook ---


def _run_pre_hook(
    hook_data: dict, runs_dir: Path | None = None
) -> subprocess.CompletedProcess:
    script = SOC_AGENT_ROOT / "hooks" / "scripts" / "infer_state_pre.py"
    env = None
    if runs_dir is not None:
        import os
        env = {**os.environ, "SOC_AGENT_RUNS_DIR": str(runs_dir)}
    return subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(hook_data),
        capture_output=True,
        text=True,
        env=env,
    )


def _write_hook_data(file_path: Path, content: str) -> dict:
    return {
        "tool_name": "Write",
        "tool_input": {"file_path": str(file_path), "content": content},
        "session_id": "test-session",
    }


def _edit_hook_data(
    file_path: Path, old_string: str, new_string: str, replace_all: bool = False
) -> dict:
    return {
        "tool_name": "Edit",
        "tool_input": {
            "file_path": str(file_path),
            "old_string": old_string,
            "new_string": new_string,
            "replace_all": replace_all,
        },
        "session_id": "test-session",
    }


class TestInferStatePre:
    def _setup_run(self, tmp_path) -> tuple[Path, Path, Path]:
        """Create a minimal run dir. Returns (run_dir, inv_path, runs_dir)."""
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        run_dir = runs_dir / "run-test"
        run_dir.mkdir()
        (run_dir / "meta.json").write_text(json.dumps({
            "run_id": "run-test",
            "signature_id": "wazuh-rule-test",
        }))
        inv = run_dir / "investigation.md"
        return run_dir, inv, runs_dir

    def test_write_initial_contextualize_passes(self, tmp_path):
        run_dir, inv, runs_dir = self._setup_run(tmp_path)
        result = _run_pre_hook(
            _write_hook_data(inv, "## CONTEXTUALIZE\n\nsome content"),
            runs_dir=runs_dir,
        )
        assert result.returncode == 0

    def test_write_duplicate_contextualize_blocked(self, tmp_path):
        """The exact bug from run 20260416-052335-rule100001: duplicate ## CONTEXTUALIZE
        created by a botched edit must be blocked before the file lands."""
        run_dir, inv, runs_dir = self._setup_run(tmp_path)

        # Simulate state after the first valid write (CONTEXTUALIZE in state.json)
        state = {
            "run_id": "run-test",
            "ticket_id": "",
            "signature_id": "wazuh-rule-test",
            "phase": "CONTEXTUALIZE",
            "history": ["CONTEXTUALIZE"],
        }
        (run_dir / "state.json").write_text(json.dumps(state))

        # Write the file with one CONTEXTUALIZE so the Edit simulation has something to read
        inv.write_text("## CONTEXTUALIZE\n\nsome content\n")

        # Simulate the bad Edit: "## CONTEXTUALIZE" → "## CONTEXTUALIZE\n\n## CONTEXTUALIZE"
        hook = _edit_hook_data(
            inv,
            old_string="## CONTEXTUALIZE",
            new_string="## CONTEXTUALIZE\n\n## CONTEXTUALIZE",
        )
        result = _run_pre_hook(hook, runs_dir=runs_dir)
        assert result.returncode == 2
        assert "CONTEXTUALIZE -> CONTEXTUALIZE" in result.stderr

    def test_edit_adding_hypothesize_passes(self, tmp_path):
        run_dir, inv, runs_dir = self._setup_run(tmp_path)
        state = {
            "run_id": "run-test",
            "ticket_id": "",
            "signature_id": "wazuh-rule-test",
            "phase": "CONTEXTUALIZE",
            "history": ["CONTEXTUALIZE"],
        }
        (run_dir / "state.json").write_text(json.dumps(state))
        inv.write_text("## CONTEXTUALIZE\n\nsome content\n")

        hook = _edit_hook_data(
            inv,
            old_string="some content",
            new_string="some content\n\n## PREDICT (loop 1)\n\nhypotheses here",
        )
        result = _run_pre_hook(hook, runs_dir=runs_dir)
        assert result.returncode == 0

    def test_edit_illegal_skip_blocked(self, tmp_path):
        """Skipping GATHER (going PREDICT→ANALYZE directly) is blocked."""
        run_dir, inv, runs_dir = self._setup_run(tmp_path)
        state = {
            "run_id": "run-test",
            "ticket_id": "",
            "signature_id": "wazuh-rule-test",
            "phase": "PREDICT",
            "history": ["CONTEXTUALIZE", "PREDICT"],
        }
        (run_dir / "state.json").write_text(json.dumps(state))
        inv.write_text("## CONTEXTUALIZE\n\n## PREDICT (loop 1)\n\nhypotheses\n")

        hook = _edit_hook_data(
            inv,
            old_string="hypotheses",
            new_string="hypotheses\n\n## ANALYZE (loop 1)\n\nanalysis",
        )
        result = _run_pre_hook(hook, runs_dir=runs_dir)
        assert result.returncode == 2
        assert "PREDICT -> ANALYZE" in result.stderr

    def test_non_investigation_file_ignored(self, tmp_path):
        other = tmp_path / "report.md"
        result = _run_pre_hook(_write_hook_data(other, "## CONTEXTUALIZE\n"))
        assert result.returncode == 0

    def test_edit_old_string_absent_passes(self, tmp_path):
        """If old_string isn't in the file the Edit will fail anyway — pre hook exits 0."""
        run_dir, inv, runs_dir = self._setup_run(tmp_path)
        inv.write_text("## CONTEXTUALIZE\n\nsome content\n")
        hook = _edit_hook_data(inv, old_string="not present", new_string="## GATHER\n")
        result = _run_pre_hook(hook, runs_dir=runs_dir)
        assert result.returncode == 0
