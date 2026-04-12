"""Tests for hook-inferred state transitions via investigation.md headers.

Tests the infer_state.py hook: phase extraction from investigation.md,
state inference, transition validation, and integration via subprocess
(simulating PostToolUse events piped to stdin).
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import MAX_LOOPS

HOOK_SCRIPT = SOC_AGENT_ROOT / "hooks" / "scripts" / "infer_state.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_meta(run_dir: Path, run_id: str = "run-test", signature_id: str = "wazuh-rule-5710"):
    """Create a meta.json in run_dir (mirrors setup_run.py output)."""
    meta = {"run_id": run_id, "signature_id": signature_id, "salt": "deadbeef"}
    (run_dir / "meta.json").write_text(json.dumps(meta))


def make_hook_event(file_path: str, content: str = "", tool_name: str = "Write") -> str:
    """Create a PostToolUse JSON event for Write/Edit to a file."""
    event = {
        "tool_name": tool_name,
        "tool_input": {"file_path": file_path, "content": content},
        "tool_use_id": "test-001",
        "session_id": "session-001",
    }
    return json.dumps(event)


def run_hook(hook_event: str, runs_dir: Path) -> subprocess.CompletedProcess:
    """Run infer_state.py with the given hook event on stdin."""
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=hook_event,
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "SOC_AGENT_RUNS_DIR": str(runs_dir)},
    )


def write_investigation(run_dir: Path, content: str, runs_dir: Path) -> subprocess.CompletedProcess:
    """Write investigation.md and run the hook against it."""
    inv_path = run_dir / "investigation.md"
    inv_path.write_text(content)
    event = make_hook_event(str(inv_path))
    return run_hook(event, runs_dir)


def load_state(run_dir: Path) -> dict:
    """Load and return state.json from run_dir."""
    return json.loads((run_dir / "state.json").read_text())


# ---------------------------------------------------------------------------
# Unit tests: extract_phases
# ---------------------------------------------------------------------------

from hooks.scripts.infer_state import extract_phases


class TestExtractPhases:
    def test_single_contextualize(self, tmp_path):
        f = tmp_path / "investigation.md"
        f.write_text("## CONTEXTUALIZE\n\n**Alert:** SEC-001\n")
        assert extract_phases(f) == ["CONTEXTUALIZE"]

    def test_full_sequence(self, tmp_path):
        f = tmp_path / "investigation.md"
        f.write_text(
            "## CONTEXTUALIZE\nstuff\n"
            "## HYPOTHESIZE (loop 1)\nstuff\n"
            "## GATHER (loop 1)\nstuff\n"
            "## ANALYZE (loop 1)\nstuff\n"
            "## CONCLUDE\nverdicts\n"
        )
        assert extract_phases(f) == [
            "CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"
        ]

    def test_loop_suffixes_stripped(self, tmp_path):
        f = tmp_path / "investigation.md"
        f.write_text(
            "## CONTEXTUALIZE\n"
            "## HYPOTHESIZE (loop 1)\n"
            "## GATHER (loop 1)\n"
            "## ANALYZE (loop 1)\n"
            "## HYPOTHESIZE (loop 2)\n"
            "## GATHER (loop 2)\n"
            "## ANALYZE (loop 2)\n"
        )
        assert extract_phases(f) == [
            "CONTEXTUALIZE",
            "HYPOTHESIZE", "GATHER", "ANALYZE",
            "HYPOTHESIZE", "GATHER", "ANALYZE",
        ]

    def test_ignores_non_phase_headers(self, tmp_path):
        f = tmp_path / "investigation.md"
        f.write_text(
            "## CONTEXTUALIZE\n"
            "## Key Evidence\n"
            "## Summary\n"
            "## HYPOTHESIZE (loop 1)\n"
        )
        assert extract_phases(f) == ["CONTEXTUALIZE", "HYPOTHESIZE"]

    def test_empty_file(self, tmp_path):
        f = tmp_path / "investigation.md"
        f.write_text("")
        assert extract_phases(f) == []

    def test_nonexistent_file(self, tmp_path):
        f = tmp_path / "investigation.md"
        assert extract_phases(f) == []

    def test_screen_phase(self, tmp_path):
        f = tmp_path / "investigation.md"
        f.write_text("## CONTEXTUALIZE\n\n## SCREEN\n\n## CONCLUDE\n")
        assert extract_phases(f) == ["CONTEXTUALIZE", "SCREEN", "CONCLUDE"]


# ---------------------------------------------------------------------------
# Integration tests: hook via subprocess
# ---------------------------------------------------------------------------


class TestInferStateHook:
    def test_creates_state_from_contextualize(self, tmp_path):
        """First write with ## CONTEXTUALIZE creates state.json."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        result = write_investigation(run_dir, "## CONTEXTUALIZE\n\n**Alert:** SEC-001\n", runs_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"

        state = load_state(run_dir)
        assert state["phase"] == "CONTEXTUALIZE"
        assert state["history"] == ["CONTEXTUALIZE"]
        assert state["signature_id"] == "wazuh-rule-5710"
        assert state["run_id"] == "run-test"

    def test_valid_transition_hypothesize(self, tmp_path):
        """CONTEXTUALIZE -> HYPOTHESIZE is valid."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        # First: CONTEXTUALIZE
        write_investigation(run_dir, "## CONTEXTUALIZE\nstuff\n", runs_dir)

        # Then: append HYPOTHESIZE
        result = write_investigation(
            run_dir,
            "## CONTEXTUALIZE\nstuff\n## HYPOTHESIZE (loop 1)\npredictions\n",
            runs_dir,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"

        state = load_state(run_dir)
        assert state["phase"] == "HYPOTHESIZE"
        assert state["history"] == ["CONTEXTUALIZE", "HYPOTHESIZE"]

    def test_illegal_transition_rejected(self, tmp_path):
        """CONTEXTUALIZE -> GATHER (skipping HYPOTHESIZE) is rejected."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        # First: CONTEXTUALIZE
        write_investigation(run_dir, "## CONTEXTUALIZE\nstuff\n", runs_dir)

        # Then: skip to GATHER (illegal)
        result = write_investigation(
            run_dir,
            "## CONTEXTUALIZE\nstuff\n## GATHER (loop 1)\nquery\n",
            runs_dir,
        )
        assert result.returncode == 2
        assert "Illegal" in result.stderr or "illegal" in result.stderr

        # State should still be CONTEXTUALIZE
        state = load_state(run_dir)
        assert state["phase"] == "CONTEXTUALIZE"

    def test_full_investigation_sequence(self, tmp_path):
        """C -> H -> G -> A -> CONCLUDE through incremental writes."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        phases_content = [
            "## CONTEXTUALIZE\nstuff\n",
            "## CONTEXTUALIZE\nstuff\n## HYPOTHESIZE (loop 1)\nstuff\n",
            "## CONTEXTUALIZE\nstuff\n## HYPOTHESIZE (loop 1)\nstuff\n## GATHER (loop 1)\nstuff\n",
            "## CONTEXTUALIZE\nstuff\n## HYPOTHESIZE (loop 1)\nstuff\n## GATHER (loop 1)\nstuff\n## ANALYZE (loop 1)\nstuff\n",
            "## CONTEXTUALIZE\nstuff\n## HYPOTHESIZE (loop 1)\nstuff\n## GATHER (loop 1)\nstuff\n## ANALYZE (loop 1)\nstuff\n## CONCLUDE\nverdicts\n",
        ]
        expected_phases = ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]

        for i, content in enumerate(phases_content):
            result = write_investigation(run_dir, content, runs_dir)
            assert result.returncode == 0, f"Phase {expected_phases[i]} failed: {result.stderr}"

        state = load_state(run_dir)
        assert state["phase"] == "CONCLUDE"
        assert state["history"] == expected_phases

    def test_screen_resolve_sequence(self, tmp_path):
        """C -> SCREEN -> CONCLUDE is valid."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        writes = [
            "## CONTEXTUALIZE\nstuff\n",
            "## CONTEXTUALIZE\nstuff\n## SCREEN\nmatched\n",
            "## CONTEXTUALIZE\nstuff\n## SCREEN\nmatched\n## CONCLUDE\nverdicts\n",
        ]
        for content in writes:
            result = write_investigation(run_dir, content, runs_dir)
            assert result.returncode == 0, f"stderr: {result.stderr}"

        state = load_state(run_dir)
        assert state["phase"] == "CONCLUDE"
        assert state["history"] == ["CONTEXTUALIZE", "SCREEN", "CONCLUDE"]

    def test_screen_fallthrough_sequence(self, tmp_path):
        """C -> SCREEN -> H -> G -> A -> CONCLUDE is valid."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        phases = ["CONTEXTUALIZE", "SCREEN", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
        content = ""
        for phase in phases:
            suffix = " (loop 1)" if phase in ("HYPOTHESIZE", "GATHER", "ANALYZE") else ""
            content += f"## {phase}{suffix}\nstuff\n"
            result = write_investigation(run_dir, content, runs_dir)
            assert result.returncode == 0, f"Phase {phase} failed: {result.stderr}"

        state = load_state(run_dir)
        assert state["phase"] == "CONCLUDE"
        assert state["history"] == phases

    def test_ticket_context_fast_resolve(self, tmp_path):
        """C -> CONCLUDE (ticket-context fast-resolve) is valid."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        writes = [
            "## CONTEXTUALIZE\nstuff\n",
            "## CONTEXTUALIZE\nstuff\n## CONCLUDE\nverdicts\n",
        ]
        for content in writes:
            result = write_investigation(run_dir, content, runs_dir)
            assert result.returncode == 0, f"stderr: {result.stderr}"

        state = load_state(run_dir)
        assert state["phase"] == "CONCLUDE"
        assert state["history"] == ["CONTEXTUALIZE", "CONCLUDE"]

    def test_investigation_with_loop(self, tmp_path):
        """C -> H -> G -> A -> H -> G -> A -> CONCLUDE (one loop back)."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        phases = [
            "CONTEXTUALIZE",
            "HYPOTHESIZE", "GATHER", "ANALYZE",
            "HYPOTHESIZE", "GATHER", "ANALYZE",
            "CONCLUDE",
        ]
        content = ""
        loop = 0
        for phase in phases:
            if phase == "HYPOTHESIZE":
                loop += 1
            suffix = f" (loop {loop})" if phase in ("HYPOTHESIZE", "GATHER", "ANALYZE") else ""
            content += f"## {phase}{suffix}\nstuff\n"
            result = write_investigation(run_dir, content, runs_dir)
            assert result.returncode == 0, f"Phase {phase} failed: {result.stderr}"

        state = load_state(run_dir)
        assert state["phase"] == "CONCLUDE"
        assert state["history"] == phases

    def test_max_loops_enforced(self, tmp_path):
        """MAX_LOOPS+1 HYPOTHESIZE entries are rejected."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        content = "## CONTEXTUALIZE\nstuff\n"
        write_investigation(run_dir, content, runs_dir)

        # Run MAX_LOOPS full cycles
        for i in range(1, MAX_LOOPS + 1):
            for phase in ["HYPOTHESIZE", "GATHER", "ANALYZE"]:
                content += f"## {phase} (loop {i})\nstuff\n"
                result = write_investigation(run_dir, content, runs_dir)
                assert result.returncode == 0, f"Loop {i} {phase} failed: {result.stderr}"

        # The (MAX_LOOPS+1)th HYPOTHESIZE should be rejected
        content += f"## HYPOTHESIZE (loop {MAX_LOOPS + 1})\nstuff\n"
        result = write_investigation(run_dir, content, runs_dir)
        assert result.returncode == 2
        assert "Maximum" in result.stderr

    def test_noop_when_no_new_phases(self, tmp_path):
        """Editing investigation.md without adding a new phase is a no-op."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        # Write CONTEXTUALIZE
        content = "## CONTEXTUALIZE\nstuff\n"
        write_investigation(run_dir, content, runs_dir)

        state_before = load_state(run_dir)

        # Edit content within the same phase (no new header)
        content = "## CONTEXTUALIZE\nstuff\nmore stuff added\n"
        result = write_investigation(run_dir, content, runs_dir)
        assert result.returncode == 0

        state_after = load_state(run_dir)
        assert state_after["phase"] == state_before["phase"]
        assert state_after["history"] == state_before["history"]

    def test_noop_for_non_investigation_file(self, tmp_path):
        """Hook ignores writes to files that aren't investigation.md."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)

        event = make_hook_event(str(run_dir / "report.md"), "## CONTEXTUALIZE\n")
        result = run_hook(event, runs_dir)
        assert result.returncode == 0
        assert not (run_dir / "state.json").exists()

    def test_noop_for_file_outside_runs(self, tmp_path):
        """Hook ignores investigation.md writes outside the runs directory."""
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        other_dir = tmp_path / "other"
        other_dir.mkdir()

        inv_path = other_dir / "investigation.md"
        inv_path.write_text("## CONTEXTUALIZE\n")

        event = make_hook_event(str(inv_path))
        result = run_hook(event, runs_dir)
        assert result.returncode == 0
        assert not (other_dir / "state.json").exists()

    def test_history_mismatch_rejected(self, tmp_path):
        """Reordering phase sections is rejected."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        # Write C -> H
        content = "## CONTEXTUALIZE\nstuff\n## HYPOTHESIZE (loop 1)\nstuff\n"
        write_investigation(run_dir, content, runs_dir)

        # Now rewrite with sections reordered (H before C)
        bad_content = "## HYPOTHESIZE (loop 1)\nstuff\n## CONTEXTUALIZE\nstuff\n"
        result = write_investigation(run_dir, bad_content, runs_dir)
        assert result.returncode == 2
        assert "mismatch" in result.stderr

    def test_conclude_is_terminal(self, tmp_path):
        """Cannot add phases after CONCLUDE."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        content = "## CONTEXTUALIZE\nstuff\n## CONCLUDE\nverdicts\n"
        write_investigation(run_dir, content, runs_dir)

        # Try to add HYPOTHESIZE after CONCLUDE
        content += "## HYPOTHESIZE (loop 1)\nstuff\n"
        result = write_investigation(run_dir, content, runs_dir)
        assert result.returncode == 2

    def test_bootstraps_from_meta_json(self, tmp_path):
        """State is bootstrapped from meta.json when state.json doesn't exist."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir, run_id="run-abc-123", signature_id="wazuh-rule-9999")

        write_investigation(run_dir, "## CONTEXTUALIZE\nstuff\n", runs_dir)

        state = load_state(run_dir)
        assert state["run_id"] == "run-abc-123"
        assert state["signature_id"] == "wazuh-rule-9999"

    def test_feedback_includes_loop_count(self, tmp_path):
        """Hook stdout includes loop count feedback."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        content = "## CONTEXTUALIZE\nstuff\n"
        write_investigation(run_dir, content, runs_dir)

        content += "## HYPOTHESIZE (loop 1)\nstuff\n"
        result = write_investigation(run_dir, content, runs_dir)
        assert "loop" in result.stdout.lower()
        assert result.returncode == 0

    def test_initial_phase_must_be_contextualize(self, tmp_path):
        """First phase must be CONTEXTUALIZE."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        result = write_investigation(run_dir, "## HYPOTHESIZE (loop 1)\nstuff\n", runs_dir)
        assert result.returncode == 2
        assert not (run_dir / "state.json").exists()

    def test_multiple_transitions_single_write(self, tmp_path):
        """Multiple new phases in a single write are all validated."""
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "run-test"
        run_dir.mkdir(parents=True)
        write_meta(run_dir)

        # Write C, H, G all at once
        content = (
            "## CONTEXTUALIZE\nstuff\n"
            "## HYPOTHESIZE (loop 1)\nstuff\n"
            "## GATHER (loop 1)\nstuff\n"
        )
        result = write_investigation(run_dir, content, runs_dir)
        assert result.returncode == 0

        state = load_state(run_dir)
        assert state["phase"] == "GATHER"
        assert state["history"] == ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER"]
