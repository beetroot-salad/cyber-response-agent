"""Tests for budget enforcement hook.

Tests the budget_enforcer.py PostToolUse hook and schemas/budget.py.

The hook entry point (`main`) accepts stdin / runs_dir / soc_agent_root as
parameters, so tests pass them directly instead of patching globals.
"""

import json
import subprocess
import sys
import time
from datetime import datetime, timedelta, UTC
from io import StringIO
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.budget_enforcer import (
    check_budgets,
    load_limits,
    load_or_create_budget,
    main as budget_main,
    parse_yaml_config,
    resolve_run_dir,
    update_budget_locked,
)
from schemas.budget import DEFAULT_LIMITS, make_budget_state


# ---------------------------------------------------------------------------
# schemas/budget.py
# ---------------------------------------------------------------------------


class TestMakeBudgetState:
    def test_creates_state_with_defaults(self):
        state = make_budget_state("run-abc")
        assert state["run_id"] == "run-abc"
        assert state["tool_calls"] == 0
        assert state["subagent_spawns"] == 0
        assert "started_at" in state

    def test_started_at_is_iso_utc(self):
        state = make_budget_state("run-abc")
        dt = datetime.fromisoformat(state["started_at"])
        assert dt.tzinfo is not None


class TestDefaultLimits:
    def test_has_all_keys(self):
        assert "max_tool_calls" in DEFAULT_LIMITS
        assert "max_subagent_spawns" in DEFAULT_LIMITS
        assert "wall_clock_timeout" in DEFAULT_LIMITS

    def test_values_are_positive_ints(self):
        for key, value in DEFAULT_LIMITS.items():
            assert isinstance(value, int)
            assert value > 0


# ---------------------------------------------------------------------------
# parse_yaml_config
# ---------------------------------------------------------------------------


class TestParseYamlConfig:
    def test_reads_flat_yaml(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("max_tool_calls: 200\nwall_clock_timeout: 900\n")
        result = parse_yaml_config(cfg)
        assert result["max_tool_calls"] == 200
        assert result["wall_clock_timeout"] == 900

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_yaml_config(tmp_path / "nope.yaml") == {}

    def test_handles_comments(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("# a comment\nmax_tool_calls: 100\n")
        result = parse_yaml_config(cfg)
        assert result["max_tool_calls"] == 100

    def test_nested_budget_section(self, tmp_path):
        cfg = tmp_path / "permissions.yaml"
        cfg.write_text("mode: recommend\nbudget:\n  max_tool_calls: 75\n  max_subagent_spawns: 3\n")
        result = parse_yaml_config(cfg)
        assert result["budget"]["max_tool_calls"] == 75
        assert result["budget"]["max_subagent_spawns"] == 3


# ---------------------------------------------------------------------------
# resolve_run_dir
# ---------------------------------------------------------------------------


def _make_run(runs_dir, run_id, signature_id="sig-1", phase=None):
    """Helper: create a run dir with meta.json and optional state.json."""
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "meta.json").write_text(
        json.dumps({"run_id": run_id, "signature_id": signature_id})
    )
    if phase:
        (run_dir / "state.json").write_text(
            json.dumps({"run_id": run_id, "phase": phase})
        )
    return run_dir


class TestResolveRunDir:
    def test_no_runs_returns_none(self, tmp_path):
        run_dir, sig = resolve_run_dir("sess-1", tmp_path)
        assert run_dir is None
        assert sig == ""

    def test_first_call_creates_mapping(self, tmp_path):
        _make_run(tmp_path, "run-abc", "wazuh-rule-5710")
        run_dir, sig = resolve_run_dir("sess-1", tmp_path)
        assert run_dir == tmp_path / "run-abc"
        assert sig == "wazuh-rule-5710"
        # Mapping file should exist now.
        mapping = tmp_path / ".sessions" / "sess-1.json"
        assert mapping.exists()

    def test_subsequent_call_uses_mapping(self, tmp_path):
        _make_run(tmp_path, "run-abc", "wazuh-rule-5710")
        resolve_run_dir("sess-1", tmp_path)
        # Second call should use cached mapping.
        run_dir, sig = resolve_run_dir("sess-1", tmp_path)
        assert run_dir == tmp_path / "run-abc"

    def test_concluded_run_ignored(self, tmp_path):
        _make_run(tmp_path, "run-done", phase="REPORT")
        run_dir, _ = resolve_run_dir("sess-1", tmp_path)
        assert run_dir is None

    def test_active_run_without_state_is_found(self, tmp_path):
        """A run with meta.json but no state.json is active (just created)."""
        _make_run(tmp_path, "run-new")
        run_dir, _ = resolve_run_dir("sess-1", tmp_path)
        assert run_dir == tmp_path / "run-new"

    def test_skips_dirs_without_meta(self, tmp_path):
        (tmp_path / "random-dir").mkdir()
        run_dir, _ = resolve_run_dir("sess-1", tmp_path)
        assert run_dir is None

    def test_concurrent_sessions_map_correctly(self, tmp_path):
        run_a = _make_run(tmp_path, "run-a", "sig-a")
        time.sleep(0.05)
        run_b = _make_run(tmp_path, "run-b", "sig-b")

        # Session 1 maps to the most recent unmapped run (run-b).
        dir_1, sig_1 = resolve_run_dir("sess-1", tmp_path)
        assert dir_1 == run_b
        assert sig_1 == "sig-b"

        # Session 2 maps to the remaining unmapped run (run-a).
        dir_2, sig_2 = resolve_run_dir("sess-2", tmp_path)
        assert dir_2 == run_a
        assert sig_2 == "sig-a"

    def test_already_mapped_run_not_reused(self, tmp_path):
        """If the only active run is already mapped to another session, return None."""
        _make_run(tmp_path, "run-abc")
        resolve_run_dir("sess-1", tmp_path)
        # sess-2 should find nothing — run-abc is already mapped.
        run_dir, _ = resolve_run_dir("sess-2", tmp_path)
        assert run_dir is None


# ---------------------------------------------------------------------------
# load_limits
# ---------------------------------------------------------------------------


class TestLoadLimits:
    def test_defaults_when_no_config(self, tmp_path):
        limits = load_limits("", soc_agent_root=tmp_path)
        assert limits == DEFAULT_LIMITS

    def test_defaults_yaml_overrides(self, tmp_path):
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "budget-defaults.yaml").write_text(
            "max_tool_calls: 200\n"
        )
        limits = load_limits("", soc_agent_root=tmp_path)
        assert limits["max_tool_calls"] == 200
        assert limits["max_subagent_spawns"] == DEFAULT_LIMITS["max_subagent_spawns"]

    def test_signature_overrides(self, tmp_path):
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "budget-defaults.yaml").write_text(
            "max_tool_calls: 200\nmax_subagent_spawns: 10\nwall_clock_timeout: 600\n"
        )
        sig_dir = tmp_path / "config" / "signatures" / "sig-1"
        sig_dir.mkdir(parents=True)
        (sig_dir / "permissions.yaml").write_text(
            "budget:\n  max_tool_calls: 75\n"
        )
        limits = load_limits("sig-1", soc_agent_root=tmp_path)
        assert limits["max_tool_calls"] == 75
        assert limits["max_subagent_spawns"] == 10


# ---------------------------------------------------------------------------
# check_budgets
# ---------------------------------------------------------------------------


class TestCheckBudgets:
    def _limits(self, **overrides):
        limits = dict(DEFAULT_LIMITS)
        limits.update(overrides)
        return limits

    def _budget(self, tool_calls=0, subagent_spawns=0, seconds_ago=0):
        started = datetime.now(UTC) - timedelta(seconds=seconds_ago)
        return {
            "run_id": "run-test",
            "tool_calls": tool_calls,
            "subagent_spawns": subagent_spawns,
            "started_at": started.isoformat(),
        }

    def test_within_budget_no_warnings(self):
        warnings = check_budgets(self._budget(tool_calls=10), self._limits())
        assert warnings == []

    def test_tool_calls_warning_at_75_pct(self):
        # 75% of 100 = 75
        warnings = check_budgets(
            self._budget(tool_calls=76), self._limits(max_tool_calls=100)
        )
        assert any("tool_calls" in w and "warning" in w.lower() for w in warnings)

    def test_tool_calls_exceeded(self):
        warnings = check_budgets(
            self._budget(tool_calls=101), self._limits(max_tool_calls=100)
        )
        assert any("tool_calls" in w and "exceeded" in w.lower() for w in warnings)

    def test_subagent_warning(self):
        warnings = check_budgets(
            self._budget(subagent_spawns=8), self._limits(max_subagent_spawns=10)
        )
        assert any("subagent" in w for w in warnings)

    def test_subagent_exceeded(self):
        warnings = check_budgets(
            self._budget(subagent_spawns=11), self._limits(max_subagent_spawns=10)
        )
        assert any("subagent" in w and "exceeded" in w.lower() for w in warnings)

    def test_wall_clock_warning(self):
        warnings = check_budgets(
            self._budget(seconds_ago=460), self._limits(wall_clock_timeout=600)
        )
        assert any("wall_clock" in w and "warning" in w.lower() for w in warnings)

    def test_wall_clock_exceeded(self):
        warnings = check_budgets(
            self._budget(seconds_ago=601), self._limits(wall_clock_timeout=600)
        )
        assert any("wall_clock" in w and "exceeded" in w.lower() for w in warnings)

    def test_multiple_exceeded_returns_multiple_warnings(self):
        warnings = check_budgets(
            self._budget(tool_calls=200, subagent_spawns=20, seconds_ago=700),
            self._limits(max_tool_calls=100, max_subagent_spawns=10, wall_clock_timeout=600),
        )
        assert len(warnings) == 3

    def test_exactly_at_threshold_triggers_warning(self):
        # 75% of 100 = exactly 75
        warnings = check_budgets(
            self._budget(tool_calls=75), self._limits(max_tool_calls=100)
        )
        assert any("tool_calls" in w for w in warnings)

    def test_exceeded_beats_warning(self):
        """At 100%, should say 'exceeded' not 'warning'."""
        warnings = check_budgets(
            self._budget(tool_calls=100), self._limits(max_tool_calls=100)
        )
        assert any("exceeded" in w.lower() for w in warnings)
        assert not any("warning" in w.lower() and "tool_calls" in w for w in warnings)


# ---------------------------------------------------------------------------
# load_or_create_budget
# ---------------------------------------------------------------------------


class TestLoadOrCreateBudget:
    def test_creates_fresh_when_missing(self, tmp_path):
        budget = load_or_create_budget(tmp_path, "run-new")
        assert budget["run_id"] == "run-new"
        assert budget["tool_calls"] == 0

    def test_reads_existing(self, tmp_path):
        (tmp_path / "budget.json").write_text(
            json.dumps({"run_id": "run-x", "tool_calls": 42, "subagent_spawns": 3,
                         "started_at": "2026-01-01T00:00:00+00:00"})
        )
        budget = load_or_create_budget(tmp_path, "run-x")
        assert budget["tool_calls"] == 42

    def test_falls_back_on_corrupt_file(self, tmp_path):
        (tmp_path / "budget.json").write_text("not json")
        budget = load_or_create_budget(tmp_path, "run-x")
        assert budget["tool_calls"] == 0


# ---------------------------------------------------------------------------
# update_budget_locked
# ---------------------------------------------------------------------------


class TestUpdateBudgetLocked:
    def test_creates_file_when_missing(self, tmp_path):
        budget = update_budget_locked(tmp_path, "run-1", "Bash")
        assert budget["tool_calls"] == 1
        assert budget["subagent_spawns"] == 0
        assert (tmp_path / "budget.json").exists()

    def test_increments_existing(self, tmp_path):
        (tmp_path / "budget.json").write_text(json.dumps(
            make_budget_state("run-1") | {"tool_calls": 5}
        ))
        budget = update_budget_locked(tmp_path, "run-1", "Bash")
        assert budget["tool_calls"] == 6

    def test_agent_increments_both(self, tmp_path):
        budget = update_budget_locked(tmp_path, "run-1", "Agent")
        assert budget["tool_calls"] == 1
        assert budget["subagent_spawns"] == 1

    def test_recovers_from_corrupt_file(self, tmp_path):
        (tmp_path / "budget.json").write_text("not json")
        budget = update_budget_locked(tmp_path, "run-1", "Bash")
        assert budget["tool_calls"] == 1

    def test_concurrent_increments(self, tmp_path):
        """Sequential calls accumulate correctly (serialized by lock)."""
        for _ in range(10):
            update_budget_locked(tmp_path, "run-1", "Bash")
        budget = json.loads((tmp_path / "budget.json").read_text())
        assert budget["tool_calls"] == 10


# ---------------------------------------------------------------------------
# Integration: main()
# ---------------------------------------------------------------------------


def _run_main(runs_dir, hook_input, soc_agent_root=None) -> int:
    """Invoke the hook entry point with a synthetic stdin and explicit runs dir."""
    return budget_main(
        stdin=StringIO(json.dumps(hook_input)),
        runs_dir=runs_dir,
        soc_agent_root=soc_agent_root,
    )


class TestBudgetEnforcerMain:
    def test_increments_tool_calls(self, tmp_path):
        _make_run(tmp_path, "run-1")
        hook_input = {"session_id": "sess-1", "tool_name": "Bash", "tool_input": {}}
        assert _run_main(tmp_path, hook_input) == 0
        budget = json.loads((tmp_path / "run-1" / "budget.json").read_text())
        assert budget["tool_calls"] == 1

    def test_agent_increments_both_counters(self, tmp_path):
        _make_run(tmp_path, "run-1")
        hook_input = {"session_id": "sess-1", "tool_name": "Agent", "tool_input": {}}
        assert _run_main(tmp_path, hook_input) == 0
        budget = json.loads((tmp_path / "run-1" / "budget.json").read_text())
        assert budget["tool_calls"] == 1
        assert budget["subagent_spawns"] == 1

    def test_accumulates_across_calls(self, tmp_path):
        _make_run(tmp_path, "run-1")
        for _ in range(5):
            hook_input = {"session_id": "sess-1", "tool_name": "Bash", "tool_input": {}}
            assert _run_main(tmp_path, hook_input) == 0
        budget = json.loads((tmp_path / "run-1" / "budget.json").read_text())
        assert budget["tool_calls"] == 5

    def test_always_exits_zero(self, tmp_path):
        _make_run(tmp_path, "run-1")
        # Pre-seed budget near limit.
        (tmp_path / "run-1" / "budget.json").write_text(json.dumps({
            "run_id": "run-1", "tool_calls": 999, "subagent_spawns": 999,
            "started_at": "2020-01-01T00:00:00+00:00",
        }))
        hook_input = {"session_id": "sess-1", "tool_name": "Bash", "tool_input": {}}
        assert _run_main(tmp_path, hook_input) == 0

    def test_prints_warning_at_threshold(self, tmp_path, capsys):
        # Use a small limit so we can trigger warning easily.
        soc_root = tmp_path / "soc"
        soc_root.mkdir()
        (soc_root / "config").mkdir()
        (soc_root / "config" / "budget-defaults.yaml").write_text(
            "max_tool_calls: 10\nmax_subagent_spawns: 10\nwall_clock_timeout: 6000\n"
        )

        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        run_dir = _make_run(runs_dir, "run-1")
        # Pre-seed at 7/10 (below 75%) then increment to 8 (80% -> warning).
        (run_dir / "budget.json").write_text(json.dumps(
            make_budget_state("run-1") | {"tool_calls": 7}
        ))

        hook_input = {"session_id": "sess-1", "tool_name": "Bash", "tool_input": {}}
        _run_main(runs_dir, hook_input, soc_agent_root=soc_root)

        captured = capsys.readouterr()
        assert "tool_calls" in captured.err
        assert "8/10" in captured.err

    def test_no_active_run_exits_zero(self, tmp_path):
        hook_input = {"session_id": "sess-1", "tool_name": "Bash", "tool_input": {}}
        assert _run_main(tmp_path, hook_input) == 0

    def test_no_session_id_exits_zero(self, tmp_path):
        hook_input = {"tool_name": "Bash", "tool_input": {}}
        assert _run_main(tmp_path, hook_input) == 0

    def test_malformed_stdin_exits_zero(self, tmp_path):
        assert budget_main(
            stdin=StringIO("not json"),
            runs_dir=tmp_path,
        ) == 0


# ---------------------------------------------------------------------------
# Script-level integration (subprocess)
# ---------------------------------------------------------------------------


class TestBudgetEnforcerScript:
    SCRIPT = SOC_AGENT_ROOT / "hooks" / "scripts" / "budget_enforcer.py"

    def test_runs_and_exits_zero(self, tmp_path):
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        _make_run(runs_dir, "run-1")

        hook_input = json.dumps({
            "session_id": "sess-script-1",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        })

        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            input=hook_input,
            capture_output=True,
            text=True,
            env={**dict(__import__("os").environ), "SOC_AGENT_RUNS_DIR": str(runs_dir)},
        )
        assert result.returncode == 0

        budget = json.loads((runs_dir / "run-1" / "budget.json").read_text())
        assert budget["tool_calls"] == 1

    def test_invalid_input_exits_zero(self):
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            input="garbage",
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0


# pytest stays referenced for the SystemExit-based tests above (none anymore,
# but pytest fixtures still in use).
_ = pytest
