"""Tests for defender/hooks/budget_enforcer.py.

Warning-only PostToolUse hook: counts tool calls / subagent spawns per
run into ``{DEFENDER_RUN_DIR}/budget.json`` and prints stderr warnings
at 75% / 100%. Always exits 0.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "budget_enforcer.py"


def _load():
    spec = importlib.util.spec_from_file_location("budget_enforcer", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _run(mod, payload: dict, limits: dict | None = None) -> int:
    return mod.main(stdin=io.StringIO(json.dumps(payload)), limits=limits)


def test_noop_without_run_dir(monkeypatch):
    mod = _load()
    monkeypatch.delenv("DEFENDER_RUN_DIR", raising=False)
    rc = _run(mod, {"tool_name": "Bash"})
    assert rc == 0


def test_counts_tool_calls_and_spawns(monkeypatch, tmp_path):
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    _run(mod, {"tool_name": "Bash"})
    _run(mod, {"tool_name": "Task"})
    _run(mod, {"tool_name": "Read"})
    budget = json.loads((tmp_path / "budget.json").read_text())
    assert budget["tool_calls"] == 3
    assert budget["subagent_spawns"] == 1


def test_warns_when_over_cap(monkeypatch, tmp_path, capsys):
    mod = _load()
    limits = {
        "max_tool_calls": 2,
        "max_subagent_spawns": 40,
        "wall_clock_timeout": 1800,
    }
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    _run(mod, {"tool_name": "Bash"}, limits=limits)
    _run(mod, {"tool_name": "Bash"}, limits=limits)  # hits cap (2/2)
    err = capsys.readouterr().err
    assert "Budget exceeded: tool_calls at 2/2" in err


def test_always_exits_zero_on_bad_input(monkeypatch, tmp_path):
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    rc = mod.main(stdin=io.StringIO("not json"))
    assert rc == 0


def test_concurrent_increments_are_serialized(monkeypatch, tmp_path):
    # Two sequential invocations both land — the flock path round-trips
    # cleanly (a smoke check that the read-modify-write doesn't clobber).
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    for _ in range(5):
        _run(mod, {"tool_name": "Bash"})
    budget = json.loads((tmp_path / "budget.json").read_text())
    assert budget["tool_calls"] == 5
