"""Tests for run.py's settings file substitution + hook registration shape."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


RUN_PATH = Path(__file__).resolve().parents[1] / "run.py"


def _load():
    spec = importlib.util.spec_from_file_location("run", RUN_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def run_mod():
    return _load()


def test_build_settings_file_substitutes_placeholders(run_mod):
    path = run_mod.build_settings_file()
    try:
        text = path.read_text()
        assert "${DEFENDER_DIR}" not in text
        assert "${PYTHON}" not in text
        data = json.loads(text)
        # The hook command must be a runnable string referencing both
        # the venv python and the absolute hook script path.
        cmd = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert sys.executable in cmd
        assert "record_lead.py" in cmd
        # Matcher must cover both Task and Agent — Claude Code dispatches
        # subagents under either name and the regex needs alternation.
        matcher = data["hooks"]["PreToolUse"][0]["matcher"]
        assert "Agent" in matcher
        assert "Task" in matcher
    finally:
        path.unlink()
