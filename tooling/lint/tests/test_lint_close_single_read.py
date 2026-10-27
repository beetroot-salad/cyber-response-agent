"""Tests for the lint_close_single_read gate: the close reads and parses the companion once, the
challenge gate reads nothing, and the one parse is guarded."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_close_single_read")

_CLOSE = (
    "from pydantic_ai.exceptions import ModelRetry\n"
    "async def _close_investigation_async(deps):\n"
    "    read = tools_mod.read_companion(deps)\n"
    "    return read\n"
    "def _refuse_if_entry_price_is_owed(text):\n"
    "    try:\n"
    "        companion, _w = parse_dense_companion(text)\n"
    "    except ModelRetry:\n"
    "        raise\n"
    "    except ValueError as exc:\n"
    "        raise ModelRetry('bad') from exc\n")
_GATE_SRC = "def check(document):\n    return document.rows\n"


def _tree(tmp_path: Path, close: str = _CLOSE, gate: str = _GATE_SRC) -> Path:
    root = tmp_path / "defender"
    (root / "runtime").mkdir(parents=True)
    (root / "investigation/close_tool.py").write_text(close, encoding="utf-8")
    (root / "investigation/challenge_gate.py").write_text(gate, encoding="utf-8")
    return root


def test_a_clean_tree_has_no_findings(tmp_path):
    assert _GATE.scan(_tree(tmp_path)) == []


def test_a_second_parse_is_found(tmp_path):
    close = _CLOSE + "def other(t):\n    return parse_dense_companion(t)\n"
    found = _GATE.scan(_tree(tmp_path, close=close))
    assert len(found) == 1 and "2 `parse_dense_companion(`" in found[0], found


def test_a_second_read_is_found(tmp_path):
    close = _CLOSE + "def other(d):\n    return tools_mod.read_companion(d)\n"
    assert any("read_companion" in f for f in _GATE.scan(_tree(tmp_path, close=close)))


@pytest.mark.parametrize("read", ["path.read_text()", "path.read_bytes()"])
def test_the_close_taking_its_own_read_is_found(tmp_path, read):
    close = _CLOSE.replace("    return read\n", f"    {read}\n    return read\n")
    found = _GATE.scan(_tree(tmp_path, close=close))
    assert len(found) == 1 and "its own" in found[0], found


@pytest.mark.parametrize("call", ["p.read_text()", "parse_dense_companion(t)",
                                  "parse_investigation(t)", "p.read_bytes()"])
def test_the_gate_reading_or_parsing_is_found(tmp_path, call):
    gate = f"def check(document, p, t):\n    return {call}\n"
    found = _GATE.scan(_tree(tmp_path, gate=gate))
    assert len(found) == 1 and "challenge_gate" in found[0], found


def test_a_parse_outside_the_guard_is_found(tmp_path):
    close = _CLOSE.replace("parse_dense_companion(text)", "text")
    close += "def elsewhere(t):\n    return parse_dense_companion(t)\n"
    assert any("not inside" in f for f in _GATE.scan(_tree(tmp_path, close=close)))


def test_a_bare_parse_is_found(tmp_path):
    close = _CLOSE.replace("    except ModelRetry:\n        raise\n", "").replace(
        "    except ValueError as exc:\n        raise ModelRetry('bad') from exc\n",
        "    except ValueError:\n        pass\n")
    assert any("bare again" in f for f in _GATE.scan(_tree(tmp_path, close=close)))


def test_a_missing_function_is_a_finding(tmp_path):
    close = _CLOSE.replace("_close_investigation_async", "renamed")
    assert any("_close_investigation_async" in f for f in _GATE.scan(_tree(tmp_path, close=close)))


def test_a_file_that_does_not_parse_is_exit_2(tmp_path):
    assert _GATE.main(["--root", str(_tree(tmp_path, gate="def (:\n"))]) == 2
