"""Tests for the lint_scrub_order gate: the lifecycle scrubs before any reader of the run folder, no
handler swallows the taint signal, and the bash tool has no in-process fallback."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_scrub_order")

_MAIN = (
    "def main():\n"
    "    summary = lifecycle()\n"
    "    run_dir.iterdir()\n"
    "    _run.cross_check_tables(run_dir)\n"
    "    ticket_writer.record_case_ticket()\n"
    "    enqueue_curation()\n"
    "    visualize()\n"
    "def _run_investigation_lifecycle():\n"
    "    try:\n"
    "        pass\n"
    "    except ValueError:\n"
    "        pass\n")
_BASH = "def _tool_bash():\n    return runner.run_parsed(cmd)\n"


def _tree(tmp_path: Path, run: str = _MAIN, bash: str = _BASH) -> Path:
    root = tmp_path / "defender"
    (root / "runtime/tools").mkdir(parents=True)
    (root / "run.py").write_text(run, encoding="utf-8")
    (root / "runtime/tools/_bash.py").write_text(bash, encoding="utf-8")
    return root


def test_a_clean_tree_has_no_findings(tmp_path):
    assert _GATE.scan(_tree(tmp_path)) == []


def test_a_reader_before_the_lifecycle_is_found(tmp_path):
    run = _MAIN.replace("    summary = lifecycle()\n", "    visualize()\n    summary = lifecycle()\n")
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1 and "visualize" in found[0], found


@pytest.mark.parametrize("name", ["lifecycle", "enqueue_curation"])
def test_a_vanished_call_is_a_finding_not_a_pass(tmp_path, name):
    run = _MAIN.replace(name + "()", "other()")
    assert any(name in f for f in _GATE.scan(_tree(tmp_path, run=run)))


@pytest.mark.parametrize("handler", ["RunTainted", "Exception", "BaseException",
                                     "(OSError, Exception)", "errors.RunTainted"])
def test_a_handler_that_swallows_the_taint_is_found(tmp_path, handler):
    run = _MAIN.replace("except ValueError", f"except {handler}")
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1 and "swallow" in found[0], found


def test_a_bare_except_is_found(tmp_path):
    found = _GATE.scan(_tree(tmp_path, run=_MAIN.replace("except ValueError", "except")))
    assert len(found) == 1 and "bare" in found[0], found


def test_the_bash_tool_calling_the_in_process_executor_is_found(tmp_path):
    bash = "def _tool_bash():\n    return bash_exec.run_parsed(cmd)\n"
    found = _GATE.scan(_tree(tmp_path, bash=bash))
    assert len(found) == 1 and "in-process" in found[0], found


def test_a_missing_function_is_a_finding(tmp_path):
    found = _GATE.scan(_tree(tmp_path, bash="x = 1\n"))
    assert any("_tool_bash" in f for f in found), found


def test_a_file_that_does_not_parse_is_exit_2(tmp_path):
    assert _GATE.main(["--root", str(_tree(tmp_path, run="def (:\n"))]) == 2
