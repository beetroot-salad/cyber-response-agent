"""Tests for the lint_scrub_order gate: the lifecycle scrubs before any reader of the run folder, no
handler swallows the taint signal, and the bash tool has no in-process fallback."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_scrub_order")

# #1342 M3: `main` and `job_main` are compositions; each calls the lifecycle, then the shared
# post-steps phase, which alone holds the readers of the scrubbed folder. The ticket comment and
# the curation enqueue stay in the operator composition, after the lifecycle.
_MAIN = (
    "def main():\n"
    "    summary = lifecycle()\n"
    "    _post_steps(summary)\n"
    "    ticket_writer.record_case_ticket()\n"
    "    enqueue_curation()\n"
    "def job_main():\n"
    "    summary = lifecycle()\n"
    "    _post_steps(summary)\n"
    "def _post_steps(summary):\n"
    "    run_dir.iterdir()\n"
    "    _run.cross_check_tables(run_dir)\n"
    "    visualize()\n"
    "def _run_investigation_lifecycle():\n"
    "    try:\n"
    "        pass\n"
    "    except ValueError:\n"
    "        pass\n")
_BASH = "def _tool_bash():\n    return runner.run_parsed(cmd)\n"


def _tree(tmp_path: Path, run: str = _MAIN, bash: str = _BASH) -> Path:
    root = tmp_path / "defender"
    (root / "investigation/tools").mkdir(parents=True)
    (root / "run.py").write_text(run, encoding="utf-8")
    (root / "investigation/tools/_bash.py").write_text(bash, encoding="utf-8")
    return root


def test_a_clean_tree_has_no_findings(tmp_path):
    assert _GATE.scan(_tree(tmp_path)) == []


@pytest.mark.parametrize("composition", ["main", "job_main"])
def test_the_post_steps_before_the_lifecycle_is_found(tmp_path, composition):
    head = f"def {composition}():\n    summary = lifecycle()\n    _post_steps(summary)\n"
    swapped = f"def {composition}():\n    _post_steps(None)\n    summary = lifecycle()\n"
    found = _GATE.scan(_tree(tmp_path, run=_MAIN.replace(head, swapped)))
    assert len(found) == 1, found
    assert composition in found[0], found
    assert "_post_steps" in found[0], found


@pytest.mark.parametrize("composition", ["main", "job_main"])
@pytest.mark.parametrize("reader", ["run_dir.iterdir()", "_run.cross_check_tables(run_dir)", "visualize()"])
def test_a_reader_called_from_a_composition_instead_of_the_post_steps_is_found(tmp_path, composition, reader):
    marker = f"def {composition}():\n    summary = lifecycle()\n"
    run = _MAIN.replace(marker, marker + f"    {reader}\n")
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1, found
    assert composition in found[0], found


def test_a_reader_before_the_lifecycle_is_found(tmp_path):
    run = _MAIN.replace("def main():\n    summary = lifecycle()", "def main():\n    enqueue_curation()\n    summary = lifecycle()")
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1, found
    assert "enqueue_curation" in found[0], found


@pytest.mark.parametrize("name", ["lifecycle", "_post_steps"])
def test_a_vanished_call_in_job_main_is_a_finding_not_a_pass(tmp_path, name):
    body = "def job_main():\n    summary = lifecycle()\n    _post_steps(summary)\n"
    run = _MAIN.replace(body, body.replace(name + "(", "other("))
    assert any("job_main" in f and name in f for f in _GATE.scan(_tree(tmp_path, run=run)))


def test_a_missing_job_main_or_post_steps_is_a_finding(tmp_path):
    without_job = _MAIN.replace("def job_main():\n    summary = lifecycle()\n    _post_steps(summary)\n", "")
    without_steps = _MAIN.replace("def _post_steps(summary):", "def _renamed(summary):")
    assert any("job_main" in f for f in _GATE.scan(_tree(tmp_path / "a", run=without_job)))
    assert any("_post_steps" in f for f in _GATE.scan(_tree(tmp_path / "b", run=without_steps)))


@pytest.mark.parametrize("function", ["main", "job_main", "_post_steps", "_run_investigation_lifecycle"])
@pytest.mark.parametrize("handler", ["RunTainted", "Exception", "BaseException",
                                     "(OSError, Exception)", "errors.RunTainted"])
def test_a_handler_that_swallows_the_taint_is_found(tmp_path, function, handler):
    guarded = f"    try:\n        pass\n    except {handler}:\n        pass\n"
    run = _plant_handler(function, guarded)
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1, found
    assert "swallow" in found[0], found
    assert function in found[0], found


@pytest.mark.parametrize("function", ["main", "job_main", "_post_steps"])
def test_a_bare_except_is_found(tmp_path, function):
    run = _plant_handler(function, "    try:\n        pass\n    except:\n        pass\n")
    found = _GATE.scan(_tree(tmp_path, run=run))
    assert len(found) == 1, found
    assert "bare" in found[0], found


@pytest.mark.parametrize("function", ["main", "job_main", "_post_steps"])
def test_a_handler_for_an_unrelated_error_is_not_a_finding(tmp_path, function):
    run = _plant_handler(function, "    try:\n        pass\n    except ValueError:\n        pass\n")
    assert _GATE.scan(_tree(tmp_path, run=run)) == []


def _plant_handler(function: str, block: str) -> str:
    """`_MAIN` with `block` added at the end of `function`'s body."""
    if function == "_run_investigation_lifecycle":
        return _MAIN.replace("    try:\n        pass\n    except ValueError:\n        pass\n", block)
    marker = {"main": "    enqueue_curation()\n", "job_main": "def job_main():\n    summary = lifecycle()\n    _post_steps(summary)\n",
              "_post_steps": "    visualize()\n"}[function]
    return _MAIN.replace(marker, marker + block, 1)


def test_the_bash_tool_calling_the_in_process_executor_is_found(tmp_path):
    bash = "def _tool_bash():\n    return bash_exec.run_parsed(cmd)\n"
    found = _GATE.scan(_tree(tmp_path, bash=bash))
    assert len(found) == 1, found
    assert "in-process" in found[0], found


def test_a_missing_function_is_a_finding(tmp_path):
    found = _GATE.scan(_tree(tmp_path, bash="x = 1\n"))
    assert any("_tool_bash" in f for f in found), found


def test_a_file_that_does_not_parse_is_exit_2(tmp_path):
    assert _GATE.main(["--root", str(_tree(tmp_path, run="def (:\n"))]) == 2
