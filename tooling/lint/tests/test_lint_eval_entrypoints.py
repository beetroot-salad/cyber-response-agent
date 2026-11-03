"""Tests for the lint_eval_entrypoints gate: no `sys.path` edits under `evaluations/`."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_eval_entrypoints")


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    for rel, text in {"evaluations/ok.py": "X = 1\n", **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_modules_that_only_import_are_clean(tmp_path):
    root = _tree(tmp_path, {"evaluations/oracle_golden/a.py":
                            "import sys\nfrom defender import _io\nprint(sys.path)\n"})
    assert _GATE.scan(root) == []


@pytest.mark.parametrize("line", [
    "sys.path.insert(0, '/x')",
    "sys.path.append('/x')",
    "sys.path.extend(['/x'])",
    "sys.path = ['/x']",
    "sys.path += ['/x']",
    "sys.path[0] = '/x'",
    "sys.path[:0] = ['/x']",
])
def test_the_old_bootstrap_spellings_are_found(tmp_path, line):
    root = _tree(tmp_path, {"evaluations/oracle_golden/a.py": f"import sys\n{line}\n"})
    found = _GATE.scan(root)
    assert len(found) == 1, found
    assert found[0].startswith("evaluations/oracle_golden/a.py:2:")


def test_a_sys_path_edit_outside_evaluations_or_in_its_tests_is_out_of_scope(tmp_path):
    bootstrap = "import sys\nsys.path.insert(0, '/x')\n"
    root = _tree(tmp_path, {"defender/run.py": bootstrap, "evaluations/tests/test_a.py": bootstrap})
    assert _GATE.scan(root) == []


def test_a_missing_evaluations_tree_is_blind(tmp_path):
    with pytest.raises(_GATE._astlib.ScanBlind):
        _GATE.scan(tmp_path)


def test_the_real_tree_is_clean():
    assert _GATE.scan(_GATE.REPO) == []
