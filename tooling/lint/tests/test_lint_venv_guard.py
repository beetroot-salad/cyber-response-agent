"""Tests for the lint_venv_guard gate: _venv.py stays stdlib-only and every guarded script calls
the guard before importing any other defender module."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_venv_guard")

_VENV = "import os, sys\nfrom pathlib import Path\ndef reexec_into_venv(): pass\n"
_SCRIPT = ("import sys\nfrom defender.execution._venv import reexec_into_venv\n"
           "reexec_into_venv()\nfrom defender.other import x\n")


def _tree(tmp_path: Path, **files: str) -> Path:
    root = tmp_path / "defender"
    for rel, text in {"execution/_venv.py": _VENV, "tool.py": _SCRIPT,
                      **{k.replace("__", "/"): v for k, v in files.items()}}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_a_clean_tree_has_no_findings(tmp_path):
    assert _GATE.scan(_tree(tmp_path)) == []


def test_a_guard_inside_the_main_block_counts(tmp_path):
    src = ("from defender.execution._venv import reexec_into_venv\n"
           "if __name__ == '__main__':\n    reexec_into_venv()\nfrom defender.other import x\n")
    assert _GATE.scan(_tree(tmp_path, **{"tool.py": src})) == []


@pytest.mark.parametrize("src", [
    "from defender.other import x\nfrom defender.execution._venv import reexec_into_venv\nreexec_into_venv()\n",
    "import defender.other\nfrom defender.execution._venv import reexec_into_venv\nreexec_into_venv()\n",
    "try:\n    from defender.other import x\nexcept ImportError:\n    pass\nfrom defender.execution._venv import reexec_into_venv\nreexec_into_venv()\n",
])
def test_a_defender_import_above_the_guard_is_found(tmp_path, src):
    found = _GATE.scan(_tree(tmp_path, **{"tool.py": src}))
    assert len(found) == 1 and "above the venv guard" in found[0], found


def test_a_guard_only_inside_a_function_is_found(tmp_path):
    src = "def go():\n    reexec_into_venv()\n"
    assert any("module scope" in f for f in _GATE.scan(_tree(tmp_path, **{"tool.py": src})))


def test_the_venv_module_importing_beyond_the_stdlib_is_found(tmp_path):
    found = _GATE.scan(_tree(tmp_path, **{"execution___venv.py": "import yaml\n"}))
    assert len(found) == 1 and "standard-library-only" in found[0], found


def test_a_tree_with_no_guarded_script_is_a_finding(tmp_path):
    root = _tree(tmp_path)
    (root / "tool.py").unlink()
    assert any("re-site" in f for f in _GATE.scan(root))


def test_tests_are_not_swept(tmp_path):
    src = "import defender.other\nreexec_into_venv()\n"
    assert _GATE.scan(_tree(tmp_path, **{"tests__t.py": src})) == []


def test_a_file_that_does_not_parse_is_exit_2(tmp_path):
    assert _GATE.main(["--root", str(_tree(tmp_path, **{"tool.py": "def (:\n"}))]) == 2
