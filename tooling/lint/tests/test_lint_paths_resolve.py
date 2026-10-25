"""Tests for the lint_paths_resolve gate: lint scope lists, baseline keys and CI commands name paths
that exist."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_paths_resolve")

_MAIN = "def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n"


def _tree(tmp_path: Path, lint: str = "", baseline: dict | None = None, ci: str = "") -> Path:
    root = tmp_path / "repo"
    (root / "tooling/lint").mkdir(parents=True)
    (root / "defender/cli").mkdir(parents=True)
    (root / ".github/workflows").mkdir(parents=True)
    (root / "defender/real").mkdir()
    (root / "defender/cli/tenant.py").write_text(_MAIN, encoding="utf-8")
    (root / "defender/cli/lib.py").write_text("X = 1\n", encoding="utf-8")
    (root / "tooling/lint/lint_x.py").write_text(lint or "X = 1\n", encoding="utf-8")
    (root / "tooling/lint/lint_x_baseline.json").write_text(
        json.dumps({"entries": baseline or {}}), encoding="utf-8")
    (root / ".github/workflows/ci.yml").write_text(ci or "jobs: {}\n", encoding="utf-8")
    return root


def test_a_clean_tree_has_no_findings(tmp_path):
    lint = 'SCOPE = ("defender/real/", "defender/cli/tenant.py")\nSWEEP_DIRS = ("real",)\n'
    ci = "      - run: python3 defender/cli/tenant.py check\n      - run: python -m defender.cli.tenant\n"
    assert _GATE.scan(_tree(tmp_path, lint=lint, ci=ci, baseline={"defender/real:x": "ok"})) == []


@pytest.mark.parametrize("lint", [
    'SCOPE = ("defender/gone/",)\n',
    'SCOPE = {"defender/gone.py": 1}\n',
    'SCOPE = frozenset({"tooling/gone.py"})\n',
    'SWEEP_DIRS = ("gone",)\n',
])
def test_a_scope_entry_naming_a_deleted_path_is_found(tmp_path, lint):
    found = _GATE.scan(_tree(tmp_path, lint=lint))
    assert len(found) == 1 and "does not exist" in found[0], found


def test_a_machine_local_folder_is_not_a_finding(tmp_path):
    lint = 'SCOPE = ("defender/.venv/", ".claude/worktrees/x")\n'
    assert _GATE.scan(_tree(tmp_path, lint=lint)) == []


def test_a_baseline_key_naming_a_deleted_path_is_found(tmp_path):
    found = _GATE.scan(_tree(tmp_path, baseline={"defender/gone/old.py:name": "x"}))
    assert len(found) == 1 and "old.py" in found[0], found


@pytest.mark.parametrize("run", [
    "python3 defender/cli/gone.py",
    "python3 defender/cli/lib.py",
    "python -m defender.cli.gone",
])
def test_a_ci_command_naming_no_runnable_module_is_found(tmp_path, run):
    found = _GATE.scan(_tree(tmp_path, ci=f"      - run: {run}\n"))
    assert len(found) == 1 and "__main__" in found[0], found


def test_a_file_that_does_not_parse_is_exit_2(tmp_path):
    assert _GATE.main(["--root", str(_tree(tmp_path, lint="def (:\n"))]) == 2
