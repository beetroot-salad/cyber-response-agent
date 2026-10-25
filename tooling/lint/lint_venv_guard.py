#!/usr/bin/env python3
"""Venv-guard fence (#1080): a script that re-executes itself into the venv does so first.

* `execution/_venv.py`, the module that holds the guard, imports only the standard library (it runs
  before the venv's packages exist).
* Every production file that calls `reexec_into_venv(` calls it at module scope (inside a compound
  statement such as `if __name__ ...` counts) before it imports any other `defender.*` module,
  because an import above the guard would load the wrong interpreter's packages.

At least one guarded script must exist: a tree with none is a finding (the rule moved), never a
pass. A file that does not parse or decode is exit 2. No baseline, no suppression.

Run from anywhere:  python tooling/lint/lint_venv_guard.py [--root DIR]
Exit 0 = clean, 1 = a finding, 2 = could not scan.
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import _astlib

#: The checkout's own `defender/`, so a run from any directory or worktree sweeps itself.
DEFENDER = Path(__file__).resolve().parents[2] / "defender"

EXCLUDED_DIRS = ("tests", ".venv", "__pycache__")
_VENV = "execution/_venv.py"
_VENV_MODULE = "defender.execution._venv"
_GUARD = "reexec_into_venv"


def _module_imports(stmt: ast.stmt) -> list[str]:
    """Every absolute module a statement imports, recursing into compound statements."""
    names: list[str] = []
    for node in ast.walk(stmt):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.append(node.module)
    return names


def _calls_guard(stmt: ast.stmt) -> bool:
    """Whether running `stmt` at import time calls the guard (a definition only declares it)."""
    if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return False
    return any(isinstance(n, ast.Call) and ast.unparse(n.func) == _GUARD for n in ast.walk(stmt))


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    findings: list[str] = []
    venv = root / _VENV
    if not venv.is_file():
        findings.append(f"{_VENV}: missing; the venv-guard rule has nothing to hold")
    else:
        _text, tree = _astlib.read_and_parse(venv, _VENV)
        findings.extend(
            f"{_VENV}: imports `{m}`; it runs before the venv's packages exist, so it must stay "
            "standard-library-only"
            for stmt in tree.body for m in _module_imports(stmt)
            if m.split(".")[0] not in sys.stdlib_module_names)
    guarded = 0
    for rel in _astlib.source_files(root, EXCLUDED_DIRS):
        if rel == _VENV:
            continue
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        if not any(_calls_guard(stmt) for stmt in tree.body):
            if any(isinstance(n, ast.Call) and ast.unparse(n.func) == _GUARD
                   for n in ast.walk(tree)):
                findings.append(f"{rel}: calls `{_GUARD}` only inside a function, never at "
                                "module scope")
            continue
        guarded += 1
        for stmt in tree.body:
            if _calls_guard(stmt):
                break
            findings.extend(
                f"{rel}:{stmt.lineno}: imports `{m}` above the venv guard"
                for m in _module_imports(stmt)
                if m.startswith("defender") and m != _VENV_MODULE)
    if not guarded:
        findings.append(f"no production file calls `{_GUARD}` at module scope; re-site the rule")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_venv_guard] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_venv_guard] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
