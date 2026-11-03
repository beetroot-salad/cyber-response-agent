#!/usr/bin/env python3
"""Evaluation-entrypoint fence (#1276): nothing under `evaluations/` edits `sys.path`.

The evaluation tools are run as modules from the repository root
(`python -m evaluations.held_out`, `python -m evaluations.oracle_golden.score`), which puts the
root on the import path before any of their code runs. A script that inserts the root itself
makes its startup depend on where the insert sits among the imports: #1275 put a `defender`
import above one and broke the documented command. This fence bans the insert, so a tool run by
filename fails loudly at start instead of growing a second import-path mechanism.

Flagged: `sys.path.insert/append/extend/remove/pop/clear(...)`, and assignment or augmented
assignment to `sys.path` or an item or slice of it. Test files under `evaluations/tests/` are
out of scope. There is no baseline and no suppression: run the tool as a module.

Run from anywhere:  python tooling/lint/lint_eval_entrypoints.py [--root DIR]
Exit 0 = clean, 1 = a finding, 2 = could not scan.
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import _astlib

REPO = Path(__file__).resolve().parents[2]

SCOPE = "evaluations/"
_MUTATORS = frozenset({"insert", "append", "extend", "remove", "pop", "clear"})


def _is_sys_path(node: ast.AST) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == "path"
            and isinstance(node.value, ast.Name) and node.value.id == "sys")


def _targets(node: ast.AST) -> list[ast.expr]:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    if isinstance(node, ast.AugAssign | ast.AnnAssign):
        return [node.target]
    return []


def _findings(tree: ast.Module, rel: str) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        hit = None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in _MUTATORS and _is_sys_path(node.func.value):
            hit = f"sys.path.{node.func.attr}(...)"
        else:
            for target in _targets(node):
                base = target.value if isinstance(target, ast.Subscript) else target
                if _is_sys_path(base):
                    hit = "an assignment to sys.path"
        if hit:
            out.append(f"{rel}:{node.lineno}: {hit} — run the tool as a module from the "
                       "repository root (`python -m evaluations...`) instead")
    return out


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not (root / "evaluations").is_dir():
        raise _astlib.ScanBlind(f"{root / 'evaluations'} is not a directory")
    findings: list[str] = []
    for rel in _astlib.source_files(root, {".venv", "__pycache__", "tests"}):
        if not rel.startswith(SCOPE):
            continue
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        findings.extend(_findings(tree, rel))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPO,
                        help="a repository-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_eval_entrypoints] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_eval_entrypoints] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
