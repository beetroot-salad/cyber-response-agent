#!/usr/bin/env python3
"""Paths-resolve fence (#1080): the paths the lints and CI name must exist.

* Every path-shaped string in a module-level list, tuple, set or dict (keys) of a
  `tooling/lint/*.py` file, and every `lint_run_records.SWEEP_DIRS` folder, exists under the
  repository root or `defender/`. A scope list that names a deleted path silently stops
  covering what it was written for.
* Every path inside a `tooling/lint/*_baseline.json` entry key exists, for the same reason.
* Every command in a `.github/workflows/ci.yml` `run:` line that names `defender/cli/<x>.py`,
  `defender/box/<x>.py` or `-m defender.cli.<x>` names a file with a module-level
  `if __name__ == "__main__":` block.

Entries naming machine-local folders (a venv, a cache, a linked worktree) are skipped: whether
they exist is the checkout's, not the tree's. There is no baseline and no suppression: fix or
delete the entry. A file that does not parse or decode is exit 2.

Run from anywhere:  python tooling/lint/lint_paths_resolve.py [--root DIR]
Exit 0 = clean, 1 = a finding, 2 = could not scan.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

import _astlib

#: The checkout's own root, so a run from any directory or worktree sweeps itself.
REPO = Path(__file__).resolve().parents[2]

_SHAPED = re.compile(r"^[\w.$-]+(?:/[\w.*-]+)*/?$")
_KEY_PATH = re.compile(
    r"(?<![\w./-])((?:[\w.-]+/)*[\w.-]+\.(?:py|md|yaml|yml|json|toml|sh|txt|tsv))(?![\w/])")
_CI_RUN = re.compile(r"^\s*(?:-\s*)?run:\s*(.*(?:defender/(?:cli|box)/|-m defender\.cli\.).*)$")
_CMD_PATH = re.compile(r"(?<![\w.-])(?:defender/)?(?:cli|box)/(\w+)\.py\b")
_CMD_MODULE = re.compile(r"-m\s+defender\.cli\.(\w+)\b")
_JUNK = frozenset({".venv", "venv", "__pycache__", "node_modules", "build", "dist", ".git",
                  ".mypy_cache", ".ruff_cache", ".pytest_cache", ".tox", ".hypothesis",
                  ".eggs", "site-packages"})


def _resolves(root: Path, entry: str) -> bool:
    entry = entry.rstrip("/")
    return any((base / entry).exists() or (base / entry).is_symlink()
               for base in (root, root / "defender"))


def _machine_local(entry: str) -> bool:
    return bool(_JUNK.intersection(entry.rstrip("/").split("/"))) \
        or entry.startswith(".claude/worktrees")


def _scope_entries(tree: ast.Module) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            name, value = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            name, value = node.target.id, node.value
        else:
            continue
        if isinstance(value, ast.Call) and value.args:
            value = value.args[0]
        if isinstance(value, ast.Dict):
            elts = [k for k in value.keys if k is not None]
        elif isinstance(value, ast.Tuple | ast.List | ast.Set):
            elts = list(value.elts)
        else:
            continue
        paths = [e.value for e in elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
                 and "/" in e.value and _SHAPED.match(e.value)]
        if name == "SWEEP_DIRS":
            paths = [f"defender/{e.value}" for e in elts
                     if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        if paths:
            out[name] = paths
    return out


def _has_main_block(source: str) -> bool:
    for node in ast.parse(source).body:
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) \
                and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__" \
                and any(isinstance(c, ast.Constant) and c.value == "__main__"
                        for c in node.test.comparators):
            return True
    return False


def _runnable(root: Path, name: str) -> bool:
    for rel in (f"defender/cli/{name}.py", f"defender/box/{name}.py"):
        path = root / rel
        if path.is_file():
            return _has_main_block(_astlib.read_source(path, rel))
    return False


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    lint_dir = root / "tooling" / "lint"
    if not lint_dir.is_dir():
        raise _astlib.ScanBlind(f"{lint_dir} is not a directory")
    findings: list[str] = []
    for path in sorted(lint_dir.glob("*.py")):
        rel = path.relative_to(root).as_posix()
        _text, tree = _astlib.read_and_parse(path, rel)
        for name, entries in _scope_entries(tree).items():
            findings.extend(f"{rel}: `{name}` names `{e}`, which does not exist"
                            for e in entries if not _resolves(root, e) and not _machine_local(e))
    for path in sorted(lint_dir.glob("*_baseline.json")):
        rel = path.relative_to(root).as_posix()
        try:
            entries = json.loads(_astlib.read_source(path, rel)).get("entries", {})
        except json.JSONDecodeError as exc:
            raise _astlib.ScanBlind(f"{rel}: not valid JSON: {exc}") from exc
        findings.extend(f"{rel}: entry key names `{p}`, which does not exist: {key[:80]}"
                        for key in entries for p in _KEY_PATH.findall(key)
                        if not _resolves(root, p) and not _machine_local(p))
    ci = root / ".github" / "workflows" / "ci.yml"
    if ci.is_file():
        for lineno, line in enumerate(_astlib.read_source(ci, "ci.yml").splitlines(), 1):
            if not (m := _CI_RUN.match(line)):
                continue
            names = _CMD_PATH.findall(m.group(1)) + _CMD_MODULE.findall(m.group(1))
            findings.extend(f".github/workflows/ci.yml:{lineno}: names command `{n}`, which "
                            "is not a file with a `__main__` block"
                            for n in names if not _runnable(root, n))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPO,
                        help="a repository-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_paths_resolve] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_paths_resolve] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
