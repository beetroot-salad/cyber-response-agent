#!/usr/bin/env python3
"""Shared suite analysis for check_calls and check_stub: which modules are THE TARGET.

At spec time the implementation does not exist, so the suite's own imports identify it:
a dotted import that is project-rooted (its first segment exists under the repo root)
but resolves to no module file or package directory is the not-yet-written target. A
third-party import (pytest, yaml) is not project-rooted and never a target; an import
that resolves is existing code.

The honest floor: a spec that *modifies* an existing module, or adds a symbol to one,
has a target these imports cannot identify — every import resolves. Both consumers take
explicit `--target <dotted.module>` for that case and exit 2 (could not look) rather
than 0 (looked, found nothing) when no target can be identified at all.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

_COPY = re.compile(r"\.copy\d+\.py$")


def suite_files(suite_dir: Path) -> list[Path]:
    """The suite's `*.py`, minus `shuffle-premises` copies (same names, premise-only
    docstrings — the check_binds exclusion, for the same reason)."""
    return [p for p in sorted(suite_dir.glob("*.py")) if not _COPY.search(p.name)]


def _binds_name(init: Path, name: str) -> bool:
    """Whether a package __init__ defines/imports `name` — if so, `from pkg import name`
    is existing code, not a missing submodule."""
    try:
        tree = ast.parse(init.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return True  # cannot tell — treat as existing, never invent a target
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                return True
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            if any((a.asname or a.name.split(".")[0]) == name for a in node.names):
                return True
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return True
    return False


def _module_exists(root: Path, dotted: str) -> bool:
    p = root / Path(*dotted.split("."))
    return p.with_suffix(".py").is_file() or p.is_dir()


def target_modules(suite_dir: Path, root: Path) -> tuple[dict[str, set[str]], list[str]]:
    """(targets, floor): dotted target module → the symbols the suite imports from it,
    plus floor notes for the shapes the import heuristic cannot classify."""
    targets: dict[str, set[str]] = {}
    floor: list[str] = []
    for py in suite_files(suite_dir):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError) as e:
            floor.append(f"{py.name}: unparseable ({e.__class__.__name__}) — its imports are unseen")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    dotted = alias.name
                    if _project_rooted(root, dotted) and not _module_exists(root, dotted):
                        targets.setdefault(dotted, set())
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                dotted = node.module
                if not _project_rooted(root, dotted):
                    continue
                if not _module_exists(root, dotted):
                    targets.setdefault(dotted, set()).update(a.name for a in node.names)
                    continue
                # The module exists: each imported name is either its attribute (existing
                # code), a submodule file, or a MISSING submodule — the last is a target.
                base = root / Path(*dotted.split("."))
                if not base.is_dir():
                    continue  # a real module file; its symbols are existing code
                init = base / "__init__.py"
                for a in node.names:
                    if a.name == "*" or _module_exists(root, f"{dotted}.{a.name}"):
                        continue
                    if init.is_file():
                        if not _binds_name(init, a.name):
                            floor.append(
                                f"{py.name}: `from {dotted} import {a.name}` binds nothing "
                                f"visible — a symbol to be added to existing code? Name the "
                                f"module with --target if it is the target."
                            )
                        continue
                    targets.setdefault(f"{dotted}.{a.name}", set())
    return targets, floor


def _project_rooted(root: Path, dotted: str) -> bool:
    head = dotted.split(".")[0]
    return (root / head).is_dir() or (root / f"{head}.py").is_file()
