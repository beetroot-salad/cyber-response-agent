#!/usr/bin/env python3
"""Shared suite analysis for check_calls and check_stub: which modules are the target.

At spec time the implementation does not exist, so a dotted import that is project-rooted
(its first segment exists under the repo root) but resolves to no module file or package
is the not-yet-written target. Third-party imports are not project-rooted; resolving
imports are existing code.

Blind spots: a spec that modifies an existing module has no unresolvable import, and a
brand-new top-level module (`from foo import parse`, no `foo.py`) looks like a third-party
import, since for one segment "project-rooted" and "exists" are the same test. Both
consumers take `--target <dotted.module>` for these, and exit 2 when no target is found.
"""
from __future__ import annotations

import ast
import functools
import re
import subprocess
import sys
from pathlib import Path

_COPY = re.compile(r"\.copy\d+\.py$")


@functools.cache
def repo_root(start: Path) -> Path:
    """The checkout containing `start` (a suite dir may live in another repo than cwd)."""
    out = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, encoding="utf-8", check=False,
    ).stdout.strip()
    if out:
        return Path(out)
    # git could not answer (no git, no `.git`, or a `safe.directory` refusal): walk up for
    # `.git` rather than return `start`, which would misplace the project root.
    base = start.resolve()
    for cand in (base, *base.parents):
        if (cand / ".git").exists():
            return cand
    return base


#: A module-level test function, however the file is named (matching `check_calls`' scan).
_DEF_TEST = re.compile(r"^(?:async\s+)?def\s+test_\w*\s*\(", re.MULTILINE)


def has_tests(suite_dir: Path) -> bool:
    """Whether the suite subtree contains a test to reason about.

    Not "holds any Python": a directory of only `conftest.py` and helpers would otherwise
    report a false clean. Checks whether a file defines a test function rather than its
    filename, since `python_files` patterns are configurable per project. Recursive, matching
    `suite_files`. (`check_stub` needs no such guard: pytest reports what it collected.)
    """
    for p in suite_files(suite_dir):
        try:
            if _DEF_TEST.search(p.read_text(encoding="utf-8")):
                return True
        except (OSError, ValueError):
            continue
    return False


def no_tests_refusal(tool: str, suite_dir: Path) -> str:
    """The could-not-look sentence for a suite directory holding no tests. Tests assert on
    this wording."""
    return (
        f"{tool}: no tests under {suite_dir} — nothing to collect, so this is a could-not-look "
        f"rather than a clean run. Point at the suite directory."
    )


def suite_files(suite_dir: Path) -> list[Path]:
    """The suite subtree's `*.py`, minus leftover premise copies (`*.copyN.py`, written by the retired
    answer-escalation step), which reuse test names with premise-only docstrings and would
    shadow the real file."""
    return [p for p in sorted(suite_dir.rglob("*.py"), key=lambda p: (p.name, p.as_posix())) if not _COPY.search(p.name)]


def names_in(node: ast.AST) -> set[str]:
    """Every identifier reachable from `node` — bare names and attribute tails alike, so
    `box.BoxExecutor` and a bare `BoxExecutor` both answer to `BoxExecutor`."""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
    return out


def _binds_name(init: Path, name: str) -> bool:
    """Whether a package __init__ defines/imports `name` — if so, `from pkg import name`
    is existing code, not a missing submodule."""
    try:
        tree = ast.parse(init.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return True  # cannot tell: treat as existing rather than invent a target
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


class _Imports:
    """What `target_modules` accumulates: dotted target module → imported symbols, plus
    floor notes for shapes the heuristic cannot classify."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.targets: dict[str, set[str]] = {}
        self.floor: list[str] = []
        self._noted_toplevel: set[str] = set()

    def note_single_segment(self, py_name: str, dotted: str) -> None:
        # A single-segment name cannot be told apart from a third-party dep, so note it
        # (once per name; stdlib names are never a target).
        if "." in dotted or dotted in self._noted_toplevel or dotted in sys.stdlib_module_names:
            return
        self._noted_toplevel.add(dotted)
        self.floor.append(
            f"{py_name}: unresolved top-level import `{dotted}` — could be a greenfield "
            f"top-level target or a third-party dep; name it with --target if it is the "
            f"target."
        )

    def visit_import(self, py_name: str, node: ast.Import) -> None:
        """`import a.b.c` — the dotted name itself is the candidate."""
        for alias in node.names:
            dotted = alias.name
            if not _project_rooted(self.root, dotted):
                self.note_single_segment(py_name, dotted)
            elif not _module_exists(self.root, dotted):
                self.targets.setdefault(dotted, set())

    def visit_import_from(self, py_name: str, node: ast.ImportFrom) -> None:
        """`from a.b import x, y` — the module, and then each name it does not resolve."""
        if node.level:
            # Relative imports are beyond this root-anchored heuristic; report them rather
            # than silently skip.
            self.floor.append(
                f"{py_name}: relative import `from "
                f"{'.' * node.level}{node.module or ''} import "
                f"{', '.join(a.name for a in node.names)}` — the heuristic resolves "
                f"project-rooted absolute imports only; name it with --target if it "
                f"is the target."
            )
            return
        if not node.module:
            return
        dotted = node.module
        if not _project_rooted(self.root, dotted):
            self.note_single_segment(py_name, dotted)
            return
        if not _module_exists(self.root, dotted):
            self.targets.setdefault(dotted, set()).update(a.name for a in node.names)
            return
        self._visit_names_of_existing(py_name, dotted, node)

    def _visit_names_of_existing(self, py_name: str, dotted: str, node: ast.ImportFrom) -> None:
        """The module exists: each imported name is an attribute, a submodule, or a missing
        submodule (a target)."""
        base = self.root / Path(*dotted.split("."))
        if not base.is_dir():
            return  # a real module file; its symbols are existing code
        init = base / "__init__.py"
        for a in node.names:
            if a.name == "*" or _module_exists(self.root, f"{dotted}.{a.name}"):
                continue
            if init.is_file():
                if not _binds_name(init, a.name):
                    self.floor.append(
                        f"{py_name}: `from {dotted} import {a.name}` binds nothing "
                        f"visible — a symbol to be added to existing code? Name the "
                        f"module with --target if it is the target."
                    )
                continue
            self.targets.setdefault(f"{dotted}.{a.name}", set())


def target_modules(suite_dir: Path, root: Path) -> tuple[dict[str, set[str]], list[str]]:
    """(targets, floor): dotted target module → the symbols the suite imports from it,
    plus floor notes for the shapes the import heuristic cannot classify."""
    imports = _Imports(root)
    for py in suite_files(suite_dir):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError) as e:
            imports.floor.append(
                f"{py.name}: unparseable ({e.__class__.__name__}) — its imports are unseen"
            )
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.visit_import(py.name, node)
            elif isinstance(node, ast.ImportFrom):
                imports.visit_import_from(py.name, node)
    return imports.targets, imports.floor


def _project_rooted(root: Path, dotted: str) -> bool:
    head = dotted.split(".")[0]
    return (root / head).is_dir() or (root / f"{head}.py").is_file()
