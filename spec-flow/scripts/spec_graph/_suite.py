#!/usr/bin/env python3
"""Shared suite analysis for check_calls and check_stub: which modules are THE TARGET.

At spec time the implementation does not exist, so the suite's own imports identify it:
a dotted import that is project-rooted (its first segment exists under the repo root)
but resolves to no module file or package directory is the not-yet-written target. A
third-party import (pytest, yaml) is not project-rooted and never a target; an import
that resolves is existing code.

The honest floor: a spec that *modifies* an existing module, or adds a symbol to one,
has a target these imports cannot identify — every import resolves. A spec whose target
is a brand-new TOP-LEVEL module is just as invisible from the other side: for a
single-segment name, "project-rooted" and "exists" are the same filesystem test, so
`from foo import parse` with no `foo.py` reads exactly like a third-party import and is
never classified a target. Both consumers take explicit `--target <dotted.module>` for
these cases and exit 2 (could not look) rather than 0 (looked, found nothing) when no
target can be identified at all.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

_COPY = re.compile(r"\.copy\d+\.py$")


def suite_dir_for(graph_path: Path, graph: dict) -> Path:
    """The suite a graph is the derivation of.

    This used to be the graph's own directory, which made adjacency load-bearing in code
    rather than convention — and left the corpus scattered across whichever test tree each
    spec happened to touch. The graph now names its suite (`tests:`, repo-relative), so the
    graphs can live together and be gated as one corpus.

    Falls back to the graph's directory when the field is absent, which keeps the plugin's
    own fixture graphs (and any graph written before the field existed) working. The
    fallback is safe rather than silent: a graph that names the wrong suite, or none, loses
    its docstrings and `check_binds` reports every demand as a prose orphan — loudly, not
    as a clean pass.
    """
    declared = graph.get("tests")
    if not declared:
        return graph_path.parent
    import _config  # local: only this path needs the repo-root resolution

    return _config.repo_root() / str(declared)


def suite_files(suite_dir: Path) -> list[Path]:
    """The suite's `*.py`, minus `shuffle-premises` copies (`*.copyN.py`): they carry the
    same test names with premise-only docstrings and sort before the real file, so left in
    they would silently shadow the prose and bodies every consumer scans."""
    return [p for p in sorted(suite_dir.glob("*.py")) if not _COPY.search(p.name)]


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


class _Imports:
    """The accumulator `target_modules` fills as it walks the suite's import statements:
    dotted target module → the symbols imported from it, plus the floor notes for shapes
    the heuristic cannot classify. One method per import form."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.targets: dict[str, set[str]] = {}
        self.floor: list[str] = []
        self._noted_toplevel: set[str] = set()

    def note_single_segment(self, py_name: str, dotted: str) -> None:
        # The single-segment blind spot (see the module docstring): for one segment,
        # project-rooted and exists collapse into the same test, so a greenfield
        # top-level target cannot be told from a third-party dep. Floor-noted rather
        # than guessed at — deduplicated per module name, stdlib names excluded (they
        # are resolvable without the project and never a not-yet-written target).
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
            # A relative import resolves against the suite's own package, which this
            # root-anchored heuristic cannot walk. Reported as floor rather than
            # skipped: a dropped import is indistinguishable from "every import
            # resolves", and that is the sentence both consumers exit 2 on.
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
        """The module exists: each imported name is either its attribute (existing code),
        a submodule file, or a MISSING submodule — the last is a target."""
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
