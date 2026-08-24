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


def suite_dir_for(graph_path: Path, graph: dict, *, root: Path) -> Path:
    """The suite a graph is the derivation of.

    This used to be the graph's own directory, which made adjacency load-bearing in code
    rather than convention — and left the corpus scattered across whichever test tree each
    spec happened to touch. The graph now names its suite (`tests:`, repo-relative), so the
    graphs can live together and be gated as one corpus.

    ANCHORED ON THE GRAPH. `root` is REQUIRED and every caller passes the graph's own directory:
    `_config.repo_root()` with no argument is the repo the PROCESS stands in, which is wrong for
    any caller handed an explicit path — the argument may name a graph in another checkout (a
    write-tests worktree is the ordinary case), and a process-anchored join then silently reads
    the wrong tree's suite. There is deliberately no default: a `None` one would be spelled the
    same as the correct call and would silently restore exactly that defect.

    Falls back to the graph's directory when the field is absent, which keeps the plugin's
    own fixture graphs (and any graph written before the field existed) working. The
    fallback is safe rather than silent: a graph that names the wrong suite, or none, loses
    its docstrings and `check_binds` reports every demand as a prose orphan — loudly, not
    as a clean pass.

    A `tests:` that is not a plain RELATIVE STRING takes the same fallback. `str()` on a list or
    an int fabricates a directory name nobody typed (`tests: [a, b]` → a literal `['a', 'b']`
    directory in the diagnostic), and `root / "/abs"` DISCARDS root outright, so an absolute
    value silently resolves the suite outside the repo — and `check_stub` then runs pytest
    there. Neither is a suite this can resolve, so neither is guessed at.

    The same fallback catches a value that ESCAPES the repo without being absolute. `tests:
    ../elsewhere` is not `is_absolute()`, but it joins and resolves to a directory outside the
    checkout just as surely, and `check_stub` would run pytest — conftest execution included —
    over whatever is there. The spelling is what differs; the outcome the absolute arm refuses is
    identical, so the test is on the RESOLVED path rather than on how it was written.
    """
    declared = graph.get("tests")
    if not isinstance(declared, str) or not declared or Path(declared).is_absolute():
        return graph_path.parent
    import _config  # local: only this path needs the repo-root resolution

    anchor = _config.repo_root(root).resolve()
    resolved = (anchor / declared).resolve()
    if not resolved.is_relative_to(anchor):
        return graph_path.parent
    return resolved


def suite_dir_from_arg(arg: Path) -> Path:
    """The suite directory a CLI argument names — the resolution `check_calls` and `check_stub`
    were missing (#949).

    A DIRECTORY is itself. A FILE is a graph, and the suite it names is the one its `tests:`
    field declares — not the directory the graph happens to sit in. Those
    were the same answer until the graphs moved into one corpus, and `p.parent` has been wrong
    ever since: it resolves to the specs directory, which holds no Python at all, so a run given
    `--target` reported "0 test(s) that never reach the target" over a suite it never opened.
    `check_binds` already routes through `suite_dir_for`; these two did not.

    ONE resolver, not two: the `tests:` rule lives in `suite_dir_for` and this is the
    path-argument dispatcher in front of it. A second copy anchored differently would answer
    differently for one graph depending on which sibling checker asked.

    An unreadable or non-mapping graph falls back to the graph's own directory rather than
    raising here. That is not a silent pass: both callers refuse a resolved directory holding no
    Python, which is precisely where that fallback lands. The except tuple carries `ValueError`
    for `UnicodeDecodeError` — a non-utf-8 graph is the commonest unreadable one, and it is a
    `ValueError`, not an `OSError`, so without it the read escapes as a traceback behind exit 1
    ("the gate looked and found something") for a gate that looked at nothing.
    """
    if arg.is_dir():
        # `.resolve()` here too: the two arms must have ONE post-condition, or `_pytest_cwd`'s
        # `d == root` Path-equality compares a relative path against an absolute git-derived root
        # and silently never matches. Relying on both callers having resolved first made this
        # function's correctness depend on an invariant it does not enforce.
        return arg.resolve()
    import yaml  # local, matching `_config` above: only these paths need the parse

    import _cli

    try:
        graph = _cli.load_graph(arg)
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        return arg.parent
    # `.resolve()` because `run()` moves cwd to the pytest rootdir and `_pytest_cwd` compares
    # `d == root` string-wise: a `tests: ../shared` left un-normalised never matches the root it
    # is under. The directory arm above is already resolved by both callers.
    return suite_dir_for(arg, graph, root=arg.parent).resolve()


#: A module-level test function, however the file is named. `check_calls` keys off the FUNCTION
#: name (`name.startswith("test_")`), so this is the same question its scan asks.
_DEF_TEST = re.compile(r"^(?:async\s+)?def\s+test_\w*\s*\(", re.MULTILINE)


def has_tests(suite_dir: Path) -> bool:
    """Whether `check_calls`' flat scan of this directory would find a test to reason about.

    Not "holds any Python" (#949). A directory of only `conftest.py` and helper modules passes
    a bare `.py` test while collecting nothing, and the consumer then prints its clean line —
    `0 test(s) that never reach the target`, exit 0 — over a suite with no tests in it, which is
    the false clean this guard exists to stop.

    Asks whether a file DEFINES a test, not whether it is NAMED like one. Filename patterns are
    `python_files`, which is configurable per project, and spec-flow ships as a plugin to repos
    that do not use the default — a name-based guard refuses a `*_spec.py` suite that its own
    consumer reads perfectly well, trading the false clean for a false refusal. The function name
    is the thing `check_calls` actually keys off, so this matches its reach exactly.

    Flat on purpose, matching `suite_files`: a nested test `check_calls` genuinely cannot read is
    honestly a could-not-look. `check_stub` has no guard of this kind — it hands the directory to
    the project's own pytest, which descends and honours the project's config, and refuses on
    what that run actually collected.
    """
    for p in suite_files(suite_dir):
        try:
            if _DEF_TEST.search(p.read_text(encoding="utf-8")):
                return True
        except (OSError, ValueError):
            continue  # unreadable here is check_calls' own scan's finding, not this guard's
    return False


def no_tests_refusal(tool: str, dirs: list[Path]) -> str:
    """The family's could-not-look sentence for a resolved suite directory holding no tests.

    One wording for both consumers: `check_calls` and `check_stub` print the identical three
    sentences, and a wording fix applied to one copy leaves the other stale — which matters
    because the message is what an author greps for and what the tests assert on.
    """
    named = str(dirs[0]) if len(dirs) == 1 else str([str(d) for d in dirs])
    return (
        f"{tool}: no tests under {named} — nothing to collect, so this is a could-not-look "
        f"rather than a clean run. Point at the suite directory, or at a graph whose "
        f"`tests:` field names it."
    )


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
