#!/usr/bin/env python3
"""Half-read policy table: flag a boundary that hardcodes one key of someone else's keyed gate
table, leaving the table's other keys with no reader at that boundary.

A module-level dict mapping string keys to per-key handlers is where each key's meaning is
decided, and the owner reaches those answers through a lookup (``T.get(d)`` / ``T[d]`` /
``d in T`` / iteration). A collaborating module that branches on one key spelled as a literal
has re-decided one row locally and declined to decide the rest — e.g. charging an entry price
for ``"false-positive"`` by literal while ``"benign"``, the table's other key, passes ungated.

What is mechanized (the consumer half, by shape only):

  - A table is a module-level ``Assign``/``AnnAssign`` whose value is an ``ast.Dict`` with
    >= 2 keys, no ``**`` spread, every key resolving to a string through
    ``_astlib.str_value`` (so hoisted key constants are the same table), and every value a
    ``Name``/``Attribute``/``Lambda``. A str->str map is a naming table and is skipped.
  - A table is armed once it is looked up generically anywhere in the corpus — ``T[expr]``
    with a non-Constant slice, ``T.get(...)``, ``.items()``/``.keys()``/``.values()``,
    ``x in T``, iteration, or the same through a resolved import (``m.T[...]``,
    ``getattr(m, "T")``). New tables are guarded with no edit to this lint.
  - A finding is a branch on a string equal to one of an armed table's keys, in a module
    that imports the owner but is not it, where the branching function does not itself reach
    the table's lookup — one finding per unread key. "Branch" is ``==``/``!=`` against a
    string, ``in``/``not in`` a literal sequence of strings, and ``case "s":``.

Calls and cross-module references resolve through ``_astlib``, never by dotted spelling.

What is not mechanized — a clean run is not a clean tree:

  1. A boundary that enumerates every key by literal is invisible: the detector fires on the
     gap, so completing the enumeration turns the gate green while making the code worse.
  2. Whether the branch actually re-derived the decision is not checked; a boundary may
     legitimately special-case one key after delegating the rest. That judgement is the
     reviewer's, recorded via the suppression marker.
  3. Cross-module key identity is value-based: the tables are private, so a consumer is tied
     to one by its key strings plus an import edge to the owner. Short generic keys collide
     (an unrelated ``direction == "benign"`` is a baselined structural false positive), and a
     consumer that does not import the owner is a false negative. The import edge is a suffix
     match, including function-local imports.
  4. The owner half is out of scope: handler completeness, exclusivity, correctness, and
     fail-closed lookup on an unknown key are not checked.
  5. Values reached as data (a lookup into a local dict, a key passed as a parameter) carry
     no literal and are never seen.

Mark a deliberate site with ``# lint-half-table: ok — <reason>``, on the site's own lines or
anywhere in the comment block directly above it.

Pre-existing sites are ratcheted via ``lint_half_read_table_baseline.json`` (see
scripts/lint/_baseline.py). ``require_reasons`` is on: an entry with no annotation fails the
gate exactly as a new finding does.

Run from repo root:  python scripts/lint/lint_half_read_table.py
Regenerate the baseline:  python scripts/lint/lint_half_read_table.py --update-baseline
Exit 0 = clean (no new sites), 1 = new/un-triaged sites, 2 = the gate could not look.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

try:  # package import in tests
    from ._astlib import (
        ModuleEnv,
        ScanBlind,
        callee,
        module_env,
        origin,
        read_and_parse,
        str_value,        source_files,

    )
    from ._baseline import Finding, gate
except ImportError:  # direct ``python scripts/lint/...`` execution
    from _astlib import (
        ModuleEnv,
        ScanBlind,
        callee,
        module_env,
        origin,
        read_and_parse,
        str_value,        source_files,

    )
    from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_half_read_table_baseline.json")
EXCLUDED_DIRS = frozenset(
    {".venv", "__pycache__", "tests", "runs"}
)
SUPPRESS = "lint-half-table: ok"

# One key is a constant, not a table; two is the smallest dispatch with something to leave
# unread.
MIN_KEYS = 2

# Reads that answer for every key, as opposed to a literal subscript answering for one.
_LOOKUP_METHODS = frozenset({"get", "items", "keys", "values"})


# corpus


def _relative(path: Path, scope: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.relative_to(scope).as_posix()


def _dotted(rel: str) -> tuple[str, ...]:
    """The module path of a source file, as tuple parts: ``a/b/__init__.py`` -> ``(a, b)``."""
    parts = Path(rel).with_suffix("").parts
    return parts[:-1] if parts and parts[-1] == "__init__" else parts


# owner side


def _module_tables(tree: ast.Module, env: ModuleEnv) -> dict[str, tuple[str, ...]]:
    """``name -> keys`` for every module-level keyed gate table this module defines.

    Every value must be a ``Name``/``Attribute``/``Lambda``, which separates a dispatch table
    from a str->str naming map.
    """
    tables: dict[str, tuple[str, ...]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        value = node.value
        if not isinstance(value, ast.Dict):
            continue
        if any(key is None for key in value.keys):  # `**spread`: the key set is not closed
            continue
        keys = [v for key in value.keys if (v := str_value(key, env)) is not None]
        if len(keys) != len(value.keys) or len(set(keys)) < MIN_KEYS:
            continue
        if not all(
            isinstance(answer, (ast.Name, ast.Attribute, ast.Lambda))
            for answer in value.values
        ):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                tables[target.id] = tuple(keys)
    return tables


def _generic_lookups(tree: ast.AST, env: ModuleEnv) -> tuple[set[str], set[str]]:
    """What this tree looks up generically, as ``(bare local names, resolved origins)``.

    Inside its owner a table is a bare local name (resolving to nothing); elsewhere it is
    reached through an import, where the dotted origin is the only sound identity —
    ``m.T[...]``, ``from m import T`` then ``T.get(...)``, and ``getattr(m, "T")`` all land on
    the same string, while a same-named attribute of a local object lands on none.
    """
    local: set[str] = set()
    origins: set[str] = set()

    def record(expr: ast.expr) -> None:
        if isinstance(expr, ast.Name):
            local.add(expr.id)
        resolved = origin(expr, env)
        if resolved is not None:
            origins.add(resolved)

    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            # A literal subscript reads one key; anything else reads whichever it is given.
            if not isinstance(node.slice, ast.Constant):
                record(node.value)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _LOOKUP_METHODS:
                record(func.value)
            elif callee(node, env) == "builtins.getattr" and len(node.args) == 2:
                base = origin(node.args[0], env)
                attr = str_value(node.args[1], env)
                if base is not None and attr is not None:
                    origins.add(f"{base}.{attr}")
        elif isinstance(node, ast.Compare):
            for op, comparator in zip(node.ops, node.comparators):
                if isinstance(op, (ast.In, ast.NotIn)):
                    record(comparator)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            record(node.iter)
    return local, origins


# consumer side


def _imported_modules(tree: ast.Module) -> set[tuple[str, ...]]:
    """Every module path this file imports, as dotted tuples.

    ``ast.walk``, not ``tree.body``: a function-local import is a collaboration edge too.
    """
    out: set[tuple[str, ...]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            base = tuple(node.module.split(".")) if node.module else ()
            if base:
                out.add(base)
            for alias in node.names:  # `from pkg import mod` / `from . import mod`
                if alias.name != "*":
                    out.add(base + (alias.name,))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                out.add(tuple(alias.name.split(".")))
    return out


def _imports_owner(imports: set[tuple[str, ...]], owner: tuple[str, ...]) -> bool:
    """Whether this file names the owner's module. A suffix match, so a relative import
    (whose dots ``ast`` does not keep in ``module``) still counts; loose toward false
    positives."""
    return any(
        path and len(path) <= len(owner) and owner[-len(path):] == path for path in imports
    )


def _branch_literals(
    tree: ast.Module, env: ModuleEnv
) -> list[tuple[str, ast.AST, tuple[str, ...], ast.AST | None]]:
    """``(string, node, enclosing scope, enclosing function)`` for every literal a control-flow
    branch turns on: ``x == "s"``, ``x != "s"``, ``x in ("s", ...)``, ``case "s":``."""
    out: list[tuple[str, ast.AST, tuple[str, ...], ast.AST | None]] = []

    def visit(node: ast.AST, scope: tuple[str, ...], func: ast.AST | None) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope, func = (*scope, node.name), node
        elif isinstance(node, ast.ClassDef):
            scope = (*scope, node.name)
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for op, comparator in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    for side in operands:
                        if (value := str_value(side, env)) is not None:
                            out.append((value, node, scope, func))
                elif isinstance(op, (ast.In, ast.NotIn)) and isinstance(
                    comparator, (ast.Tuple, ast.List, ast.Set)
                ):
                    for element in comparator.elts:
                        if (value := str_value(element, env)) is not None:
                            out.append((value, node, scope, func))
        elif isinstance(node, ast.MatchValue):
            if (value := str_value(node.value, env)) is not None:
                out.append((value, node, scope, func))
        for child in ast.iter_child_nodes(node):
            visit(child, scope, func)

    visit(tree, (), None)
    return out


def _reaches_lookup(func: ast.AST | None, env: ModuleEnv, table_origin: str) -> bool:
    """Whether the branching function itself reaches the owner's lookup; if so the literal
    is a special case of a decision made through the owner, not a local re-decision."""
    if func is None:
        return False
    return table_origin in _generic_lookups(func, env)[1]


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    """The marker on the site's own line span, or anywhere in the contiguous comment block
    directly above it (the reason rarely fits on the branch's own line)."""
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    if any(SUPPRESS in lines[i - 1] for i in range(start, end + 1) if 0 < i <= len(lines)):
        return True
    i = start - 1
    while i > 0 and lines[i - 1].lstrip().startswith("#"):
        if SUPPRESS in lines[i - 1]:
            return True
        i -= 1
    return False


# the scan


def _reexport_edges(
    corpus: list[tuple[str, ast.Module, list[str], ModuleEnv]],
    tables: dict[tuple[str, str], tuple[str, ...]],
) -> dict[tuple[str, str], set[tuple[str, ...]]]:
    """Facade modules that re-export a table, as extra module paths standing in for its owner.

    Splitting a file behind a facade moves the table's definition without moving the name
    consumers import, so the import-edge suffix match would never hit and those consumers
    would go quiet.

    One hop only: a re-export of a re-export is a facade over a facade, a shape to refuse
    rather than resolve.
    """
    edges: dict[tuple[str, str], set[tuple[str, ...]]] = {}
    owners = {(owner_rel, name) for owner_rel, name in tables}
    for rel, tree, _lines, _env in corpus:
        # For `pkg/__init__.py` the package is its own dotted path (`_dotted` dropped the
        # `__init__`), so a one-dot import there resolves inside the package, not beside it.
        package = _dotted(rel) if rel.endswith("/__init__.py") else tuple(_dotted(rel)[:-1])
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.module is None:
                continue
            if node.level:                      # `from ._gating import T`
                target = package + tuple(node.module.split("."))
            else:
                target = tuple(node.module.split("."))
            for alias in node.names:
                for owner_rel, name in owners:
                    if name != alias.name:
                        continue
                    owner = _dotted(owner_rel)
                    if len(target) <= len(owner) and owner[-len(target):] == target:
                        edges.setdefault((owner_rel, name), set()).add(_dotted(rel))
    return edges


def _scan_file(
    rel: str,
    tree: ast.Module,
    lines: list[str],
    env: ModuleEnv,
    tables: dict[tuple[str, str], tuple[str, ...]],
    reexports: dict[tuple[str, str], set[tuple[str, ...]]] | None = None,
) -> list[Finding]:
    literals = _branch_literals(tree, env)
    if not literals:
        return []
    imports = _imported_modules(tree)
    covered: dict[tuple[str, str], set[str]] = {}
    sites: dict[tuple[str, str, str], tuple[ast.AST, tuple[str, ...]]] = {}
    for value, node, scope, func in literals:
        for (owner_rel, name), keys in tables.items():
            if owner_rel == rel or value not in keys:
                continue
            owner = _dotted(owner_rel)
            # The owner's own path, or any facade re-exporting the table under its name.
            stand_ins = (reexports or {}).get((owner_rel, name), set())
            if not (_imports_owner(imports, owner)
                    or any(_imports_owner(imports, path) for path in stand_ins)):
                continue
            if _reaches_lookup(func, env, f"{'.'.join(owner)}.{name}"):
                continue
            covered.setdefault((owner_rel, name), set()).add(value)
            sites.setdefault((owner_rel, name, value), (node, scope))

    findings: list[Finding] = []
    for (owner_rel, name), seen in sorted(covered.items()):
        missing = sorted(set(tables[(owner_rel, name)]) - seen)
        if not missing:
            # Every key has a reader here; the gate is blind to this shape by design.
            continue
        live = [
            (value, *sites[(owner_rel, name, value)])
            for value in sorted(seen)
            if not _suppressed(sites[(owner_rel, name, value)][0], lines)
        ]
        if not live:
            continue
        value, node, scope = live[0]
        qual = ".".join(scope) or "<module>"
        table = f"{'.'.join(_dotted(owner_rel))}.{name}"
        for gap in missing:
            findings.append(
                Finding(
                    fingerprint=f"{rel}:{qual}:{table}:unread:{gap}",
                    display=(
                        f"{rel}:{node.lineno}: {qual}() branches on {value!r}, one key of "
                        f"{table} — key {gap!r} has no reader here"
                    ),
                )
            )
    return findings


def _scan(scope: Path = DEFENDER) -> list[Finding]:
    """Two passes over one corpus: which tables are armed, then who half-reads them.

    ``scope`` is the test seam; arming is a whole-corpus property, so tests need it to show
    the gate arming and disarming.
    """
    corpus: list[tuple[str, ast.Module, list[str], ModuleEnv]] = []
    for path in (scope / _r for _r in source_files(scope, EXCLUDED_DIRS)):
        rel = _relative(path, scope)
        text, tree = read_and_parse(path, rel)
        corpus.append((rel, tree, text.splitlines(), module_env(tree)))

    # Pass 1: every keyed gate table, and whether anything reads it generically.
    declared: dict[tuple[str, str], tuple[str, ...]] = {}
    owner_local: dict[str, set[str]] = {}
    corpus_origins: set[str] = set()
    for rel, tree, _lines, env in corpus:
        local, origins = _generic_lookups(tree, env)
        owner_local[rel] = local
        corpus_origins |= origins
        for name, keys in _module_tables(tree, env).items():
            declared[(rel, name)] = keys
    armed = {
        (rel, name): keys
        for (rel, name), keys in declared.items()
        if name in owner_local[rel]
        or f"{'.'.join(_dotted(rel))}.{name}" in corpus_origins
    }

    reexports = _reexport_edges(corpus, armed)
    findings: list[Finding] = []
    for rel, tree, lines, env in corpus:
        findings.extend(_scan_file(rel, tree, lines, env, armed, reexports))
    return findings


HEADER = (
    "lint_half_read_table baseline — a boundary that branches on ONE key of another module's "
    "keyed gate table, spelled as a string literal, leaving that table's other keys with no "
    "reader there (#879: close_tool charges the `false-positive` entry price by literal while "
    "`benign` passes ungated). A table is watched only once something reads it generically, so "
    "the gate arms itself as tables land. Fingerprint is "
    "file:function:owner.TABLE:unread:KEY (no line number). CI fails on an entry absent here "
    "OR present with no reason. The gate covers only the one-key-branch shape: a boundary that "
    "enumerates EVERY key by literal is invisible to it, and key identity across modules is "
    "value-based, so short generic keys collide. Regenerate: python "
    "scripts/lint/lint_half_read_table.py --update-baseline."
)


def main(
    argv: list[str],
    *,
    scope: Path = DEFENDER,
    baseline_path: Path = BASELINE_PATH,
) -> int:
    if not scope.is_dir():
        print(f"scan scope not found at {scope}", file=sys.stderr)
        return 2
    # An unreadable file never entered the corpus, and an unreadable owner silently disarms
    # its table repo-wide. Exit 2: the gate could not run, which is not "clean".
    try:
        findings = _scan(scope)
    except ScanBlind as exc:
        print(f"lint_half_read_table: {exc}", file=sys.stderr)
        return 2
    print(
        "A keyed gate table's owner decides what each key MEANS. Reach that decision through "
        "the owner's lookup instead of branching on one key's spelling and leaving the rest "
        "of the table unread at this boundary."
    )
    print("Suppress a deliberate site with `# lint-half-table: ok — <reason>`.")
    return gate(
        findings,
        baseline_path,
        argv,
        label="lint_half_read_table",
        header=HEADER,
        require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
