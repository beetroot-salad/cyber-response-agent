#!/usr/bin/env python3
"""Unanchored-default smell: flag a parameter re-defaulted in the body via a self-referential
None-coalesce to a named/called fallback, under ``defender/``.

The shape ::

    def f(repo_root: Path | None = None):
        repo_root = repo_root if repo_root is not None else REPO_ROOT   # ← flagged
        ...

Both problems are about a single source of truth:

1. The signature says ``Path | None`` but the first body line makes it non-None. Optionality
   should be parsed away once at the boundary, then passed inward as a concrete value.
2. The fallback (``REPO_ROOT`` / ``CATALOG_DIR`` / ``subscription_env()``) is default
   knowledge; repeating ``else REPO_ROOT`` in N functions lets it drift. Anchor it in one
   place: a signature default (``repo_root: Path = REPO_ROOT``), or better, defer to the
   callee/boundary that already owns it.

What this flags: ``NAME = NAME if NAME is not None else <FALLBACK>`` (or the reversed
``NAME = <FALLBACK> if NAME is None else NAME``), plain or annotated, where ``NAME`` is a
parameter of the enclosing function and ``<FALLBACK>`` is a ``Name`` / ``Attribute`` /
``Call`` (shared/external state, the drift-prone kind).

What it does not flag:

- Literal fallbacks (``[]`` / ``{}`` / ``""`` / ``0``) and no-arg empty-container
  constructors (``set()``, ``dict()`` ...): the None-sentinel mutable-default idiom.
- Binding to a new name (``_spawn = spawn if spawn is not None else subprocess.Popen``): the
  DI/test-seam shape that owns its default. Still discouraged at scale (see
  ``defender/CLAUDE.md``).
- ``x = x or <fallback>``: common, often fine, and separately buggy on falsy values; too noisy
  to lint. ``defender/CLAUDE.md`` covers it in prose.

Pre-existing sites are ratcheted via ``lint_unanchored_default_baseline.json``
(see scripts/lint/_baseline.py); the gate fails only on a new file+function+param triple,
where *function* is the dotted path of enclosing classes/defs (``Class.method``).
Suppress a deliberate site with ``# lint-default: ok — <reason>`` on the assignment.

Run from repo root:  python scripts/lint/lint_unanchored_default.py
Regenerate the baseline:  python scripts/lint/lint_unanchored_default.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _baseline import Finding, gate
from _astlib import ScanBlind, read_and_parse, source_files

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unanchored_default_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")

SUPPRESS = "lint-default: ok"


def _param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    a = func.args
    names = {arg.arg for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs)}
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    return names


def _coalesce_fallback(value: ast.expr, name: str) -> ast.expr | None:
    """If ``value`` is the self-referential None-coalesce of ``name`` —
    ``name if name is not None else F`` or ``F if name is None else name`` —
    return the fallback ``F``; else None."""
    if not isinstance(value, ast.IfExp):
        return None
    test = value.test
    if not (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and len(test.comparators) == 1
        and isinstance(test.left, ast.Name)
        and test.left.id == name
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is None
    ):
        return None
    if isinstance(test.ops[0], ast.IsNot):       # name if name is not None else F
        kept, fallback = value.body, value.orelse
    elif isinstance(test.ops[0], ast.Is):        # F if name is None else name
        kept, fallback = value.orelse, value.body
    else:
        return None
    if isinstance(kept, ast.Name) and kept.id == name:
        return fallback
    return None


def _assign_target(node: ast.AST) -> str | None:
    """The single ``Name`` target of an ``x = ...`` / ``x: T = ...`` statement."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    return None


_EMPTY_CONTAINER_BUILTINS = frozenset(
    {"list", "dict", "set", "tuple", "frozenset", "bytearray", "bytes"}
)


def _is_empty_container_call(node: ast.expr) -> bool:
    """A no-arg call to a built-in container constructor (``set()`` / ``dict()`` …): the
    literal-less form of the empty-container idiom, exempt like ``[]`` / ``{}``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _EMPTY_CONTAINER_BUILTINS
        and not node.args
        and not node.keywords
    )


def _is_named_fallback(fallback: ast.expr) -> bool:
    """Whether the fallback references shared/external state, rather than being a literal or
    empty container."""
    if _is_empty_container_call(fallback):
        return False
    return isinstance(fallback, (ast.Name, ast.Attribute, ast.Call))


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno
    end = getattr(node, "end_lineno", start) or start
    return any(
        SUPPRESS in lines[i - 1] for i in range(start, end + 1) if 0 < i <= len(lines)
    )


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    def visit(node: ast.AST, scope: tuple[str, ...], params: set[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = (*scope, node.name)
            params = _param_names(node)
        elif isinstance(node, ast.ClassDef):
            # A class body is its own namespace: `x = ...` binds a class attribute, not the
            # enclosing function's param. Push the class name so `Class.method` siblings
            # get distinct fingerprints.
            scope = (*scope, node.name)
            params = set()
        target = _assign_target(node)
        if target is not None and target in params:
            value = node.value  # AnnAssign without a RHS (`x: T`) has value None
            fallback = _coalesce_fallback(value, target) if value is not None else None
            if (
                fallback is not None
                and _is_named_fallback(fallback)
                and not _suppressed(node, lines)
            ):
                qual = ".".join(scope)
                fp = f"{rel}:{qual}:{target}"
                if fp not in seen:
                    seen.add(fp)
                    findings.append(
                        Finding(
                            fingerprint=fp,
                            display=(
                                f"{rel}:{node.lineno}: parameter {target!r} re-defaulted "
                                f"in-body in {qual}() — anchor the default in the "
                                f"signature ({target}: T = DEFAULT) or resolve it at the "
                                f"boundary"
                            ),
                        )
                    )
        for child in ast.iter_child_nodes(node):
            visit(child, scope, params)

    visit(tree, (), set())
    return findings


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    for name in source_files(DEFENDER, EXCLUDED_DIRS):
        path = DEFENDER / name
        text, tree = read_and_parse(path, path.relative_to(REPO_ROOT).as_posix())
        rel = path.relative_to(REPO_ROOT).as_posix()
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_unanchored_default baseline — a parameter re-defaulted in-body via a "
    "self-referential None-coalesce to a named/called fallback (the "
    "`x = x if x is not None else DEFAULT` smell: an Optional that's immediately "
    "made non-None, with the default knowledge duplicated across call sites). "
    "Anchor the default in the signature (`x: T = DEFAULT`) or resolve it once at "
    "the boundary. Fingerprint is file:function:param, function qualified by its "
    "enclosing classes/defs (no line number). CI fails "
    "on a triple absent here. Regenerate: python "
    "scripts/lint/lint_unanchored_default.py --update-baseline. Annotate "
    'intentional entries; "" = un-triaged debt to anchor.'
)


def main(argv: list[str]) -> int:
    if not DEFENDER.is_dir():
        print(f"defender/ not found at {DEFENDER}", file=sys.stderr)
        return 2
    # An unreadable file never entered the corpus. Exit 2: the gate could not run, which is
    # not "clean".
    try:
        findings = _scan()
    except ScanBlind as exc:
        print(f"lint_unanchored_default: {exc}", file=sys.stderr)
        return 2
    print(
        "Anchor an optional parameter's default in ONE place — a signature default "
        "(`x: T = DEFAULT`) or a single boundary resolution — instead of re-defaulting "
        "it in-body with `x = x if x is not None else DEFAULT`."
    )
    print("Suppress a deliberate site with `# lint-default: ok — <reason>`.")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_unanchored_default", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
