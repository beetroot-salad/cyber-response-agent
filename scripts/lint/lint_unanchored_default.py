#!/usr/bin/env python3
"""Unanchored-default smell — flag a parameter re-defaulted *in the body* via a
self-referential None-coalesce to a named/called fallback, under ``defender/``.

The recurring shape (the "defensive one-liner") ::

    def f(repo_root: Path | None = None):
        repo_root = repo_root if repo_root is not None else REPO_ROOT   # ← flagged
        ...

Two things are wrong with it, and both are about a single source of truth:

1. The signature says ``repo_root: Path | None`` but the first body line makes it
   non-None — the ``Optional`` is a *lie*. The optionality should be parsed away
   at the boundary (resolve once at the entry/composition root, then pass the
   concrete value inward as a non-``Optional``), not re-validated at every layer.
2. The fallback (``REPO_ROOT`` / ``CATALOG_DIR`` / ``subscription_env()``) is
   *default knowledge*. Repeating ``else REPO_ROOT`` in N functions duplicates
   that knowledge and lets it drift. The fix is to anchor the default in ONE
   place: a signature default referencing the constant (``repo_root: Path =
   REPO_ROOT``) when the body needs a concrete value, or — better — defer to the
   single callee/boundary that already owns the default and don't re-default here.

What this flags: a statement ``NAME = NAME if NAME is not None else <FALLBACK>``
(or the reversed ``NAME = <FALLBACK> if NAME is None else NAME``), assignment or
annotated, where ``NAME`` is a parameter of the enclosing function AND
``<FALLBACK>`` is a ``Name`` / ``Attribute`` / ``Call`` — i.e. it references
shared/external state, the drift-prone kind.

What it deliberately does NOT flag:

- *Literal* fallbacks (``x = x if x is not None else []`` / ``{}`` / ``""`` /
  ``0``), and the empty-container *constructors* that have no literal form
  (``set()`` / ``dict()`` / ``list()`` / ``tuple()`` / ``frozenset()``). The
  None-sentinel into an empty container is the sanctioned idiom for a mutable
  default (``def f(items=[])`` is the famous bug); it carries no
  single-source-of-truth concern.
- Binding to a *new* name (``_spawn = spawn if spawn is not None else
  subprocess.Popen``). Resolving an optional param into a fresh local is the DI/
  test-seam shape that *owns* its default; the self-referential restriction
  leaves it alone. Still discouraged at scale — see ``defender/CLAUDE.md``.
- The ``x = x or <fallback>`` form. It is both common-and-often-fine and
  separately buggy on valid-falsy values (``0``/``""``/``[]``); linting it is too
  noisy. ``defender/CLAUDE.md`` covers it in prose.

The cure pattern (``param: T = DEFAULT`` in the signature, or no in-body default
at all) is NOT flagged — that is the anchored single source this gate pushes
toward.

Pre-existing sites are ratcheted via ``lint_unanchored_default_baseline.json``
(see scripts/lint/_baseline.py); the gate fails only on a NEW
file+function+param triple, where *function* is the dotted path of enclosing
classes/defs (``Class.method``) so two same-named siblings stay distinct.
Suppress a deliberate site with ``# lint-default: ok — <reason>`` on the
assignment.

Run from repo root:  python scripts/lint/lint_unanchored_default.py
Regenerate the baseline:  python scripts/lint/lint_unanchored_default.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _baseline import Finding, gate
from _astlib import ScanBlind, read_and_parse

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unanchored_default_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")

SUPPRESS = "lint-default: ok"


def _in_scope(path: Path) -> bool:
    rel = path.relative_to(DEFENDER)
    return not any(part in EXCLUDED_DIRS for part in rel.parts)


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
    """A no-arg call to a built-in container constructor (``set()`` / ``dict()`` /
    ``list()`` …) — the literal-less form of the sanctioned empty-container
    mutable-default idiom (a ``set`` has no literal). It carries no drift-prone
    default knowledge, so it is exempt just like ``[]`` / ``{}`` / ``""``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _EMPTY_CONTAINER_BUILTINS
        and not node.args
        and not node.keywords
    )


def _is_named_fallback(fallback: ast.expr) -> bool:
    """Fallback references shared/external state (the drift-prone kind), not a
    literal/empty-container (the sanctioned mutable-default idiom). An empty
    container built via its constructor (``set()`` / ``dict()`` / ``list()``) is
    the literal-less form of that idiom and is likewise exempt."""
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
            # A class body is its own namespace: ``x = ...`` binds a class
            # attribute, not the enclosing function's param. Drop params so a
            # same-named class attribute isn't misread as an in-body re-default
            # (the new-name shape the gate exempts), and push the class name so
            # two ``Class.method`` siblings don't share one fingerprint.
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
    for path in sorted(DEFENDER.rglob("*.py")):
        if not _in_scope(path):
            continue
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
    # A file inside the scan scope that could not be read or parsed never entered the corpus,
    # so a violation could sit in it and this gate would still print 0 findings. Exit 2 — the
    # gate could not run, which is categorically not "clean" (#618/#621/#652).
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
