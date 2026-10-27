#!/usr/bin/env python3
"""Store ownership fence (#1324): every session-store open has an owner that closes it.

A store handle left to the garbage collector stays open until collection happens to run, and
SQLite then deletes the store's `-wal`/`-shm` files at that unpredictable moment. The run once
closed its store on three of its six exits. So a call to `open_store`, `open_store_for_read`,
`open_source_store` or `source_store_if_any` (a bare name or an attribute) must be one of:

* a `with` item, directly or wrapped in `contextlib.closing(...)` / `closing(...)`;
* the argument of an `ExitStack.enter_context(...)`;
* returned straight to the caller (`return open_store(...)`, or a lambda's body), which hands
  ownership on — the caller is then the opener as far as this fence is concerned;
* closed on the spot (`open_store_for_read(p).close()`);
* assigned to a name the same function then opens a `with` on (`with store:` or
  `with closing(store):`) — the shape an opener that may return `None` needs.

Anything else — above all `handle = open_store(...)` closed by hand later — is a finding. The
runtime half of the rule is `UnclosedStoreWarning`, which the test suite turns into an error.

Suppress an intentional site with `# lint-store-ownership: ok — <reason>` on the call. No
baseline.

Run from anywhere:  python tooling/lint/lint_store_ownership.py [--root DIR]
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

EXCLUDED_DIRS = (".venv", "__pycache__")

OPENERS = frozenset({"open_store", "open_store_for_read", "open_source_store",
                     "source_store_if_any"})

SUPPRESS = "lint-store-ownership: ok"


def _called_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _with_names(scope: ast.AST) -> set[str]:
    """The names `scope` opens a `with` on, bare or wrapped in `closing(...)`."""
    names: set[str] = set()
    for node in ast.walk(scope):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        for item in node.items:
            expr = item.context_expr
            if isinstance(expr, ast.Call) and _called_name(expr) == "closing" and expr.args:
                expr = expr.args[0]
            if isinstance(expr, ast.Name):
                names.add(expr.id)
    return names


def _enclosing_scope(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.AST | None:
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return node
    return None


def _owned(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    parent = parents.get(call)
    if (isinstance(parent, ast.Assign) and len(parent.targets) == 1
            and isinstance(parent.targets[0], ast.Name)):
        scope = _enclosing_scope(parent, parents)
        return scope is not None and parent.targets[0].id in _with_names(scope)
    # `closing(open_store(...))` is judged by where the `closing` sits.
    if isinstance(parent, ast.Call) and call in parent.args and _called_name(parent) == "closing":
        call, parent = parent, parents.get(parent)
    if isinstance(parent, ast.Call) and call in parent.args:
        return _called_name(parent) == "enter_context"
    if isinstance(parent, ast.withitem):
        return parent.context_expr is call
    if isinstance(parent, ast.Return):
        return True
    if isinstance(parent, ast.Lambda):
        return parent.body is call
    if isinstance(parent, ast.Attribute) and parent.attr == "close":
        return isinstance(parents.get(parent), ast.Call)
    return False


def _suppressed(call: ast.Call, lines: list[str]) -> bool:
    end = call.end_lineno or call.lineno
    return any(SUPPRESS in lines[i - 1] for i in range(call.lineno, end + 1) if i <= len(lines))


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for name in _astlib.source_files(root, EXCLUDED_DIRS):
        path = root / name
        text, tree = _astlib.read_and_parse(path, name)
        lines = text.split("\n")  # not splitlines(): it also breaks on \f and \u2028, which ast does not
        parents = _parents(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and _called_name(node) in OPENERS
                    and not _owned(node, parents) and not _suppressed(node, lines)):
                findings.append(
                    f"{root.name}/{name}:{node.lineno}: `{_called_name(node)}(...)` has no "
                    "owner: open it in a `with`, hand it to `enter_context`, or return it")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_store_ownership] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_store_ownership] {len(found)} finding(s).")
    if found:
        print("Suppress an intentional site with `# lint-store-ownership: ok — <reason>`.")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
