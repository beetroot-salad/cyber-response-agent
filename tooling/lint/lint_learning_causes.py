#!/usr/bin/env python3
"""Learning causes fence (#1537): one owner of the closed cause lists, and every cause checked against them.

`defender/records/learning_causes.py` owns why a learning item or batch is set aside: the `ItemCause` and `BatchCause`
lists, and the `Why` value that carries a cause with its detail. Two shapes undo that, and each is a finding:

  - second-list      a tuple, list or set literal, or a `Literal[...]`, in product code that holds three or more of the
                     cause names: a second copy of a list, which drifts from the owner (a cause added to one copy and
                     not the other passes the type checker and fails at a database check, or the other way round).
  - unchecked-why    a bare `Why(...)` built in product code. Passed to an untyped callee (the tick's store handle is
                     `Any`), it takes any string as its cause. `Why.item(...)` and `Why.batch(...)` take only their
                     table's list, so a misspelt cause is a type error wherever the value goes.

The owner's own module and the migrations (each keeps a frozen copy of the list it created the checks from) are out of
scope; so are the tests. The cause names are read from the owner's source, not copied here. There is no baseline and no
suppression. A file that does not parse or decode, or an owner with no lists in it, is exit 2, never skipped.

Run from anywhere:  python tooling/lint/lint_learning_causes.py [--root DIR]
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

OWNER = "records/learning_causes.py"
EXCLUDED_DIRS = ("tests", ".venv", "__pycache__")
_LISTS = ("ItemCause", "BatchCause")
_WHY = frozenset({"defender.records.learning_causes.Why", "defender.learning_store.Why"})
#: How many cause names one literal must hold to be a copy of a list: two can be an ordinary pair of values.
_COPY_AT = 3


def cause_names(root: Path) -> frozenset[str]:
    """Every name in the owner's `ItemCause` and `BatchCause` Literals."""
    _text, tree = _astlib.read_and_parse(root / OWNER, OWNER)
    names: set[str] = set()
    found: set[str] = set()
    for stmt in tree.body:
        if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id in _LISTS and isinstance(stmt.value, ast.Subscript)):
            found.add(stmt.targets[0].id)
            names.update(_strings(stmt.value.slice))
    if found != set(_LISTS) or not names:
        raise _astlib.ScanBlind(f"{OWNER} defines no {' and '.join(_LISTS)} Literals to read the cause names from")
    return frozenset(names)


def _strings(node: ast.AST) -> list[str]:
    elts = node.elts if isinstance(node, (ast.Tuple, ast.List, ast.Set)) else [node]
    return [e.value for e in elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    causes = cause_names(root)
    findings: list[str] = []
    for rel in _astlib.source_files(root, EXCLUDED_DIRS):
        if rel == OWNER or rel.startswith("migrations/versions/"):
            continue
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        env = _astlib.module_env(tree)
        for node in ast.walk(tree):
            # A `Literal[...]` of several names is its slice's tuple, met here like any other.
            if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                held = causes.intersection(_strings(node))
                if len(held) >= _COPY_AT:
                    findings.append(f"{rel}:{node.lineno}: second-list: a literal holds {len(held)} learning causes "
                                    f"({', '.join(sorted(held)[:3])}, ...): import the lists from {OWNER}")
            elif isinstance(node, ast.Call) and _astlib.callee(node, env) in _WHY:
                findings.append(f"{rel}:{node.lineno}: unchecked-why: a bare `Why(...)` takes any cause; build it "
                                "with `Why.item(...)` or `Why.batch(...)`")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_learning_causes] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_learning_causes] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
