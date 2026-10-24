#!/usr/bin/env python3
"""Tenant-delivery fence (#1108 P3): two who-may-spell-what rules over production source.

* No production code spells `git-credentials`: delivery has no credential location on disk.
* The box's code-check file name (`CODE_CHECK_FILE` in `box/_spec.py`) is spelled exactly once
  in production source, where that constant defines it, and appears in no agent-facing prose (docs, templates and
  the shipped tenant knowledge trees' agent halves).

A spelling is any constant expression that folds to the name: a literal, a `+` of literals, an
f-string whose parts all fold, or a literal separator's `join` over literals. Computed spellings
(slicing, `chr`, a value read at run time) are out of reach. Docstrings are not spellings.

There is no baseline and no suppression: fix the use. A file that does not parse or decode is a
finding of exit 2, never skipped.

Run from anywhere:  python tooling/lint/lint_delivery_architecture.py [--root DIR]
Exit 0 = clean, 1 = a finding, 2 = could not scan.
"""
from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterator
from pathlib import Path

import _astlib

#: The checkout's own `defender/`, so a run from any directory or worktree sweeps itself.
DEFENDER = Path(__file__).resolve().parents[2] / "defender"

EXCLUDED_DIRS = ("tests", ".venv", "__pycache__")
_CREDENTIAL_NAME = "git-credentials"
_SPEC = "box/_spec.py"
_CHECK_CONSTANT = "CODE_CHECK_FILE"

#: Prose a model may be handed: every text file of these kinds under `defender/` except the
#: operator docs, the top-level `docs/` and the tests, plus the two shipped tenant knowledge trees' agent halves.
_PROSE_SUFFIXES = (".md", ".txt", ".yaml", ".yml", ".j2", ".jinja", ".tmpl")
_OPERATOR_DOCS = frozenset({"README.md", "CLAUDE.md", "AGENTS.md"})
_KNOWLEDGE_TREES = ("tenant-template", "tenant-fixture")


def _folded(node: ast.AST) -> str | None:
    """The string a constant expression spells, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded(node.left), _folded(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = [_folded(value) for value in node.values]
        return None if None in parts else "".join(parts)
    if isinstance(node, ast.FormattedValue) and node.format_spec is None \
            and node.conversion in (-1, ord("s")):
        return _folded(node.value)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"  # lint-ast-resolve: ok — str.join on a literal receiver; no binding to resolve
            and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple))):
        separator, parts = _folded(node.func.value), [_folded(e) for e in node.args[0].elts]
        return None if separator is None or None in parts else separator.join(parts)
    return None


def _non_docstring_nodes(tree: ast.Module) -> list[ast.AST]:
    docstrings = set()
    for node in ast.walk(tree):
        if (isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and node.body and isinstance(node.body[0], ast.Expr)):
            value = node.body[0].value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                docstrings.add(id(value))
    return [node for node in ast.walk(tree) if id(node) not in docstrings]


def _spellings(name: str, nodes: list[ast.AST]) -> Iterator[ast.AST]:
    """The outermost constant expressions among `nodes` that spell `name`."""
    hits = [node for node in nodes
            if not isinstance(node, ast.expr_context) and name in (_folded(node) or "")]
    inner = {id(child) for node in hits for child in ast.walk(node) if child is not node}
    yield from (node for node in hits if id(node) not in inner)


def _check_file_name(root: Path) -> str | None:
    """`CODE_CHECK_FILE`'s value, read from the box spec's module-level assignment."""
    spec = root / _SPEC
    if not spec.is_file():
        return None
    _text, tree = _astlib.read_and_parse(spec, _SPEC)
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == _CHECK_CONSTANT for t in stmt.targets):
            return _folded(stmt.value)
    return None


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    findings: list[str] = []
    check_name = _check_file_name(root)
    if check_name is None:
        findings.append(f"{_SPEC}: no module-level `{_CHECK_CONSTANT} = <literal>`; the "
                        "code-check name rule has nothing to hold")
    check_spelled: list[tuple[str, int, str]] = []
    for rel in _astlib.source_files(root, EXCLUDED_DIRS):
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        nodes = _non_docstring_nodes(tree)
        for node in _spellings(_CREDENTIAL_NAME, nodes):
            findings.append(f"{rel}:{node.lineno}: spells `{_CREDENTIAL_NAME}`: delivery has "
                            "no credential location on disk")
        if check_name is not None:
            check_spelled.extend((rel, node.lineno, _folded(node) or "")
                                 for node in _spellings(check_name, nodes))
    if check_name is not None:
        if len(check_spelled) != 1:
            findings.append(f"the code-check file name `{check_name}` must be spelled exactly "
                            f"once in production source (in {_SPEC}), found "
                            f"{len(check_spelled)}: {[f'{p}:{n}' for p, n, _v in check_spelled]}")
        for path in _agent_facing_text(root):
            if check_name.encode() in path.read_bytes():
                findings.append(f"{path.relative_to(root.parent).as_posix()}: agent-facing "
                                f"text names the box's check file `{check_name}`")
    return findings


def _agent_facing_text(root: Path) -> list[Path]:
    """The prose files a model may be handed."""
    found = [root / rel for rel in _astlib.source_files(
                 root, EXCLUDED_DIRS, suffixes=_PROSE_SUFFIXES,
                 prune=lambda d: d.parent == root and d.name == "docs")
             if rel.rsplit("/", 1)[-1] not in _OPERATOR_DOCS]
    for tree in _KNOWLEDGE_TREES:
        agent = root.parent / "knowledge" / tree / "agent"
        if agent.is_dir():
            found.extend(agent / rel for rel in
                         _astlib.source_files(agent, ("__pycache__",), suffixes=("",)))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_delivery_architecture] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_delivery_architecture] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
