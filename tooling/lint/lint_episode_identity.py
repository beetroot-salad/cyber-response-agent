#!/usr/bin/env python3
"""Episode identity fence (#1187): ids carry no composed meaning, and the folders and file names of
an episode have one owner.

Three rules over production source, all static (nothing is imported):

* `id-meaning`. No production source composes, derives or bounds a run or episode id by meaning:
  an `episode_id` joined to a `-` (f-string, `+`, `join`, `format`, `%`, directly or through a
  local alias or attribute), a call of a function that does so, the banned id deriver functions
  and the id-length constant (called, passed around, re-exported by name, or defined), and
  `RunId.mint` given a label or clock.
* `owner-folders`. The walk owner (`records/`, the episode handle) makes no folder by its
  PATH (`os.makedirs`, `os.mkdir` without `dir_fd`, `Path(...).mkdir`); it goes through a held
  root.
* `roster-name`. The arm roster's file name is spelled only in the episode layout
  (`records/_episode_paths.py`), never as a string literal elsewhere (docstrings aside).

There is no baseline and no inline suppression. A file that does not parse or decode is ScanBlind
(exit 2), never skipped.

Run from anywhere:  python tooling/lint/lint_episode_identity.py [--root DIR]
Exit 0 = clean, 1 = a finding, 2 = could not scan.
"""
from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

import _astlib
from _episode_scope import bound_values, owned, scoped_nodes, spells

#: The checkout's own `defender/`, so a run from any directory or worktree sweeps itself.
DEFENDER = Path(__file__).resolve().parents[2] / "defender"

#: The arm roster's file name, and the one module that may spell it.
ROSTER_NAME = "arms.json"
ROSTER_OWNER = "records/_episode_paths.py"

#: Functions production must neither call nor pass around (C1 of the design): the stamp-label
#: minter, the `-n<message>` episode-id deriver, the held-out folder-name matcher, and #1257's
#: composer of an arm id. A *definition* alone is not flagged: the contract is "nothing calls".
BANNED_FUNCTIONS = frozenset({"mint_run_id", "episode_id_for", "_claimed_slug", "arm_run_id_for",
                              "world_token_for", "episode_token_for"})
#: The 206-byte bound's constant: neither defined nor read.
BANNED_CONSTANT = "RUN_ID_MAX_BYTES"

@dataclass(frozen=True, order=True)
class Hit:
    """One site the census found: where, what shape, and the spelling or origin."""

    rel: str
    line: int
    kind: str
    what: str

    def __str__(self) -> str:
        return f"{self.rel}:{self.line} {self.kind} {self.what}"


def census(root: Path, *, skip_tests: bool = True) -> list[Hit]:
    """Find production sites that derive meaning from run or episode identifiers."""
    root = Path(root)
    excluded = (".venv", "__pycache__", "node_modules") + (("tests",) if skip_tests else ())
    hits: list[Hit] = []
    parsed = []
    for rel in _astlib.source_files(root, excluded):
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        module, package = _astlib.module_and_package(rel, root="defender")
        parsed.append((rel, tree, _astlib.module_env(tree, module, package)))
    composers = _composers([tree for _rel, tree, _env in parsed])
    for rel, tree, env in parsed:
        with _astlib.scan_guard(rel):
            for node, values in scoped_nodes(tree):
                hits.extend(_hits_at(node, env, rel, values))
                hits.extend(_composer_calls(node, rel, values, composers))
    return sorted(set(hits))


def _joined_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[int, str]:
    """Find function parameters joined to separators in identifier compositions."""
    args = [a.arg for a in (*func.args.posonlyargs, *func.args.args)]
    values = bound_values(func)

    def reaches(node: ast.AST, name: str, seen: frozenset[str] = frozenset()) -> bool:
        for n in (x for x in ast.walk(node) if isinstance(x, ast.Name)):
            if n.id == name or (n.id not in seen and any(
                    reaches(v, name, seen | {n.id}) for v in values.get(n.id, ()))):
                return True
        return False

    out: dict[int, str] = {}
    for node in ast.walk(func):
        fields: list[ast.AST] = []
        if isinstance(node, ast.JoinedStr):
            fields = [f.value for f, after in zip(node.values, node.values[1:], strict=False)
                      if isinstance(f, ast.FormattedValue) and isinstance(after, ast.Constant)
                      and isinstance(after.value, str) and after.value.startswith("-")]
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and isinstance(
                node.right, ast.Constant) and isinstance(node.right.value, str) and (
                node.right.value.startswith("-")):
            fields = [_rightmost(node.left)]
        offset = 1 if args[:1] in (["self"], ["cls"]) else 0
        out.update({index - offset: name for index, name in enumerate(args)
                    if index >= offset and any(reaches(f, name) for f in fields)})
    return out


def _composers(trees: list[ast.Module]) -> dict[str, dict[int, str]]:
    """`{function or method name: {call position: parameter}}` over every file: the functions `_joined_params` finds."""
    out: dict[str, dict[int, str]] = {}
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                    joined := _joined_params(node)):
                out.setdefault(node.name, {}).update(joined)
    return out


def _composer_calls(node: ast.AST, rel: str, values: dict,
                    composers: dict[str, dict[int, str]]) -> list[Hit]:
    """Find composing calls whose joined parameter receives an episode identifier."""
    if not isinstance(node, ast.Call):
        return []
    func = node.func
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(
        func, ast.Attribute) else None
    joined = composers.get(name or "")
    if not joined:
        return []
    handed = [(i, a) for i, a in enumerate(node.args)] + [
        (next((i for i, p in joined.items() if p == k.arg), -1), k.value)
        for k in node.keywords]
    if any(i in joined and _names_episode_id(a, values) for i, a in handed):
        return [Hit(rel, node.lineno, "composer", ast.unparse(node))]
    return []


def _banned_origin(origin: str | None) -> str | None:
    """The banned name an import-resolved origin ends in, if any."""
    last = origin.rsplit(".", 1)[-1] if origin else None
    return last if last in BANNED_FUNCTIONS or last == BANNED_CONSTANT else None


def _hits_at(node: ast.AST, env, rel: str, values: dict) -> list[Hit]:
    return [*_composed(node, rel, values), *_concatenated(node, rel, values),
            *_banned_use(node, env, rel), *_banned_text(node, rel),
            *_labelled_mint(node, env, rel)]


def _names_episode_id(node: ast.AST, values: dict) -> bool:
    """Recognize episode_id directly or through a locally bound alias."""
    return spells(node, "episode_id", values)


def _rightmost(node: ast.expr) -> ast.expr:
    """The last operand of a `+` chain (`a + b + c` is `(a + b) + c`)."""
    while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        node = node.right
    return node


def _concatenated(node: ast.AST, rel: str, values: dict) -> list[Hit]:
    """`concat` hits: an `episode_id` joined to a `-` by `+`, `str.join`, `str.format` or `%`."""
    def text(n: ast.AST) -> str | None:
        return n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        right = text(node.right)
        if right is not None and right.startswith("-") and _names_episode_id(
                _rightmost(node.left), values):
            return [Hit(rel, node.lineno, "concat", ast.unparse(node))]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        fmt = text(node.left)
        if fmt is not None and "-%" in fmt and _names_episode_id(node.right, values):
            return [Hit(rel, node.lineno, "concat", ast.unparse(node))]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        fmt = text(node.func.value)
        named = any(_names_episode_id(a, values) for a in (*node.args, *node.keywords))
        if fmt == "-" and node.func.attr == "join" and named:
            return [Hit(rel, node.lineno, "concat", ast.unparse(node))]
        if fmt is not None and "}-" in fmt and node.func.attr == "format" and named:
            return [Hit(rel, node.lineno, "concat", ast.unparse(node))]
    return []


def _composed(node: ast.AST, rel: str, values: dict) -> list[Hit]:
    """`fstring` hits: a replacement field naming `episode_id` (directly or through a local alias) followed at once by a `-`."""
    out: list[Hit] = []
    if isinstance(node, ast.JoinedStr):
        for field, after in zip(node.values, node.values[1:], strict=False):
            if (isinstance(field, ast.FormattedValue)
                    and isinstance(after, ast.Constant) and isinstance(after.value, str)
                    and after.value.startswith("-")
                    and _names_episode_id(field.value, values)):
                out.append(Hit(rel, node.lineno, "fstring", "{" + ast.unparse(field.value) + "}-"))
    return out


def _banned_use(node: ast.AST, env, rel: str) -> list[Hit]:
    """`ref` hits (a banned function or the constant used, however it is reached) and the constant's `def`."""
    out: list[Hit] = []
    if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
        scope = env.scope_of.get(node, env)
        banned = _banned_origin(_astlib.origin(node, env))
        if banned is None and isinstance(node, ast.Name) and node.id in scope.own_defs and (
                node.id in BANNED_FUNCTIONS):
            banned = node.id
        if banned is not None:
            out.append(Hit(rel, node.lineno, "ref", banned))
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and (
            node.id == BANNED_CONSTANT):
        out.append(Hit(rel, node.lineno, "def", node.id))
    return out


def _banned_text(node: ast.AST, rel: str) -> list[Hit]:
    """`str` hits: a banned name as a string constant (an `__all__` re-export)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and (
            node.value in BANNED_FUNCTIONS or node.value == BANNED_CONSTANT):
        return [Hit(rel, node.lineno, "str", node.value)]
    return []


def _labelled_mint(node: ast.AST, env, rel: str) -> list[Hit]:
    """Find RunId.mint calls that pass a label or clock, including import aliases."""
    if isinstance(node, ast.Call) and (node.args or node.keywords):
        called = _astlib.callee(node, env)
        func = node.func
        if (called is None and isinstance(func, ast.Call) and _astlib.callee(func, env) == (
                "builtins.getattr") and len(func.args) == 2
                and isinstance(func.args[1], ast.Constant) and func.args[1].value == "mint"):
            owner = _astlib.origin(func.args[0], env)
            called = f"{owner}.mint" if owner is not None else None
        if called is not None and called.endswith("RunId.mint"):
            return [Hit(rel, node.lineno, "mint-args", called)]
    return []


def folders_made_by_path(root: Path) -> list[str]:
    """Every call in the walk owner's source under `root` that makes a folder by its PATH."""
    found = []
    for rel in _astlib.source_files(root, (".venv", "__pycache__", "node_modules", "tests")):
        if not owned(rel):
            continue
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        module, package = _astlib.module_and_package(rel, root="defender")
        env = _astlib.module_env(tree, module, package)
        for node, values in scoped_nodes(tree):
            if not isinstance(node, ast.Call):
                continue
            called = _astlib.callee(node, env)
            path_maker = called == "os.makedirs" or (
                called == "os.mkdir" and not _astlib.has_kw(node, "dir_fd"))
            if not path_maker and called is None and isinstance(
                    node.func, ast.Attribute) and node.func.attr == "mkdir":
                path_maker = (spells(node.func.value, "Path(", values)
                              or _astlib.has_kw(node, "parents") or _astlib.has_kw(node, "exist_ok"))
            if path_maker:
                found.append(f"{rel}:{node.lineno} {ast.unparse(node)}")
    return found


def roster_name_spellings(root: Path) -> list[str]:
    """Find arms.json string literals outside docstrings in production source."""
    hits: list[str] = []
    for rel in _astlib.source_files(root, (".venv", "__pycache__", "node_modules", "tests")):
        if rel == "records/_episode_paths.py":
            continue
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        with _astlib.scan_guard(rel):
            docstrings = {
                id(node.body[0].value) for node in ast.walk(tree)
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef))
                and node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)}
            hits.extend(f"{rel}:{node.lineno}" for node in ast.walk(tree)
                        if isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and ROSTER_NAME in node.value and id(node) not in docstrings)
    return sorted(hits)


def id_meaning(root: Path) -> list[str]:
    return [f"id-meaning: {hit}" for hit in census(root)]


def owner_folders(root: Path) -> list[str]:
    return [f"owner-folders: the walk owner makes a folder by its path: {line}"
            for line in folders_made_by_path(root)]


def roster_name(root: Path) -> list[str]:
    return [f"roster-name: {ROSTER_NAME} is spelled outside its owner at {where}"
            for where in roster_name_spellings(root)]


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    return [*id_meaning(root), *owner_folders(root), *roster_name(root)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_episode_identity] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_episode_identity] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
