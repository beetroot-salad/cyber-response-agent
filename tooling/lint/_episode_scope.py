"""Local-value resolution and the walk owner, shared by the episode-path lints and their censuses.

A census that matches a spelling is defeated by binding the value to another name first
(`ep = episode_id; f"{ep}-{label}"`), so `spells` follows a name through the assignments visible in
its scope. `WALK_OWNER` is the ONE definition of the repository's walk owner (relative to
`defender/`; a folder prefix ends in `/`)."""
from __future__ import annotations

import ast
from collections.abc import Mapping

def bound_values(scope: ast.AST) -> dict[str, list[ast.expr]]:
    """`{name: [values]}`: every value `scope`'s OWN statements bind a plain name to — `x = v`."""
    out: dict[str, list[ast.expr]] = {}

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                                  ast.ClassDef)):
                continue
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        out.setdefault(target.id, []).append(child.value)
            elif (isinstance(child, ast.AnnAssign) and child.value is not None
                  and isinstance(child.target, ast.Name)) or isinstance(child, ast.NamedExpr):
                out.setdefault(child.target.id, []).append(child.value)
            walk(child)

    walk(scope)
    return out


def spells(node: ast.AST, needle: str, values: Mapping[str, list[ast.expr]],
           _seen: frozenset[str] = frozenset()) -> bool:
    """Recognize a source spelling directly or through locally bound names and attributes."""
    if needle in ast.unparse(node):
        return True
    keys = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    keys |= {"." + n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
    return any(spells(value, needle, values, _seen | {key})
               for key in sorted(keys - _seen) for value in values.get(key, ()))


def attribute_values(tree: ast.AST) -> dict[str, list[ast.expr]]:
    """`{".<attr>": [values]}` for every `<anything>.<attr> = value` (and annotated) assignment."""
    out: dict[str, list[ast.expr]] = {}
    for node in ast.walk(tree):
        targets = (node.targets if isinstance(node, ast.Assign)
                   else [node.target] if isinstance(node, ast.AnnAssign) and node.value else [])
        for target in targets:
            if isinstance(target, ast.Attribute):
                out.setdefault("." + target.attr, []).append(node.value)
    return out


def scoped_nodes(tree: ast.AST) -> list[tuple[ast.AST, dict[str, list[ast.expr]]]]:
    """Pair AST nodes with the assignments visible in their local scope."""
    out: list[tuple[ast.AST, dict[str, list[ast.expr]]]] = []
    attrs = attribute_values(tree)

    def walk(node: ast.AST, values: dict[str, list[ast.expr]]) -> None:
        for child in ast.iter_child_nodes(node):
            out.append((child, values))
            inner = ({**bound_values(child), **attrs} if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) else values)
            walk(child, inner)

    walk(tree, {**bound_values(tree), **attrs})
    return out


#: The walk's owner: the run repository and the episode handle. Cover the whole owner package as
#: it gains modules.
WALK_OWNER = ("records/", "episodes/_episode_handle.py")


def owned(rel: str) -> bool:
    """Is `rel` (relative to `defender/`) in the walk's owner?"""
    return any(rel == own or (own.endswith("/") and rel.startswith(own)) for own in WALK_OWNER)
# Observe process opens directly so calls outside an injected seam remain visible.
