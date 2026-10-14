"""O8/A5/P3: one credential location owner, tenant delivery remains dormant."""
from __future__ import annotations

import ast

from ._support import DEFENDER, target

_OWNER = "learning/author/tenant_delivery.py"


def production_trees():
    for path in sorted(DEFENDER.rglob("*.py")):
        relative = path.relative_to(DEFENDER)
        if any(part in {"tests", ".venv", "__pycache__"} for part in relative.parts):
            continue
        yield relative.as_posix(), ast.parse(path.read_text(encoding="utf-8"))


def non_docstring_nodes(tree):
    docstrings = set()
    for node in ast.walk(tree):
        if (isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and node.body and isinstance(node.body[0], ast.Expr)):
            value = node.body[0].value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                docstrings.add(id(value))
    return [node for node in ast.walk(tree) if id(node) not in docstrings]


def test_git_credential_location_has_one_production_owner():
    target()  # A zero-implementation tree is not a successful ownership census.
    found = []
    for path, tree in production_trees():
        parents = {id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for node in non_docstring_nodes(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if "git-credentials" not in node.value:
                continue
            if path == "_tenant.py":
                # The layout may name the file; it cannot become a second credential reader.
                parent = parents[id(node)]
                assert (isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Div)) or (
                    isinstance(parent, ast.Call) and isinstance(parent.func, ast.Attribute)
                    and parent.func.attr == "joinpath"  # lint-ast-resolve: ok — path-construction spelling census; no callable-binding claim
                ), f"{path}:{node.lineno}: layout credential literal must only construct a path"
            else:
                assert path == _OWNER, f"{path}:{node.lineno}: extra forge credential location owner"
            found.append(path)
    assert found, "the single credential location must be explicit in its owning module"


def test_tenant_delivery_has_no_production_callers_until_p4():
    target()
    uses = []
    for path, tree in production_trees():
        if path == _OWNER:
            continue
        for node in non_docstring_nodes(tree):
            names = []
            if isinstance(node, ast.Name):
                names.append(node.id)
            elif isinstance(node, ast.Attribute):
                names.append(node.attr)
            elif isinstance(node, ast.alias):
                names.extend((node.name, node.asname or ""))  # lint-ast-resolve: ok — dormant-symbol lexical ban includes aliases, not binding resolution
            elif isinstance(node, ast.ImportFrom):
                names.append(node.module or "")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                names.append(node.value)
            if any(name == "TenantDelivery" or "tenant_delivery" in name.split(".") for name in names):
                uses.append(f"{path}:{node.lineno}")
    assert uses == [], f"P3 delivery is dormant; production wiring belongs to P4: {uses}"
