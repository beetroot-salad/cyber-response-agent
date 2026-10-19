"""Explicit host identities, package ownership and dormant tenant delivery."""
from __future__ import annotations

import ast

from ._support import DEFENDER, target

_OWNER = "learning/author/version_control/"


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


def test_delivery_has_no_disk_credential_location():
    target()
    assert list(_spellings("git-credentials")) == []


def test_tenant_delivery_has_no_production_callers_until_p4():
    target()
    uses = []
    for path, tree in production_trees():
        if path.startswith(_OWNER):
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


#: Prose a model may be handed: every text file of these kinds under `defender/` except the
#: operator docs and the tests, plus the two shipped tenant knowledge trees' agent halves.
_PROSE_SUFFIXES = frozenset({".md", ".txt", ".yaml", ".yml", ".j2", ".jinja", ".tmpl"})
_OPERATOR_DOCS = frozenset({"README.md", "CLAUDE.md", "AGENTS.md"})


def _agent_facing_text():
    for path in sorted(DEFENDER.rglob("*")):
        relative = path.relative_to(DEFENDER)
        if (relative.parts[0] in {"docs", "tests", ".venv"} or "__pycache__" in relative.parts
                or path.name in _OPERATOR_DOCS or path.suffix not in _PROSE_SUFFIXES
                or not path.is_file()):
            continue
        yield path
    for tree in ("tenant-template", "tenant-fixture"):
        yield from (p for p in sorted((DEFENDER.parent / "knowledge" / tree / "agent").rglob("*"))
                    if p.is_file())


def _folded(node):
    """The string a constant expression spells, else None: a literal, `+` of spelled parts, an
    f-string whose parts all spell, a literal separator's join over literal elements. Computed
    spellings beyond these (slicing, `chr`, a value read at run time) are out of a census's reach."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded(node.left), _folded(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = [_folded(value) for value in node.values]
        return None if None in parts else "".join(parts)
    if isinstance(node, ast.FormattedValue) and node.format_spec is None and node.conversion in (-1, ord("s")):
        return _folded(node.value)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"  # lint-ast-resolve: ok — str.join on a literal receiver; no binding to resolve
            and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple))):
        separator, parts = _folded(node.func.value), [_folded(e) for e in node.args[0].elts]
        return None if separator is None or None in parts else separator.join(parts)
    return None


def _spellings(name):
    """Every outermost constant expression in production source that spells `name`."""
    for path, tree in production_trees():
        hits = [node for node in non_docstring_nodes(tree)
                if not isinstance(node, ast.expr_context) and name in (_folded(node) or "")]
        inner = {id(child) for node in hits for child in ast.walk(node) if child is not node}
        yield from ((path, node.lineno, _folded(node)) for node in hits if id(node) not in inner)


def test_code_check_file_name_is_owned_by_the_box_package_and_absent_from_agent_text():
    from defender import box
    from defender.box import _oracle
    name = box.CODE_CHECK_FILE  # a zero-implementation tree is not a successful census
    spelled = sorted(_spellings(name))
    assert len(spelled) == 1, f"the check file's name must be spelled exactly once: {spelled}"
    path, _line, value = spelled[0]
    assert path.startswith("box/"), spelled
    assert value == name, spelled
    assert [f for f in _oracle.RUNNER_FILES if name in f] == [f"defender/{name}"]
    named = [str(p.relative_to(DEFENDER.parent)) for p in _agent_facing_text()
             if name.encode() in p.read_bytes()]
    assert named == [], f"agent-facing text names the box's check file: {named}"
