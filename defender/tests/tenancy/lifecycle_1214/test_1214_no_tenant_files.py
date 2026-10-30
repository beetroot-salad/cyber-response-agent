"""#1214 O6: production code neither reads nor writes `tenant.json` or `publish-status.json`.

No production module spells either name, `tenancy/_tenant.py` (the row's former owner) included: the lab's old row
file is deleted by hand when it moves, not by code (DC-8, SK-6).
"""
from __future__ import annotations

import ast
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[3]
#: The row's former owner: held to the same rule as every other module.
FORMER_OWNER = "tenancy/_tenant.py"
ROW, STATUS = "tenant.json", "publish-status.json"
#: Names whose use outside the owner is a read or write of the retired row (O6).
ROW_READERS = {"ROW_NAME", "retire_row", "row_path", "create_tenant", "require_tenant", "read_forge_binding",
               "refuse_foreign_data_root", "ForgeBinding"}


def _production_sources() -> list[Path]:
    return [p for p in DEFENDER.rglob("*.py")
            if "tests" not in p.relative_to(DEFENDER).parts and ".venv" not in p.parts]


def _strings(tree: ast.AST) -> list[tuple[int, str]]:
    """Every string constant of `tree` except docstrings: (line, value)."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return [(n.lineno, n.value) for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]


def _spells(value: str, name: str) -> bool:
    return value == name or value.endswith("/" + name)


def _rel(path: Path) -> str:
    return path.relative_to(DEFENDER).as_posix()


def test_no_production_module_spells_tenant_json():
    """No production module spells the row's file name, its former owner included (O6, SK-6)."""
    sources = _production_sources()
    assert any(_rel(p) == FORMER_OWNER for p in sources)  # control: the census sees the former owner and production
    found = [f"{_rel(p)}:{n}" for p in sources
             for n, value in _strings(ast.parse(p.read_text(encoding="utf-8"))) if _spells(value, ROW)]
    assert found == []


def test_no_production_module_spells_publish_status_json():
    """Publish status lives in PostgreSQL: not even the owner names the file (O6)."""
    found = [f"{_rel(p)}:{n}" for p in _production_sources()
             for n, value in _strings(ast.parse(p.read_text(encoding="utf-8"))) if _spells(value, STATUS)]
    assert found == []


def test_no_production_module_reads_the_row_through_its_names():
    """The row's readers, writers and remover are gone: no import or use of them anywhere (O6)."""
    hits = []
    for path in _production_sources():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.Attribute):
                names = [node.attr]
            elif isinstance(node, ast.Name):
                names = [node.id]
            hits += [f"{_rel(path)}:{node.lineno}:{n}" for n in names if n in ROW_READERS]
    assert hits == []
