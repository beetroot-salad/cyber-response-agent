"""#1214 O6: production code neither reads nor writes `tenant.json` or `publish-status.json`.

Only the owner (`tenancy/_tenant.py`) may spell `tenant.json` (DC-8, SK-6), and only inside `retire_row`,
the one function adoption calls to delete it. `publish-status.json` is spelled nowhere.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[3]
OWNER = "tenancy/_tenant.py"
ROW, STATUS = "tenant.json", "publish-status.json"
#: Names whose use outside the owner is a read or write of the retired row (O6).
ROW_READERS = {"ROW_NAME", "row_path", "create_tenant", "require_tenant", "read_forge_binding",
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


def test_no_production_module_outside_the_owner_spells_tenant_json():
    """No production module but the owner spells the row's file name (O6, SK-6)."""
    sources = _production_sources()
    assert any(_rel(p) == OWNER for p in sources)  # control: the census sees the owner and production
    found = [f"{_rel(p)}:{n}" for p in sources if _rel(p) != OWNER
             for n, value in _strings(ast.parse(p.read_text(encoding="utf-8"))) if _spells(value, ROW)]
    assert found == []


def test_no_production_module_spells_publish_status_json():
    """Publish status lives in PostgreSQL: not even the owner names the file (O6)."""
    found = [f"{_rel(p)}:{n}" for p in _production_sources()
             for n, value in _strings(ast.parse(p.read_text(encoding="utf-8"))) if _spells(value, STATUS)]
    assert found == []


def test_the_owner_touches_the_row_only_to_retire_it():
    """Inside the owner every use of the row-name constant or literal sits in `retire_row`; its one definition is no use (O6, DC-8)."""
    tree = ast.parse((DEFENDER / OWNER).read_text(encoding="utf-8"))
    functions = {f.name: f for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "retire_row" in functions, "the owner must expose the one retirement function adoption calls"
    inside = {id(n) for n in ast.walk(functions["retire_row"])}
    definition = {id(a.value) for a in ast.walk(tree) if isinstance(a, (ast.Assign, ast.AnnAssign)) and a.value
                  and any(isinstance(t, ast.Name) and t.id == "ROW_NAME"
                          for t in (a.targets if isinstance(a, ast.Assign) else [a.target]))}
    uses = [n for n in ast.walk(tree) if id(n) not in definition  # the module constant's own definition is no use
            and ((isinstance(n, ast.Name) and n.id == "ROW_NAME" and isinstance(n.ctx, ast.Load))
                 or (isinstance(n, ast.Constant) and isinstance(n.value, str) and _spells(n.value, ROW)))]
    docstring_lines = {f.body[0].lineno for f in functions.values()
                       if f.body and isinstance(f.body[0], ast.Expr) and isinstance(f.body[0].value, ast.Constant)}
    outside = sorted(n.lineno for n in uses if id(n) not in inside and n.lineno not in docstring_lines)
    assert outside == []
    assert any(id(n) in inside for n in uses), "retire_row never names the row it retires"


def test_no_production_module_outside_the_owner_reads_the_row_through_its_names():
    """The row's readers and writers are gone: no import or attribute use of them outside the owner (O6)."""
    hits = []
    for path in _production_sources():
        if _rel(path) == OWNER:
            continue
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


def test_retire_row_removes_a_regular_file_reports_an_absent_one_and_refuses_a_link(tmp_path):
    """`retire_row(data_root, T)`: True and gone for a regular file; False when absent; a link at the row path is
    refused and its target survives (GAP-Re-3, O6, O9). The refusal's type is the implementer's."""
    from defender.tenancy import retire_row

    tenant = "7f3c1a52-9d4e-4b8a-a1c6-2e5d8b9f0c13"
    folder = tmp_path / tenant
    folder.mkdir()
    assert retire_row(tmp_path, tenant) is False  # absent
    (folder / "tenant.json").write_text("{}", encoding="utf-8")
    (folder / "keep.txt").write_text("kept", encoding="utf-8")
    assert retire_row(tmp_path, tenant) is True
    assert not (folder / "tenant.json").exists()
    assert (folder / "keep.txt").read_text(encoding="utf-8") == "kept"
    assert retire_row(tmp_path, tenant) is False  # again: nothing left
    target = tmp_path / "elsewhere.json"
    target.write_text("{\"alias\": 1}", encoding="utf-8")
    (folder / "tenant.json").symlink_to(target)
    with pytest.raises(Exception):  # noqa: B017, PT011 — a refusal; its type is not pinned
        retire_row(tmp_path, tenant)
    assert target.read_text(encoding="utf-8") == "{\"alias\": 1}", "the link's target was written through or removed"
