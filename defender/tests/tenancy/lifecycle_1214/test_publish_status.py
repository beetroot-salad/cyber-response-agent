# ruff: noqa: PT018, F811
"""#1214 O6, as #1618 leaves it: the tenant's last publish outcome is no longer kept anywhere (D7: "the `publish_status`
table goes", with its writers `record.published`, `record.refusal`, `record_publish_status`); the migration that drops it
is `tests/migrations/test_1618_publish_status_migration.py`. Retired here with it (#1618 D7, design "Retired promises"):
the record/read/replace/clear/per-tenant cases of `record_publish_status`/`publish_status` and "finish deletes the
publish status". What stays:

#1214 attack-3 hole 6 (O6): after a fetch nothing named `tenant.json` or `publish-status.json` exists under the data
root, and no production string expression folds to either name (a concatenation is not a constant).

#1214 O6: production code neither reads nor writes `tenant.json` or `publish-status.json`.

No production module spells either name, `tenancy/_tenant.py` (the row's former owner) included: the lab's old row
file is deleted by hand when it moves, not by code (DC-8, SK-6).
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from defender.tests.tenancy.knowledge_1618 import _support as K


@pytest.mark.parametrize("repository", ["memory", "postgres"])
def test_no_tenant_repository_keeps_a_publish_outcome(repository):
    """#1618 D7: neither tenant repository records or reads a publish outcome any more (its table is dropped)."""
    from defender.tenancy import InMemoryTenantRepository
    from defender.tenancy.postgres import PostgresTenantRepository

    cls = {"memory": InMemoryTenantRepository, "postgres": PostgresTenantRepository}[repository]
    assert hasattr(cls, "forge_wiring"), "control: the repository class is the one tenant records are read through"
    assert [name for name in ("record_publish_status", "publish_status") if hasattr(cls, name)] == []


def _shadow_files(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for name in (ROW, STATUS) for p in root.rglob(name))


def test_the_shadow_file_check_sees_a_planted_file(tmp_path):
    """Control: the check reports a file of either name wherever it sits under the root."""
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / STATUS).write_text("x", encoding="utf-8")
    (tmp_path / ROW).write_text("x", encoding="utf-8")
    assert _shadow_files(tmp_path) == [f"t/{STATUS}", ROW]


@pytest.mark.parametrize("outcome", ["ok", "refused"])
def test_a_fetch_leaves_no_row_or_status_file_under_the_data_root(tmp_path, data_root, outcome):
    """The fetch child (#1618 flow 1, which replaced the publish child), answering `ok` or refused (Forgejo unreachable),
    writes neither file under the data root (O6)."""
    with K.scene(tmp_path, data_root) as t:
        if outcome == "refused":
            K.forge_down(t)
        report = K.child_report(t, tmp_path, K.owned_dest(tmp_path / "copies"))
        assert report.word == outcome, report
        assert _shadow_files(Path(K.tenant_root(t)).parent) == []


def _folded(node: ast.AST) -> str | None:
    """The string a constant-only expression builds: literals, `+`, f-strings without fields, `''.join` of literals,
    `%` and `.format` of literals; None for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded(node.left), _folded(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = [_folded(v) for v in node.values]
        return None if None in parts else "".join(parts)  # type: ignore[arg-type]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple)):
        # `str.join` on a literal separator: a method of a value, which `_astlib.callee` cannot resolve.
        if node.func.attr != "join":  # lint-ast-resolve: ok — a str method on a literal receiver; the spelling is the fact
            return None
        sep = _folded(node.func.value)
        parts = [_folded(e) for e in node.args[0].elts]
        return None if sep is None or None in parts else sep.join(parts)  # type: ignore[arg-type]
    return None


def test_the_folding_scan_sees_each_way_of_building_a_name():
    """Control for the scan below: concatenation, f-string and join spell the name; a plain word does not."""
    for source in ('"publish-" + "status.json"', '"-".join(["publish", "status.json"])', 'f"publish-status.json"'):
        assert _folded(ast.parse(source, mode="eval").body) == "publish-status.json", source
    assert _folded(ast.parse('"publish" + "ing"', mode="eval").body) == "publishing"


def test_no_production_expression_folds_to_the_row_or_status_file_name():
    """No `+`, f-string or join in production builds `publish-status.json`; `tenant.json` is built only by the owner (O6)."""
    hits = []
    for path in _production_sources():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call)):
                value = _folded(node)
                owner_row = _rel(path) == "tenancy/_tenant.py" and value is not None and Path(value).name == ROW
                if value is not None and Path(value).name in (ROW, STATUS) and not owner_row:
                    hits.append(f"{_rel(path)}:{node.lineno}:{value}")
    assert hits == []


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
