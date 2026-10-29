"""#1214 attack-3 hole 6 (O6): after a publish nothing named `tenant.json` or `publish-status.json` exists under the data
root, and no production string expression folds to either name (a concatenation is not a constant).
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from defender.tests.tenancy.lifecycle_1214.test_1214_no_tenant_files import (
    ROW,
    STATUS,
    _production_sources,
    _rel,
)
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, unbind_forge


def _shadow_files(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for name in (ROW, STATUS) for p in root.rglob(name))


def test_the_shadow_file_check_sees_a_planted_file(tmp_path):
    """Control: the check reports a file of either name wherever it sits under the root."""
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / STATUS).write_text("x", encoding="utf-8")
    (tmp_path / ROW).write_text("x", encoding="utf-8")
    assert _shadow_files(tmp_path) == [f"t/{STATUS}", ROW]


@pytest.mark.parametrize("outcome", ["fresh", "misconfigured"])
def test_a_publish_leaves_no_row_or_status_file_under_the_data_root(tmp_path, data_root, outcome):
    """The publish child's success and its local misconfiguration both record to the database only (O6)."""
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        if outcome == "misconfigured":
            unbind_forge(t)
        else:
            t.merge(B.MERGE_FILES)
        line = B.run_child(t, mint=outcome == "misconfigured")
        assert B.outcome_class(line) == outcome, line
        assert _shadow_files(Path(t.data_root)) == []


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
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join" \
            and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple)):
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
