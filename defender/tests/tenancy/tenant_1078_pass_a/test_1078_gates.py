"""The #1077 rename proof still covers the tenant record's owner (#1078).

The gate tests that used to sit here (tenant-location acquisition, the row-name constant) moved
to tests/lint/test_lint_run_records_tenant_owner_1078.py beside the other lint tests."""
from __future__ import annotations

import ast
import uuid

from defender.tests.support.shared.contracts._by_path import DEFENDER, load_module


def test_rename_proof_with_a_new_row_constant(tmp_path):
    """The #1077 rename proof keeps passing with the new tenancy/_tenant.py constants in its renamed
    set; DEFAULT_TENANT_ID's _SKIP_NAMES entry goes with the constant."""
    proof = load_module(DEFENDER / "tests" / "storage" / "test_1077_rename_proof.py",
                        name=f"rename_proof_1078_{uuid.uuid4().hex}")
    assert "DEFAULT_TENANT_ID" not in proof._SKIP_NAMES, (
        "the rename proof still skips DEFAULT_TENANT_ID, which D2 deletes")
    source = (DEFENDER / "tenancy/_tenant.py").read_text(encoding="utf-8")
    rewritten, _count = proof._rewrite_owner(source)
    before = _upper_str_constants(source)
    after = _upper_str_constants(rewritten)
    unrenamed = sorted(n for n, v in before.items()
                       if n not in proof._SKIP_NAMES and v not in proof._SKIP_VALUES
                       and after.get(n) == v)
    assert unrenamed == [], f"the rewrite leaves tenancy/_tenant.py's {unrenamed} unrenamed"
    result = proof._round_trip(proof._renamed_tree(tmp_path), tmp_path / "work")
    assert result.returncode == 0, (
        f"the renamed tree's round trip failed:\n{result.stdout[-2000:]}\n"
        f"{result.stderr[-3000:]}")


def _upper_str_constants(source: str) -> dict[str, str]:
    out = {}
    for node in ast.parse(source).body:
        if (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id.isupper() and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            out[node.targets[0].id] = node.value.value
    return out
