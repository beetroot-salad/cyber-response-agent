"""Structural tenant-location acquisition, record names and rename coverage (#1210)."""
from __future__ import annotations

import ast
import uuid

from defender.tests.support.shared.contracts import _spec1077 as S
from defender.tests.support.shared.contracts._by_path import DEFENDER, load_module

JOIN_FINDING = "literal-free join onto an owner-derived value"


def test_d1_tenantpaths_owner_class(tmp_path):
    """Root acquisition is rejected before a value can escape through a local or call."""
    source = (
        "from defender.tenancy._tenant import accept_tenant\n"
        "from defender.episodes._episode_paths import EpisodePaths\n\n"
        "def direct(root, t, d, run_id):\n"
        "    return accept_tenant(root, t, defender_dir=d).runs / run_id\n\n"
        "def through_a_local(root, t, d, run_id):\n"
        "    runs = accept_tenant(root, t, defender_dir=d).runs\n"
        "    return runs / run_id\n\n"
        "def control(ep, run_id):\n"
        "    return EpisodePaths(ep).runs / run_id\n")
    found = S.gate_findings(tmp_path, "runtime/joins.py", source)
    joins = [f.display for f in found if JOIN_FINDING in f.display]
    assert any("control()" in d for d in joins), f"the join arm is not live: {joins}"
    acquisitions = [f.display for f in found if "owner-only record location" in f.display]
    for fn in ("direct()", "through_a_local()"):
        assert any(fn in d for d in acquisitions), (
            f"a Tenant accessor in {fn} escaped the acquisition gate: {acquisitions}")
    accessors = S.gate().RECORD_LOCATION_NAMES
    missing = {"row_path", "episodes", "learning"} - set(accessors)
    assert not missing, f"_accessor_names() does not list Tenant's {sorted(missing)}"


def test_d1_row_constant_not_exempt(tmp_path):
    """The row-name constant is not in _OWNER_NON_RECORD_EXPORTS, so the lint flags a
    'tenant.json' literal outside the owner."""
    found = S.gate_findings(tmp_path, "runtime/forges_the_row.py",
                            "from pathlib import Path\n\n"
                            "def row(root: Path, t: str) -> Path:\n"
                            "    return root / t / 'tenant.json'\n")
    assert S.reports(found, "forges_the_row.py"), (
        "a 'tenant.json' literal outside the owner is not flagged: " + S.displays(found))

    tenant = S.tenant()
    gate = S.gate()
    exported_row = [n for n in gate._OWNER_NON_RECORD_EXPORTS
                    if getattr(tenant, n, None) == "tenant.json"]
    assert exported_row == [], f"the row name is exported as a non-record: {exported_row}"
    public_row = [n for n, v in vars(tenant).items()
                  if v == "tenant.json" and not n.startswith("_")]
    for name in public_row:
        imported = S.gate_findings(tmp_path / f"imp-{name}", "runtime/imports_it.py",
                                   f"from defender.tenancy._tenant import {name}\n")
        assert S.reports(imported, "imports_it.py"), (
            f"importing the row-name constant {name} outside the owner is not refused")


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
