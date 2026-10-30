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
        "from defender.records._episode_paths import EpisodePaths\n\n"
        "def direct(root, t, d, run_id):\n"
        "    return accept_tenant(root, t, defender_dir=d).runs / run_id\n\n"
        "def through_a_local(root, t, d, run_id):\n"
        "    runs = accept_tenant(root, t, defender_dir=d).runs\n"
        "    return runs / run_id\n\n"
        "def control(ep, run_id):\n"
        "    return EpisodePaths(ep).runs / run_id\n")
    found = S.gate_findings(tmp_path, "investigation/joins.py", source)
    joins = [f.display for f in found if JOIN_FINDING in f.display]
    assert any("control()" in d for d in joins), f"the join arm is not live: {joins}"
    acquisitions = [f.display for f in found if "owner-only record location" in f.display]
    for fn in ("direct()", "through_a_local()"):
        assert any(fn in d for d in acquisitions), (
            f"a Tenant accessor in {fn} escaped the acquisition gate: {acquisitions}")
    accessors = S.gate().RECORD_LOCATION_NAMES
    missing = {"row_path", "episodes", "learning"} - set(accessors)
    assert not missing, f"_accessor_names() does not list Tenant's {sorted(missing)}"


def test_d1_the_row_name_is_spelled_by_no_one_and_the_kind_is_retired():
    """The row file is retired (#1214 O6, SK-6): its former owner neither binds `tenant.json` to a constant nor keeps a
    function that touches it (the lab's row file is deleted by hand); the registry marks the kind retired (DC-8)."""
    tenant = S.tenant()
    assert not hasattr(tenant, "retire_row"), "the owner still keeps a function for the retired row"
    owner_source = (DEFENDER / "tenancy/_tenant.py").read_text(encoding="utf-8")
    assert _upper_str_constants(owner_source), "control: the census reads the owner's constants"
    bound = {n for n, v in _upper_str_constants(owner_source).items() if v == "tenant.json"}
    assert bound == set(), f"the owner still binds the row name: {bound}"
    rows = [line.split("\t") for line in (DEFENDER / "docs/run-records-kinds.tsv").read_text(encoding="utf-8").splitlines()]
    [row] = [r for r in rows if r[0] == "tenant_row"]
    assert "retired" in "\t".join(row[6:]).lower(), f"the tenant_row kind is not marked retired: {row}"


def test_rename_proof_with_a_new_row_constant(tmp_path):
    """The #1077 rename proof keeps passing with tenancy/_tenant.py's constants in its renamed
    set, and keeps no `_SKIP_NAMES` entry for the deleted DEFAULT_TENANT_ID."""
    proof = load_module(DEFENDER / "tests" / "storage" / "test_1077_rename_proof.py",
                        name=f"rename_proof_1078_{uuid.uuid4().hex}")
    assert "DEFAULT_TENANT_ID" not in proof._SKIP_NAMES, (
        "the rename proof still skips the deleted DEFAULT_TENANT_ID")
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
