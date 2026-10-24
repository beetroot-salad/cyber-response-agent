"""Tests for lint_run_records' tenant-owner rules (#1078, #1210): root acquisition from the Tenant
owner class is rejected, and the row-name literal is not exempt outside the owner."""
from __future__ import annotations

from defender.tests.support.shared.contracts import _spec1077 as S

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
