"""#1618 K1, K8: no lock, no clone/exports/`current` path on `Tenant`, `RunTenant`'s roots required (static)."""
from __future__ import annotations

import dataclasses

import pytest

from defender.tests.tenancy.knowledge_1618 import _slice_a as A

LOCK_NAMES = ["LockBusy", "tenant_lock", "publish_locked", "materialise_export", "knowledge_lock"]


def test_a13_the_census_scans_product_code_and_sees_a_kept_name():
    """Positive control: the scanner covers the product tree and finds names that stay (K1)."""
    assert len(A.product_python()) > 300
    assert not any(p.startswith("defender/tests/") for p in A.product_python())
    assert A.uses("check_knowledge_folder"), "control: a kept name is found"
    assert A.uses("owned_temporary")


@pytest.mark.parametrize("name", LOCK_NAMES)
def test_a13_no_product_code_names_the_lock(name):
    """Each lock name is absent from product code (K1)."""
    assert A.uses(name) == []


def test_a13_no_product_string_names_the_lock_file():
    """`knowledge.lock` is spelled nowhere in product code (K1)."""
    assert A.uses("", literal="knowledge.lock") == []


@pytest.mark.parametrize("name", ["agent", "settings", "knowledge", "exports", "knowledge_lock", "export_folder"])
def test_a15_tenant_has_no_knowledge_path(name):
    """`Tenant` carries no clone, export or lock path (K8)."""
    from defender.tenancy import Tenant

    assert hasattr(Tenant, "tenant_root"), "control: the probe sees properties"
    assert not hasattr(Tenant, name)


def test_a15_run_tenant_roots_are_required():
    """`RunTenant`'s agent and settings roots have no default (K8); `grants` is the control."""
    from defender.systems.run_tenant import RunTenant

    fields = {f.name: f for f in dataclasses.fields(RunTenant)}
    assert fields["grants"].default is dataclasses.MISSING
    assert fields["grants"].default_factory is dataclasses.MISSING
    for name in ("agent_root", "settings_root"):
        f = fields[name]
        assert f.default is dataclasses.MISSING, name
        assert f.default_factory is dataclasses.MISSING, name
