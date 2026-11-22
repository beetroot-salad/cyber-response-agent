"""#1618 K7: offboarding removes the tenant's host-side private repositories (`<data root>/.repo-scratch/`) by name."""
from __future__ import annotations

import os
import uuid

import pytest

from defender.tests.support.api._mount1161 import API
from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld, lifecycle_config


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    w.host_actor = w.new_host(w.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=0.3),
                              containers=lambda _tenant: None)
    yield w
    w.close()


def test_1618_k7_offboarding_removes_the_tenants_repo_scratch_entries_by_name_whoever_owns_them(world):
    """A tenant's `.repo-scratch/` entries go with its folder, even one a live process owns (by name, not by the sweep); another tenant's stays. (K7)"""
    tenant = world.active_tenant()
    other = str(uuid.uuid4())
    scratch = world.data_root / ".repo-scratch"
    mine = os.getpid(), A.process_start(os.getpid())
    gone = [A.plant(scratch / A.named(tenant, *mine), by_name=True) for _ in range(2)]
    gone.append(A.plant(scratch / A.named(tenant, *A.dead_mark()), by_name=True))
    kept = A.plant(scratch / A.named(other, *mine), by_name=True)

    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()

    assert world.item(tenant)["state"] == "offboarded"
    assert not (world.data_root / tenant).exists(), "control: the tenant's folder went"
    assert [p.name for p in gone if p.exists()] == [], "offboarding left the tenant's private repositories"
    assert kept.is_dir(), "control: another tenant's entry is not the offboarded tenant's to remove"
