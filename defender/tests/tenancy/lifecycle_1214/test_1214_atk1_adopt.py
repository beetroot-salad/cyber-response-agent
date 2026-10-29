# ruff: noqa: F811, PT018
"""#1214 attack-1 H-6: adopting again before the job is active retires nothing of the lab (O9, Flow 5)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214.test_1214_adopt import LAB, Lab, lab, world  # noqa: E402,F401 — fixtures


def _untouched(world, lab: Lab) -> None:
    bao = world.openbao
    assert (lab.folder / "tenant.json").is_file()
    assert (lab.issuer_dir / "client" / LAB).is_dir()
    assert f"delivery-{LAB}" in bao.approles and f"tenant-{LAB}" in bao.oidc_roles and f"tenant-{LAB}" in bao.entities


def test_adopt_called_while_the_job_is_under_way_leaves_the_labs_working_credential_and_row_alone(world, lab):
    """The new generation does not exist yet, so the old facts are the lab's only working credential: a second `adopt`
    mid-job removes none of them (O9)."""
    lab.adopt()
    world.drive(stop=lambda: world.item(LAB)["step"] == "install")
    assert world.item(LAB)["state"] == "creating"
    lab.adopt()
    _untouched(world, lab)


def test_adopt_called_while_the_job_has_failed_leaves_the_labs_facts_and_they_go_once_it_is_active(world, lab):
    """A failed job can still fall back on the old facts; `adopt` retires them only after resume has made the tenant
    active (O9)."""
    world.integration.fail_next = 1
    lab.adopt()
    world.drive()
    assert world.item(LAB)["failure"] and world.item(LAB)["state"] == "creating"
    lab.adopt()
    _untouched(world, lab)
    assert world.ops.post(f"/admin/tenants/{LAB}/resume").status_code == 202
    world.drive()
    assert world.item(LAB)["state"] == "active"
    lab.adopt()
    assert not (lab.folder / "tenant.json").exists() and f"delivery-{LAB}" not in world.openbao.approles
