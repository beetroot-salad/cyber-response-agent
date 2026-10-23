"""#1106 e2e: a run's box mounts only its own tenant's agent/ half, read-only (observed on the argv start_box composes); DooD translates the source through a covering shared mount and refuses an uncovered one."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.sandbox._spec1092 import STOCK_ROOTFS, make_run_dir, plant_tree

pytestmark = pytest.mark.e2e
ACME = fixture_uuid("tenant:acme")
BRAVO = fixture_uuid("tenant:bravo")


@pytest.fixture(autouse=True)
def _boxed_only(monkeypatch):
    """Neither the unsandboxed opt-out nor a runtime override may turn a box fault into the host executor — that..."""
    from defender import box as box_mod

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)


@pytest.fixture
def two_tenants(tmp_path, data_root):
    """#1108 P4: both tenants published for real under one data root (S0's helper), so each
    run reads its own run copy."""
    from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

    with published_tenant(tmp_path / "forge", root=data_root, tenant_id=ACME,
                          files={"settings/verb-grants.yaml": T.TABLE_A},
                          repo_name="acme") as acme, \
            published_tenant(tmp_path / "forge", root=data_root, tenant_id=BRAVO,
                             files={"settings/verb-grants.yaml": T.TABLE_B},
                             repo_name="bravo") as bravo:
        yield data_root, acme, bravo


@pytest.mark.parametrize(("own", "other"), [(ACME, BRAVO), (BRAVO, ACME)])
def test_the_box_mounts_its_own_tenants_agent_half_read_only_and_nothing_else(
        tmp_path, two_tenants, own, other):
    """Re-spelled for #1108 P4 (O-A; OD12 class ii — #1106's obligation, new seams): a run's box,
    started by `run.main` through production's `start_box` over the recording Docker double,
    shows the model view's `/agent` bound read-only from THIS run's copy of its own tenant's
    export (not the clone: the retired `agent` mount), and no mount exposes the copy's
    `settings/`, the tenant's clone, or anything of the other tenant."""
    from defender.runtime.model_view import MODEL_AGENT
    from defender.tests.e2e._box665 import RecordingDocker
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
    from defender.tests.tenancy.tenant_1108_p4.test_run_copy import _boxed_lifecycle, _Investigation

    root, acme, bravo = two_tenants
    mine = {ACME: acme, BRAVO: bravo}[own]
    docker, investigation = RecordingDocker(), _Investigation()
    out = B.launch(mine, tmp_path / own, publish=lambda *a, **k: B.fresh(mine.commit),
                   lifecycle=_boxed_lifecycle(docker, investigation))
    assert out.reached, out.text()
    assert investigation.calls == 1, out.text()
    copy_root = B.run_copies(mine) / out.seen[0].run_dir.name

    agent_mounts = [m for m in docker.mounts() if m["target"] == str(MODEL_AGENT)]
    assert len(agent_mounts) <= 1, docker.mounts()
    inside = docker._through_binds(Path(MODEL_AGENT) / B.LESSON_REL)
    assert inside.resolve().is_relative_to((copy_root / "stage" / "agent").resolve()), (
        f"the box's {MODEL_AGENT} is not this run's copy of its own tenant: {inside}")
    assert all(m["readonly"] for m in docker.mounts()
               if Path(m["source"]).resolve().is_relative_to(copy_root.resolve())), docker.mounts()
    sources = [Path(m["source"]) for m in docker.mounts()]
    for forbidden in (copy_root / "settings", copy_root / "owner", B.clone_dir(mine),
                      root / other):
        assert not T.exposes(sources, forbidden), (
            f"a box mount exposes {forbidden}: {docker.mounts()}")
    # The control on the same predicate: the copy's agent half is what is exposed.
    assert T.exposes(sources, copy_root / "stage" / "agent")


def test_the_agent_source_is_translated_through_a_covering_shared_mount(tmp_path):
    """DooD translates the source while the target is the model view's `/agent` (#1255 P1; it
    used to remain this run process's agent path)."""
    from defender import box as box_mod

    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    run_dir = make_run_dir(tmp_path / "r")
    agent = tmp_path / "tenants" / ACME / "knowledge" / "agent"
    shared = ((tmp_path, Path("/daemon/shared")),)
    argv = box_mod._create_argv(
        "defender-run-r1106", run_dir, defender_dir,
        box_mod.BoxSpec(rootfs=STOCK_ROOTFS), shared, tenant_agent=agent,
    ).argv
    source = Path("/daemon/shared") / agent.relative_to(tmp_path)
    assert f"type=bind,source={source},target=/agent,readonly" in argv


def test_an_agent_source_on_no_shared_mount_refuses_the_box_naming_it():
    """The negative on the same builder:"""
    from defender import box as box_mod
    from defender.execution.box_codec import BoxFault

    shared = ((Path("/workspace"), Path("/home/dev/projects/repo")),)
    with pytest.raises(BoxFault) as caught:
        box_mod._create_argv(
            "defender-run-r1106", Path("/workspace/.runs/r1106"), Path("/workspace/defender"),
            box_mod.BoxSpec(rootfs=STOCK_ROOTFS), shared,
            tenant_agent=Path("/srv/tenants/acme/agent"),
        )
    assert "/srv/tenants/acme/agent" in str(caught.value)
    assert "C46" in str(caught.value)
