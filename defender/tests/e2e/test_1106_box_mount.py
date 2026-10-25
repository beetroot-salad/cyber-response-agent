"""#1106 e2e: a run's box mounts only its own tenant's agent/ half, read-only (observed on the argv start_box composes); DooD translates the source through a covering shared mount and refuses an uncovered one."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.sandbox._spec1092 import STOCK_ROOTFS, make_run_dir, plant_tree
from defender.tests.tenancy.tenant_1108_p2._support import AgentReadDocker

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
def two_tenants(tmp_path):
    root = tmp_path / "tenants"
    T.place_tenant(root, ACME, table=T.TABLE_A)
    T.place_tenant(root, BRAVO, table=T.TABLE_B)
    return root, T.accept(root, ACME), T.accept(root, BRAVO)


def _start(tmp_path: Path, agent: Path) -> AgentReadDocker:
    from defender import box as box_mod

    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    run_dir = make_run_dir(tmp_path / "r")
    rec = AgentReadDocker(agent)
    box = box_mod.start_box(
        run_dir, defender_dir, tenant_agent=agent,
        spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS), docker=rec)
    assert box.sandboxed is True, "the box fell back to the host executor"
    return rec


@pytest.mark.parametrize(("own", "other"), [(ACME, BRAVO), (BRAVO, ACME)])
def test_the_box_mounts_its_own_tenants_agent_half_read_only_and_nothing_else(
        tmp_path, two_tenants, own, other):
    root, acme, bravo = two_tenants
    mine, theirs = {ACME: acme, BRAVO: bravo}[own], {ACME: acme, BRAVO: bravo}[other]
    rec = _start(tmp_path, mine.agent)
    mounts = rec.mounts()
    joined = " ".join(rec.create_argv or [])

    # #1255 (design rev 4, P1): the agent half is bound from its host path to the model view's
    # fixed `/agent`, not at its own host path.
    agent_mounts = [m for m in mounts if m["source"] == str(mine.agent)]
    assert agent_mounts == [{
        "source": str(mine.agent), "target": "/agent", "readonly": True,
    }], mounts
    # Nothing of the other tenant, anywhere on the argv; no settings half of ANY tenant.
    assert str(root / other) not in joined, joined
    assert str(theirs.agent) not in joined, joined
    for m in mounts:
        for side in (m["source"], m["target"]):
            assert "settings" not in Path(side).parts, m
    assert str(mine.settings) not in joined
    assert str(theirs.settings) not in joined
    for m in mounts:
        source = Path(m["source"])
        for forbidden in (mine.settings, theirs.settings, root / other):
            assert not T.exposes([source], forbidden), (
                f"the bind of {source} exposes {forbidden} inside the box: {m}")
    # The control on the same predicate: the agent bind does expose what it is meant to.
    assert T.exposes([Path(agent_mounts[0]["source"])], mine.agent)


def test_the_agent_source_is_translated_through_a_covering_shared_mount(tmp_path):
    """DooD translates the source while the target is the model view's `/agent` (#1255 P1; it
    used to remain this run process's agent path)."""
    from defender import box as box_mod

    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    run_dir = make_run_dir(tmp_path / "r")
    agent = tmp_path / "tenants" / ACME / "knowledge" / "agent"
    shared = ((tmp_path, Path("/daemon/shared")),)
    argv = box_mod._create_argv("defender-run-r1106", run_dir, defender_dir, box_mod.BoxSpec(rootfs=STOCK_ROOTFS), shared, lane=box_mod._run_lane_mounts(run_dir, defender_dir, agent)).argv
    source = Path("/daemon/shared") / agent.relative_to(tmp_path)
    assert f"type=bind,source={source},target=/agent,readonly" in argv


def test_an_agent_source_on_no_shared_mount_refuses_the_box_naming_it():
    """The negative on the same builder:"""
    from defender import box as box_mod
    from defender.execution.box_codec import BoxFault

    shared = ((Path("/workspace"), Path("/home/dev/projects/repo")),)
    with pytest.raises(BoxFault) as caught:
        box_mod._create_argv("defender-run-r1106", Path("/workspace/.runs/r1106"), Path("/workspace/defender"), box_mod.BoxSpec(rootfs=STOCK_ROOTFS), shared, lane=box_mod._run_lane_mounts(Path("/workspace/.runs/r1106"), Path("/workspace/defender"), Path("/srv/tenants/acme/agent")))
    assert "/srv/tenants/acme/agent" in str(caught.value)
    assert "C46" in str(caught.value)
