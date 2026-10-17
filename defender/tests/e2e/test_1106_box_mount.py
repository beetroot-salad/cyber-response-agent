"""#1106 e2e: a run's box mounts only its own tenant's agent/ half, read-only (observed on the argv start_box composes); DooD translates the source through a covering shared mount and refuses an uncovered one."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests import _tenants1106 as T
from defender.tests._spec1092 import STOCK_ROOTFS, make_run_dir, plant_tree
from defender.tests.tenant_1108_p2._support import AgentReadDocker

pytestmark = pytest.mark.e2e


@pytest.fixture(autouse=True)
def _boxed_only(monkeypatch):
    """Neither the unsandboxed opt-out nor a runtime override may turn a box fault into the host executor — that..."""
    from defender.runtime import box as box_mod

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)


@pytest.fixture
def two_tenants(tmp_path):
    root = tmp_path / "tenants"
    T.place_tenant(root, "acme", table=T.TABLE_A)
    T.place_tenant(root, "bravo", table=T.TABLE_B)
    return root, T.accept(root, "acme"), T.accept(root, "bravo")


def _start(tmp_path: Path, agent: Path) -> AgentReadDocker:
    from defender.runtime import box as box_mod

    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    run_dir = make_run_dir(tmp_path / "r")
    rec = AgentReadDocker(agent)
    box = box_mod.start_box(
        run_dir, defender_dir, tenant_agent=agent,
        spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS), docker=rec)
    assert box.sandboxed is True, "the box fell back to the host executor"
    return rec


@pytest.mark.parametrize(("own", "other"), [("acme", "bravo"), ("bravo", "acme")])
def test_the_box_mounts_its_own_tenants_agent_half_read_only_and_nothing_else(
        tmp_path, two_tenants, own, other):
    root, acme, bravo = two_tenants
    mine, theirs = {"acme": acme, "bravo": bravo}[own], {"acme": acme, "bravo": bravo}[other]
    rec = _start(tmp_path, mine.agent)
    mounts = rec.mounts()
    joined = " ".join(rec.create_argv or [])

    agent_mounts = [m for m in mounts if m["target"] == str(mine.agent)]
    assert agent_mounts == [{
        "source": str(mine.agent), "target": str(mine.agent), "readonly": True,
    }], mounts
    # Nothing of the other tenant, anywhere on the argv; no settings half of ANY tenant.
    assert str(root / other) not in joined, joined
    assert str(theirs.agent) not in joined, joined
    for m in mounts:
        for side in (m["source"], m["target"]):
            assert "settings" not in Path(side).parts, m
    assert str(mine.settings) not in joined
    assert str(theirs.settings) not in joined
    # A mount SOURCE is a tree: a bind of `<root>/<tenant>` (or of the root) holds `settings/`
    # without spelling it. For EVERY bind, no settings folder — this tenant's or the other's —
    # and nothing of the other tenant may sit at, below or above its source.
    for m in mounts:
        source = Path(m["source"])
        for forbidden in (mine.settings, theirs.settings, root / other):
            assert not T.exposes([source], forbidden), (
                f"the bind of {source} exposes {forbidden} inside the box: {m}")
    # The control on the same predicate: the agent bind does expose what it is meant to.
    assert T.exposes([Path(agent_mounts[0]["source"])], mine.agent)


def test_the_agent_source_is_translated_through_a_covering_shared_mount(tmp_path):
    """DooD translates the source while the target remains this run process's agent path."""
    from defender.runtime import box as box_mod

    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    run_dir = make_run_dir(tmp_path / "r")
    agent = tmp_path / "tenants" / "acme" / "knowledge" / "agent"
    shared = ((tmp_path, Path("/daemon/shared")),)
    argv = box_mod._create_argv(
        "defender-run-r1106", run_dir, defender_dir,
        box_mod.BoxSpec(rootfs=STOCK_ROOTFS), shared, tenant_agent=agent,
    ).argv
    source = Path("/daemon/shared") / agent.relative_to(tmp_path)
    assert f"type=bind,source={source},target={agent},readonly" in argv


def test_an_agent_source_on_no_shared_mount_refuses_the_box_naming_it():
    """The negative on the same builder:"""
    from defender.runtime import box as box_mod
    from defender.runtime.box_codec import BoxFault

    shared = ((Path("/workspace"), Path("/home/dev/projects/repo")),)
    with pytest.raises(BoxFault) as caught:
        box_mod._create_argv(
            "defender-run-r1106", Path("/workspace/.runs/r1106"), Path("/workspace/defender"),
            box_mod.BoxSpec(rootfs=STOCK_ROOTFS), shared,
            tenant_agent=Path("/srv/tenants/acme/agent"),
        )
    assert "/srv/tenants/acme/agent" in str(caught.value)
    assert "C46" in str(caught.value)
