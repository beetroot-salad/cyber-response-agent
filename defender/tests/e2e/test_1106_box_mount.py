"""#1106 — a run's box holds its own tenant's `agent/` half, read-only, and nothing else of any
tenant's (O1, M6).

M6: one extra READ-ONLY bind, whose source is the RESOLVED `TenantDir.agent` and whose target is
one fixed constant (`box.TENANT_AGENT_TARGET`) outside the `defender_dir` mount target. The
`settings/` half is never a mount source. The source goes through the existing shared-mount
coverage check, so a tenants root on a path the daemon cannot see refuses the box at start
(C46's refusal) rather than surfacing as docker's "bind source path does not exist".

Observed on the REAL `start_box` over the recording docker fake (`_box665.RecordingDocker`):
the `docker run` argv it composes is the box's mount list. Two tenants live in ONE tmp root so
"nothing of tenant B" is a claim about a B that exists beside A — and each direction is run, so
every absence has its presence as the control on the same argv.

(The design's "a listing inside the box" half needs a live daemon; the argv is what a live box
is created FROM, and `test_665_box_live.py` is where live mount mechanics are confirmed.)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests import _tenants1106 as T
from defender.tests._spec1092 import STOCK_ROOTFS, make_run_dir, plant_tree
from defender.tests.e2e._box665 import RecordingDocker

pytestmark = pytest.mark.e2e


@pytest.fixture(autouse=True)
def _boxed_only(monkeypatch):
    """Neither the unsandboxed opt-out nor a runtime override may turn a box fault into the
    host executor — that would make "no mount" and "no box" indistinguishable."""
    from defender.runtime import box as box_mod

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)


@pytest.fixture
def two_tenants(tmp_path):
    root = tmp_path / "tenants"
    T.plant_tenant(root, "acme", table=T.TABLE_A)
    T.plant_tenant(root, "bravo", table=T.TABLE_B)
    resolve = T.tenants().tenant_dir
    return root, resolve(root, "acme"), resolve(root, "bravo")


def _start(tmp_path: Path, agent: Path) -> RecordingDocker:
    from defender.runtime import box as box_mod

    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    run_dir = make_run_dir(tmp_path / "r")
    rec = RecordingDocker()
    box = box_mod.start_box(
        run_dir, defender_dir, tenant_agent=agent,
        spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS), docker=rec)
    assert box.sandboxed is True, "the box fell back to the host executor"
    return rec


@pytest.mark.parametrize(("own", "other"), [("acme", "bravo"), ("bravo", "acme")])
def test_the_box_mounts_its_own_tenants_agent_half_read_only_and_nothing_else(
        tmp_path, two_tenants, own, other):
    from defender.runtime import box as box_mod

    root, acme, bravo = two_tenants
    mine, theirs = {"acme": acme, "bravo": bravo}[own], {"acme": acme, "bravo": bravo}[other]
    rec = _start(tmp_path, mine.agent)
    mounts = rec.mounts()
    joined = " ".join(rec.create_argv or [])

    agent_mounts = [m for m in mounts if m["target"] == str(box_mod.TENANT_AGENT_TARGET)]
    assert agent_mounts == [{
        "source": str(mine.agent), "target": str(box_mod.TENANT_AGENT_TARGET), "readonly": True,
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


def test_the_agent_target_is_a_fixed_absolute_path_outside_the_trees_the_box_already_binds(
        tmp_path, two_tenants):
    """A fixed constant (the model's view of "my tenant's knowledge" must not depend on where
    the operator keeps the root), absolute, and inside neither the `defender_dir` target nor
    the run dir — a target nested in the read-only tree would shadow part of it."""
    from defender.runtime import box as box_mod

    target = Path(box_mod.TENANT_AGENT_TARGET)
    assert target.is_absolute()
    assert not target.is_relative_to(T.DEFENDER)
    assert not T.DEFENDER.is_relative_to(target)
    rec = _start(tmp_path, two_tenants[1].agent)
    for m in rec.mounts():
        if m["target"] != str(target):
            assert not target.is_relative_to(m["target"]), (target, m)
            assert not Path(m["target"]).is_relative_to(target), (target, m)


def test_the_agent_source_is_translated_through_a_covering_shared_mount():
    """Under docker-outside-of-docker the agent half, like every bind source, is handed to the
    daemon by the path the DAEMON sees; the target stays the fixed constant."""
    from defender.runtime import box as box_mod

    shared = ((Path("/workspace"), Path("/home/dev/projects/repo")),)
    argv = box_mod._create_argv(
        "defender-run-r1106", Path("/workspace/.runs/r1106"), Path("/workspace/defender"),
        box_mod.BoxSpec(rootfs=STOCK_ROOTFS), shared,
        tenant_agent=Path("/workspace/knowledge/tenants/acme/agent"),
    ).argv
    joined = " ".join(argv)
    assert (
        "type=bind,source=/home/dev/projects/repo/knowledge/tenants/acme/agent,"
        f"target={box_mod.TENANT_AGENT_TARGET},readonly"
    ) in joined, joined


def test_an_agent_source_on_no_shared_mount_refuses_the_box_naming_it():
    """The negative on the same builder: a tenants root the daemon cannot see is C46's
    refusal, naming the agent source — the run dir and defender dir around it are covered."""
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
