"""#1618 flow 8 / K7, host half of A18: the sweep is never reached from a job container's tick; host owners' folders stay."""
from __future__ import annotations

import os
import sys
import uuid

import pytest

from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._container_entry1170 import ThreadCalls
from defender.tests.support.jobs._job_helper_learning import listing
from defender.tests.support.jobs._learning_container1170 import seen_in_container
from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K

process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]


def test_a18_a_tick_in_the_job_container_never_sweeps_and_leaves_host_owners_folders(scene):
    """With dead host owners' folders in all three roots, the container-side tick does not call the sweep and removes none; a host sweep then does (K7, F8)."""
    from defender.learning.branch import post_step

    root = scene.root
    tenant = root / scene.tenant
    dead = A.dead_mark()
    planted = [
        A.plant(tenant / "run-knowledge" / str(uuid.uuid4()), pid=dead[0], start=dead[1]),
        A.plant(tenant / "drafts" / "b-dead-1618", pid=dead[0], start=dead[1]),
        A.plant(root / ".repo-scratch" / A.named(scene.tenant, *dead), pid=dead[0], start=dead[1], by_name=True),
    ]
    sweep = A._attr_sweep()
    ticks: list[int] = []

    def entry(c, seen):
        argv = ["--tenant", scene.tenant]
        return post_step.main(argv, environ=c.env, author_tick=lambda *a, **k: ticks.append(1) or 0)

    with ThreadCalls({"sweep": sweep}) as calls:
        seen = seen_in_container(scene, "post-step", entry, job_id=None, family_less=True)
        assert seen.ran
        assert ticks == [1], "control: the container's tick ran"
        assert calls.container("sweep") == 0
        assert all(os.path.lexists(p) for p in planted), "a container-side tick removed a host owner's folder"
        sweep(scene.t.data_root, scene.tenant)
        assert calls.helper("sweep") == 1, "control: the watcher sees a host-side sweep"
    assert not any(os.path.lexists(p) for p in planted), "control: the host sweep removes dead owners"
    assert listing(tenant / "drafts") == []
    assert K  # the scene's seam names live in _support
