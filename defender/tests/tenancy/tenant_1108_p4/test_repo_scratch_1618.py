"""#1618 K7: every host-side private repository sits under `<data root>/.repo-scratch/` while its operation runs, never under `<T>`,
and the host sweep takes a dead owner's. One case per operation that opens one; one per sweep trigger."""
from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import threading

import pytest

from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper_learning import run_kind
from defender.tests.support.learning.core._feedback1278 import FeedbackCurator, make_scene
from defender.tests.support.learning.core._store1278 import (
    authored_and_merged,
    migrated_database,  # noqa: F401 — fixture
    world,  # noqa: F401 — fixture
)
from defender.tests.support.learning.core._tickfaults1278 import AUTHOR_LANE, Cast, Scene
from defender.tests.tenancy.adoption_1471._forge import DIGEST, RENDERING, SYSTEM
from defender.tests.tenancy.knowledge_1618 import _repos_1618 as R
from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_p4._drain_support import without_clone
from defender.tests.tenancy.tenant_1108_p4.test_1278_feedback import READ_ISSUE, _due, _files
from defender.tests.tenancy.tenant_1108_p4.test_1278_revert import LESSON

pytestmark = [pytest.mark.postgres]

# the jobs scene (the helper's own delivery) and its autouse process state, as `test_job_helper_learning` takes them
process_state = J.process_state
scene = J.scene


@pytest.fixture
def feedback_world(p4_tenant, migrated_database, monkeypatch, tmp_path):  # noqa: F811
    """`test_1278_feedback.world`'s scene (a forge token that reads issues, both curators waking at one item)."""
    s = make_scene(p4_tenant, migrated_database, tmp_path, monkeypatch)
    s.t.forge.scopes = set(READ_ISSUE)
    return s


# --- the operations: each returns the scene's tenant (`t`) it ran against, with the watch armed just before the call ---------

def _fetch_child(request, tmp_path):
    t = request.getfixturevalue("world").t
    without_clone(t)
    watch = R.Watch(t)
    watch.arm()
    report = K.child_report(t, tmp_path, K.owned_dest(K.tenant_root(t) / "run-knowledge"))
    assert report.word == "ok", report
    return t, watch


def _drain_tick(request, tmp_path):
    w = request.getfixturevalue("world")
    without_clone(w.t)
    s = Scene(w, AUTHOR_LANE)
    s.seed()
    cast = Cast(s)
    watch = R.Watch(w.t)
    watch.arm()
    s.run(cast)
    assert cast.started(), "premise: the tick served a batch"
    return w.t, watch


def _revert(request, tmp_path):
    w = request.getfixturevalue("world")
    t = w.t
    authored_and_merged(w)
    without_clone(t)
    watch = R.Watch(t)
    watch.arm()
    cli = importlib.import_module("defender.cli.learning.revert_lesson")
    rc = cli.main(["--tenant", t.tenant_id, LESSON], client=t.forge.client, identity=t.vault.identity(), directory=t.directory)
    assert rc == 0
    return t, watch


def _adoption(request, tmp_path):
    t = request.getfixturevalue("world").t
    without_clone(t)
    step = importlib.import_module("defender.learning.author.version_control.adoption")
    watch = R.Watch(t)
    watch.arm()
    with t.open_delivery() as delivery:  # FORCED: a delivery is a context manager whose exit removes its private repository
        step.adopt(delivery.repository, system=SYSTEM, rendering=RENDERING, digest=DIGEST)
    return t, watch


def _feedback(request, tmp_path):
    s = request.getfixturevalue("feedback_world")
    old_id, _number = _due(s, request.getfixturevalue("caplog"), comment="cite the alert rule, not the host")
    without_clone(s.t)
    watch = R.Watch(s.t)
    watch.arm()
    from defender.tests.support.learning.core._feedback1278 import tick

    tick(s, FeedbackCurator(_files("f1")))
    return s.t, watch


def _helper_batch_start(request, tmp_path):
    sc = request.getfixturevalue("scene")
    import shutil

    root = sc.root / sc.tenant
    for name in ("knowledge", "exports"):
        shutil.rmtree(root / name, ignore_errors=True)
    watch = R.Watch(sc.t)
    watch.arm()
    run_kind(sc, "post-step", lambda c: (c.request("batch.start", lanes=["lessons"]), 0)[1], family_less=False)
    return sc.t, watch


OPERATIONS = {
    "fetch-child": _fetch_child,
    "host-drain-tick": _drain_tick,
    "revert": _revert,
    "adoption": _adoption,
    "feedback": _feedback,
    "helper-batch-start": _helper_batch_start,
}


@pytest.mark.parametrize("operation", list(OPERATIONS))
def test_1618_k7_every_operation_that_opens_a_host_side_private_repository_keeps_it_owned_under_repo_scratch_and_leaves_none(
        operation, request, tmp_path, caplog):
    """While it runs the repository is a 0700 entry of a live owner under `.repo-scratch/`, none under `<T>`, and none remains. (K7, F4, F11)"""
    t, watch = OPERATIONS[operation](request, tmp_path)

    R.assert_private_while_open(watch)
    R.assert_nothing_left(t)


def test_1618_k7_a_killed_fetch_childs_repository_is_swept_by_the_host_sweep(world, tmp_path):  # noqa: F811
    """A fetch child killed while it holds its private repository leaves an entry whose owner is dead; the host sweep removes it. (K7, F8)"""
    t = world.t
    without_clone(t)
    reached, never = threading.Event(), threading.Event()

    def hold(_service):
        reached.set()
        never.wait(60)

    t.server.on_service = hold
    wrapper = tmp_path / "wrapper.py"
    wrapper.write_text(K._CHILD_WRAPPER, encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"module": K.CHILD_MODULE, "tenant_id": t.tenant_id, "origin": t.origin,
                                "data_root": str(R.scratch_root(t).parent)}), encoding="utf-8")
    dest = K.owned_dest(K.tenant_root(t) / "run-knowledge")
    child = subprocess.Popen([sys.executable, str(wrapper), str(spec), t.tenant_id, "--data-root", str(R.scratch_root(t).parent),  # noqa: S603
                              "--dest", str(dest)], cwd=A.IMPORT_ROOT, env={**os.environ, "PYTHONPATH": str(A.IMPORT_ROOT)},
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert reached.wait(20), "the child never fetched"
        assert K.repo_scratch(t), "premise: the child holds a repository entry"
        child.kill()
        child.wait(30)
    finally:
        never.set()
        child.kill()
        child.wait(30)
    left = K.repo_scratch(t)
    assert left, "premise: a killed child cannot clean up after itself"

    K.sweep(t)

    assert K.repo_scratch(t) == [], f"the sweep left a dead owner's repository: {left}"


# --- sweep triggers (F8): fetch_copy's start, the helper's batch.start, a host drain tick ------------------------------------


def _trigger_fetch_copy(request, tmp_path):
    t = request.getfixturevalue("world").t
    without_clone(t)
    planted = R.plant_dead_owner_entry(t)
    K.fetch_copy(t, K.owned_dest(K.tenant_root(t) / "run-knowledge"))
    return planted


def _trigger_batch_start(request, tmp_path):
    sc = request.getfixturevalue("scene")
    planted = R.plant_dead_owner_entry(sc.t)
    run_kind(sc, "post-step", lambda c: (c.request("batch.start", lanes=["lessons"]), 0)[1], family_less=False)
    return planted


def _trigger_drain_tick(request, tmp_path):
    w = request.getfixturevalue("world")
    without_clone(w.t)
    s = Scene(w, AUTHOR_LANE)
    s.seed()
    planted = R.plant_dead_owner_entry(w.t)
    s.run(Cast(s))
    return planted


TRIGGERS = {"fetch_copy-start": _trigger_fetch_copy, "helper-batch.start": _trigger_batch_start, "host-drain-tick": _trigger_drain_tick}


@pytest.mark.parametrize("trigger", list(TRIGGERS))
def test_1618_k7_each_sweep_trigger_removes_a_dead_owners_repository_entry(trigger, request, tmp_path):
    """A planted `.repo-scratch/` entry of a dead owner is gone after the trigger ran (control: it was there before). (K7, F8)"""
    planted = TRIGGERS[trigger](request, tmp_path)

    assert not planted.exists(), f"{trigger} did not sweep the dead owner's entry"
