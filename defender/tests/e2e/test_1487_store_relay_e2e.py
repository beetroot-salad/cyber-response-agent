"""#1487 O8 (a), (b) and O1's "no process in its container held a database address", in real job containers. NOT RUN
HERE: like `test_job_box_boundary_e2e.py` it needs a native docker daemon with the levered runtime and the job image;
CI's `test` job runs it.

One flow: a real worker over a completed investigation runs its learning job in a real container (the helper's real
docker); the container writes the job's end record with its finding; the worker's own end write stores it; the worker
then starts the post-step in a second real container, whose tick store (through the helper) claims that finding. The
host seeds nothing of the finding. The programs are `tests/support/jobs/_real_containers1487.py`'s: the learning
container's real entry (reading the episode's held rows) is `tests/learning/branch/test_1487_hand_in.py`'s."""
from __future__ import annotations

import pytest

from defender.tests.e2e.test_job_box_boundary_e2e import requires_box
from defender.tests.support.jobs import _real_containers1487 as R
from defender.tests.support.jobs._job_helper import ensure_job_network, helper_scene
from defender.tests.support.jobs._jobs1342 import StandInContainers, an_alert, job_store, make_worker
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, batches, call
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture

pytestmark = [pytest.mark.e2e, pytest.mark.box, pytest.mark.postgres, requires_box]

R.compiled()


@pytest.fixture
def flow(tmp_path, monkeypatch, migrated_database):  # noqa: F811
    """The worker's run over one completed investigation: what the host reads after it, what each container saw."""
    import anyio

    from defender.box import run_docker

    with helper_scene(tmp_path, monkeypatch, migrated_database) as scene:
        monkeypatch.setenv("DEFENDER_DEPLOYMENT", "dev")
        monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")  # the helper binds the thresholds: one finding is due
        monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
        ensure_job_network(run_docker)
        (scene.root / scene.tenant / "learning").mkdir(exist_ok=True)
        out: dict = {"scene": scene}

        async def go() -> None:
            async with job_store(scene.dsn) as store:
                alert = await an_alert(store, scene.tenant)
                inv, _ = await store.create_investigation(scene.tenant, alert.alert_id, "k1", actor="u-1")
                claim = await store.claim()
                assert claim.record.investigation_id == inv.investigation_id, "premise: only this one was queued"
                await store.finish(scene.tenant, inv.investigation_id, stage="completed", disposition="malicious",
                                   cost_usd=0.0)
                ((job,),) = execute(scene.dsn, "SELECT id FROM jobs.learning_jobs WHERE investigation_id = %s",
                                    (inv.investigation_id,))
                job = str(job)
                rows = [_row(job)]
                R.prepare(scene.root, scene.tenant, scene.dsn, rows=rows)
                out.update(job=job, rows=rows, host_dial=R.host_can_dial(scene.dsn))
                worker = make_worker(
                    store, scene.root, lambda _launch: ["/bin/false"],
                    containers=StandInContainers(tmp_path / "containers"), slots=3, learning_slots=1,
                    learning_argv=R.real_child(scene.t.commit, "learning"),
                    post_step_argv=R.real_child(scene.t.commit, "post-step"))
                await worker.drain()

        anyio.run(go)
        out["learning"] = R.observed(scene.root, scene.tenant, "learning")
        out["post_step"] = R.observed(scene.root, scene.tenant, "post-step")
        yield out


def _row(job: str) -> dict:
    """A defender finding the job's judge could have held (`<job>/w-b/0/0`): one the worker's screen admits."""
    from defender.tests.support.jobs._findings1487 import defender_row

    return defender_row(job)


def _job_row(flow) -> dict:
    cols = ("status", "reason", "publish_state")
    (found,) = execute(flow["scene"].dsn, f"SELECT {', '.join(cols)} FROM jobs.learning_jobs WHERE id = %s",  # noqa: S608
                       (flow["job"],))
    return dict(zip(cols, found, strict=True))


def test_o8a_a_learning_jobs_container_ends_completed_and_the_workers_end_write_stores_its_finding(flow):
    """(O8a, O1) the end record the container wrote is `completed`; the worker's end write stored the finding as the job's."""
    scene, job = flow["scene"], flow["job"]
    assert _job_row(flow) == {"status": "completed", "reason": None, "publish_state": "done"}
    seen = flow["post_step"]["work_before"]
    assert [row[:2] + row[3:] for row in seen] == [["finding", f"{job}/w-b/0/0", job]], "stored for the tenant, its source run the job"
    assert [row[2] for row in seen] == ["waiting"], "waiting when the post-step's tick looked"
    held = {i.key: i for i in call(scene.dsn, "work", scene.tenant)}
    assert held[f"{job}/w-b/0/0"].source_run == job


def test_o8b_a_post_step_containers_tick_claims_that_finding_through_the_helper(flow):
    """(O8b) the claim the post-step container made through its helper is a working author batch holding the finding, as the host reads it."""
    scene, job = flow["scene"], flow["job"]
    claimed = flow["post_step"]["claimed"]
    assert claimed is not None, "nothing was due: the finding never reached the helper's thresholds"
    assert claimed["lane"] == AUTHOR_LANE
    assert claimed["keys"] == [["finding", f"{job}/w-b/0/0"]]
    (batch,) = [b for b in batches(scene.dsn, scene.tenant) if b.lane == AUTHOR_LANE]
    assert (str(batch.id), batch.phase) == (claimed["batch"], "working")
    (item,) = [i for i in call(scene.dsn, "work", scene.tenant) if i.key == f"{job}/w-b/0/0"]
    assert (item.status, str(item.batch_id)) == ("in_batch", claimed["batch"])


def test_o4_the_real_post_step_hands_its_tick_the_job_containers_port(flow):
    """(O4, Amendment 1) `post_step.main` in the container called its tick with `store=` only, and that store is the port
    `JobContainer.tick_store()` builds there, not an adapter over a database of its own."""
    seen = flow["post_step"]
    assert seen["exit"] == 0
    assert seen["tick_kwargs"] == ["store"], seen["tick_kwargs"]
    assert seen["tick_store"] == seen["port"], (seen["tick_store"], seen["port"])
    assert "StoreAdapter" not in seen["tick_store"], seen["tick_store"]


@pytest.mark.parametrize("which", ["learning", "post_step"])
def test_o1_no_process_in_a_job_container_held_a_database_address_login_or_a_connect(flow, which):
    """(O1) in each real container: no address, login or variable of the database in any process, no open connection to it, a dial of its address fails."""
    assert flow["host_dial"], "control: the address the container dials is live from the host"
    assert R.database_held(flow[which], flow["scene"].dsn) == []
