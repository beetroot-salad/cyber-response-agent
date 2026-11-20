"""#1557 O5, O6: a job's per-claim folders (`<root>/.job-scratch/<claim>/`, with the job's `shared/` in it, and
`<root>/.job-sockets/<claim>/`) are gone once the worker has handled the child's exit, however it ended and whatever
its kind; a worker's start removes whatever a predecessor left under both roots before it claims; a removal that fails
is an error naming the folder, and the worker starts anyway.

The children here play a kind's helper (#1170) as `test_1344_learning_jobs` does: a scripted child that leaves the
folders a helper makes (paths filled with the claim its worker handed it) and then exits or dies. The helper's own side
(no scratch in the episode folder, no removal steered by a link under `<T>/`) is `test_job_helper_learning.py`'s
`test_1557_*`."""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
from pathlib import Path

import pytest

from defender.tests.jobs import test_1344_learning_jobs as _learning
from defender.tests.jobs.test_1344_learning_jobs import job_child, learning_worker, post_child, queued_job
from defender.tests.support.jobs._jobs1342 import StandInContainers, job_store, row
from defender.tests.support.jobs._worker1342 import _child, _committed, _queued, _until, _worker

# The shared fixture, bound in this module so pytest finds it here (an import of `world` would be shadowed by each
# test's parameter of that name).
world = _learning.world

#: The per-claim folders a helper makes, as a child leaves them (`{root}`, `{claim}` filled in): the claim's scratch
#: with the job's `shared/` (an oracle scratch in it) and an oracle box's runner beside it, and the socket folder.
LEFT = ("{root}/.job-scratch/{claim}/shared/defender-oracle-x/inputs",
        "{root}/.job-scratch/{claim}/oracle-x/defender-oracle-runner-y",
        "{root}/.job-sockets/{claim}/held")
#: What must be gone.
GONE = ("{root}/.job-scratch/{claim}", "{root}/.job-sockets/{claim}")
#: Claims no live worker holds: what a killed worker's helpers left.
DEAD = "d" * 32
STUCK = "e" * 32
#: Deep enough that Python 3.11's descriptor-based `shutil.rmtree` gives up (RecursionError).
DEPTH = 3000


def _fill(template: str, root: Path, claim: str) -> Path:
    return Path(template.replace("{root}", str(root)).replace("{claim}", claim))


def _plant(root: Path, claim: str) -> None:
    for template in LEFT:
        _fill(template, root, claim).mkdir(parents=True, exist_ok=True)
        (_fill(template, root, claim) / "f.json").write_text("{}", encoding="utf-8")


def _unremovable(base: Path) -> None:
    """What a job can leave in its `shared/` that the data root's owner cannot remove by plain removal: a 0555 folder
    holding a file (it defeats a non-root owner) and a chain of folders `DEPTH` deep (it defeats any owner here)."""
    (base / "locked").mkdir(parents=True)
    (base / "locked" / "inside.json").write_text("{}", encoding="utf-8")
    (base / "locked").chmod(0o555)
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for _ in range(DEPTH):
            os.mkdir("d", dir_fd=fd)
            child = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
    finally:
        os.close(fd)


def _clear(base: Path) -> None:
    """Remove an `_unremovable` tree (or what is left of one) without recursion: unlock its locked folder, then lift
    the chain's second level into the first's place, one level at a time, so no path ever grows long."""
    locked = base / "locked"
    if locked.exists():
        locked.chmod(0o755)
        shutil.rmtree(locked)
    chain, spare = base / "d", base / "d-spare"
    while (chain / "d").exists():
        os.rename(chain / "d", spare)
        os.rmdir(chain)
        os.rename(spare, chain)
    if chain.exists():
        os.rmdir(chain)
    shutil.rmtree(base)


async def _serve_one(world: dict, containers: StandInContainers) -> str:
    """`serve()` until its first row has run (so its start is past), then SIGTERM: the row's id."""
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, _child(world, files=_committed()),
                                              containers=containers).serve())
        try:
            await _until(lambda: (row(world["dsn"], inv) or {}).get("stage") == "completed", "the first row to run")
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        return inv


# --- O5: after the child, every kind, every ending ----------------------------------------------------------------------

@pytest.mark.anyio
@pytest.mark.postgres
@pytest.mark.parametrize("ending", ["exit", "killed"])
@pytest.mark.parametrize("kind", ["learning", "post-step", "investigation"])
async def test_1557_o5_a_childs_per_claim_folders_are_gone_once_the_worker_has_handled_its_exit(world, kind, ending):
    """The child of `kind` leaves its claim's scratch (with `shared/` and a runner) and socket folders and exits 0, or
    dies by SIGKILL (its helper killed, its own removal never run); once the worker is done with it, neither folder is
    left. (O5: normal end, helper killed; every kind)"""
    root = world["root"]
    witness = f"{world['tmp']}/witness/{{claim}}"
    leaves: dict = {"dirs": [t.replace("{root}", str(root)) for t in (*LEFT, witness)]}
    if ending == "killed":
        leaves["die_by"] = int(signal.SIGKILL)
    async with job_store(world["dsn"]) as store:
        if kind == "investigation":
            child = _child(world, files=_committed(), **leaves)
            await _queued(store)
            await _worker(world, store, child).drain()
        else:
            child = (job_child(world, **leaves) if kind == "learning" else post_child(world, **leaves))
            others = post_child(world) if kind == "learning" else job_child(world)
            await queued_job(world, store, ticket="T-1")
            jobs, post = (child, others) if kind == "learning" else (others, child)
            await learning_worker(world, store, job=jobs, post=post).drain()

    (seen,) = child.seen_all().values()
    claim = seen["claim"]
    assert claim, "premise: the worker handed its child a claim"
    assert (world["tmp"] / "witness" / claim).is_dir(), "control: the child left its folders"
    left = [str(_fill(t, root, claim)) for t in GONE if _fill(t, root, claim).exists()]
    assert left == [], f"O5: the {kind} child's per-claim folders are left after it {ending}: {left}"


# --- O5: a killed worker's leftovers, at the next start ----------------------------------------------------------------

@pytest.mark.anyio
@pytest.mark.postgres
async def test_1557_o5_a_killed_workers_per_claim_folders_are_gone_once_the_next_worker_has_started(
        world, tmp_path, caplog):
    """A worker killed with its helpers leaves its claims' folders, and a job left a link among them; the next `serve()`
    removes what is under both roots before it claims: once its first row has run, neither of the dead claim's folders
    is left, the link is gone and what it pointed at is untouched, a tenant's folder is untouched, and nothing is
    logged as a failed removal (the row's own claim folders, already gone, included). (O5: worker killed and
    restarted)"""
    root = world["root"]
    _plant(root, DEAD)
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    (decoy / "precious.json").write_text("{}", encoding="utf-8")
    link = root / ".job-sockets" / ("f" * 32)
    link.symlink_to(decoy, target_is_directory=True)
    kept = root / "00000000-0000-4000-8000-000000000000" / "episodes" / "e" / "kept.json"
    kept.parent.mkdir(parents=True)
    kept.write_text("{}", encoding="utf-8")

    with caplog.at_level(logging.ERROR, logger="defender.worker"):
        await _serve_one(world, StandInContainers(tmp_path / "containers"))

    left = [str(_fill(t, root, DEAD)) for t in GONE if _fill(t, root, DEAD).exists()]
    assert left == [], f"O5: a dead worker's per-claim folders are left after the next start: {left}"
    assert not os.path.lexists(link), "a link among the per-job folders was left"
    assert (decoy / "precious.json").is_file(), "the start's removal followed a link among the per-job folders"
    assert kept.is_file(), "a tenant's folder was touched by the start"
    failed = [r.getMessage() for r in caplog.records if "per-job folder" in r.getMessage()]
    assert failed == [], f"a removal was logged as failed: {failed}"


# --- O6: a removal that fails is an error, and the worker starts anyway -------------------------------------------------

@pytest.mark.anyio
@pytest.mark.postgres
async def test_1557_o6_a_leftover_the_start_cannot_remove_is_an_error_naming_it_and_the_worker_still_serves(
        world, tmp_path, caplog):
    """A predecessor's claim folder holding what plain removal cannot take: the next `serve()` logs an error naming
    that folder, still removes the other dead claim's folders, and serves its first row. (O6)"""
    root = world["root"]
    _plant(root, DEAD)
    stuck = _fill("{root}/.job-scratch/{claim}", root, STUCK)
    twin = tmp_path / "twin"
    try:  # what plain removal cannot take is taken down here, however the case ends
        _unremovable(stuck / "shared")
        _unremovable(twin)
        with pytest.raises((OSError, RecursionError)):
            shutil.rmtree(twin)  # premise: plain removal cannot take this tree here
        with caplog.at_level(logging.ERROR, logger="defender.worker"):
            inv = await _serve_one(world, StandInContainers(tmp_path / "containers"))

        assert (row(world["dsn"], inv) or {}).get("stage") == "completed", "O6: the worker did not serve after the failure"
        errors = [r for r in caplog.records if r.levelno >= logging.ERROR and str(stuck) in r.getMessage()]
        assert errors, f"O6: no error names the folder the start could not remove: {[r.getMessage() for r in caplog.records]}"
        left = [str(_fill(t, root, DEAD)) for t in GONE if _fill(t, root, DEAD).exists()]
        assert left == [], f"one folder the start could not remove kept it from removing the others: {left}"
    finally:
        for base in (stuck / "shared", twin):
            if base.exists():
                _clear(base)
        shutil.rmtree(stuck, ignore_errors=True)
