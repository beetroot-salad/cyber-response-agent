"""#1342 across real processes: the death tie when the worker is killed or stopped (O7, M8), a
worker in another process running what this one queued (O15), `serve()`'s own signal handlers, and
the worker's default child argv (O6).

The worker runs as `_worker_proc1342.py` (its own process, `serve()` until SIGTERM/SIGINT). Children
are the scripted stand-in (the job lane through the per-job host helper is `test_job_helper.py`'s). Every wait is
bounded."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from defender.tests.support.jobs._jobs1342 import (
    DEFENDER,
    GOLDEN_REPORT,
    T1,
    WORKTREE,
    an_alert,
    job_end,
    job_store,
    register_tenant,
    row,
)

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

SUPPORT = DEFENDER / "tests" / "support" / "jobs"
IDLE_BEFORE_QUEUING = 4.0  # seconds the serving worker idles first: several fixed poll intervals (M10)


def _env(data_root: Path, dsn: str) -> dict[str, str]:
    """The worker's environment: its children inherit it, so they read tenant records from `dsn` (r6 R6-2)."""
    return {**os.environ, "DEFENDER_DATA_ROOT": str(data_root), "DEFENDER_DATABASE_DSN": dsn,
            "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"}


def _wait(condition, *, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.05)


def _gone(pid: int) -> bool:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except FileNotFoundError:
        return True
    return "\nState:\tZ" in status


@contextmanager
def worker_process(tmp_path: Path, config: dict) -> Iterator[subprocess.Popen]:
    ready = tmp_path / "worker-ready"
    path = tmp_path / "worker.json"
    path.write_text(json.dumps({**config, "ready": str(ready)}), encoding="utf-8")
    proc = subprocess.Popen(  # noqa: S603 — the test's own worker process
        [sys.executable, str(SUPPORT / "_worker_proc1342.py"), str(path)],
        env=_env(Path(config["data_root"]), config["dsn"]), cwd=str(WORKTREE), stderr=subprocess.PIPE)
    try:
        _wait(lambda: ready.exists() or proc.poll() is not None, timeout=120, what="the worker")
        assert ready.exists(), f"the worker died at start: {proc.stderr.read().decode(errors='replace')[-2000:]}"
        yield proc
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=30)


# --- O15 -----------------------------------------------------------------------------------------

async def test_o15_a_worker_in_another_process_runs_what_this_one_queued(migrated_database, tmp_path):
    """Queued from here after the worker is up and idle: it polls, runs it, queued → running → completed. (O15, M10)"""
    import anyio

    dsn = migrated_database
    register_tenant(dsn, T1)
    root = tmp_path / "data"
    runs = root / T1 / "runs"
    runs.mkdir(parents=True)
    release = tmp_path / "release"
    golden = GOLDEN_REPORT.read_text(encoding="utf-8")
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        config = {"dsn": dsn, "data_root": str(root), "child": "scripted", "where": str(tmp_path / "child"),
                  "runs": str(runs), "wait_for": str(release), "containers": str(tmp_path / "containers"),
                  "files": {"{id}.job-end.json": job_end(), "{id}/report.md": golden}}
        with worker_process(tmp_path, config) as proc:
            # M10/D-p: the worker is up and idle for a few poll intervals before anything is queued.
            await anyio.sleep(IDLE_BEFORE_QUEUING)
            assert proc.poll() is None, "the idle worker exited"
            inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
            assert inv.stage == "queued"
            stages = []
            for _ in range(1200):
                current = (await store.get_investigation(T1, inv.investigation_id)).stage
                if not stages or stages[-1] != current:
                    stages.append(current)
                if current == "running":
                    release.touch()
                if current == "completed":
                    break
                await anyio.sleep(0.05)
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=60)

    assert "running" in stages, stages
    assert stages[-1] == "completed", stages
    final = row(dsn, inv.investigation_id)
    assert (final["disposition"], final["failure_reason"], final["cost_usd"]) == ("inconclusive", None, 0)
    assert final["started_at"] is not None
    assert final["finished_at"] is not None


# --- O7 ------------------------------------------------------------------------------------------

def _box_of(containers: Path, inv: str) -> Path:
    """The stand-in container the child's box start made for `inv`: filed under the claim its worker handed the child."""
    [box] = containers.glob(f"claims/*/defender-run-{inv}")
    return box


# Retired (#1170 A4, A5, B10): `test_o7_killing_the_worker_ends_the_child_through_its_unwind_but_leaves_the_box` and
# `test_o7_stopping_the_worker_terminates_the_child_removes_the_box_and_leaves_the_row` drove the retired host job entry
# (`_blocking_entry1342.py` calling `run.job_main` with no job socket, which now does nothing by design), and the first
# pinned "the box outlives a killed worker", which the box-ends-with-its-helper rule replaces. Their surviving behaviour
# is carried by `test_job_helper.py::test_a5_killing_the_worker_ends_its_helper_and_the_helpers_container_goes_with_it`
# (the death tie), `::test_o7_a_stop_from_the_worker_stops_the_container_gracefully_lets_the_job_write_its_end_then_removes_by_label`
# (the worker's stop: graceful stop, then removal by the claim's label), `::test_o9_..._shaped_by_the_helper` (the run box
# stamped with the launch record's box token) and `test_o7_a_deliberate_stop_sends_sigterm_to_every_child_and_writes_no_row`
# below (the row is left as it was).


def _scripted_config(dsn: str, root: Path, runs: Path, tmp_path: Path, **options) -> dict:
    return {"dsn": dsn, "data_root": str(root), "child": "scripted", "where": str(tmp_path / "child"),
            "runs": str(runs), "wait_for": str(tmp_path / "never"), "containers": str(tmp_path / "containers"),
            "options": options, "stop_grace": 2.0}


@pytest.mark.parametrize("stop", [signal.SIGTERM, signal.SIGINT])
async def test_o7_a_deliberate_stop_sends_sigterm_to_every_child_and_writes_no_row(
        migrated_database, tmp_path, stop):
    """SIGTERM or SIGINT to the worker: each of two children gets SIGTERM, the sweeps run (each box carries its own child's claim and claim's token), both rows stay `running`. (O7, D3, r5 C1)"""
    dsn, root = migrated_database, tmp_path / "data"
    register_tenant(dsn, T1)
    runs = root / T1 / "runs"
    runs.mkdir(parents=True)
    containers = tmp_path / "containers"
    containers.mkdir()
    async with job_store(dsn) as store:
        ids = []
        for n in range(2):
            alert = await an_alert(store, T1, ticket=f"T-{n}")
            inv, _ = await store.create_investigation(T1, alert.alert_id, f"k{n}", actor="u-1")
            ids.append(inv.investigation_id)
        config = _scripted_config(dsn, root, runs, tmp_path, term="mark",
                                  term_mark=str(tmp_path / "termed-{id}"), box_dir=str(containers))
        with worker_process(tmp_path, config) as proc:
            seen = tmp_path / "child" / "seen"
            _wait(lambda: len(list(seen.glob("*.json"))) == 2, timeout=60, what="both children")
            for i in ids:  # the stand-in is planted after `seen`: signal only once both exist
                _wait(lambda i=i: list(containers.glob(f"claims/*/defender-run-{i}")), timeout=30, what="the child's box")
            boxes = {i: _box_of(containers, i) for i in ids}
            for i, box in boxes.items():
                _wait(lambda b=box: b.read_text(encoding="utf-8") != "", timeout=30, what="the child's box token")
                launch = json.loads((runs / f"{i}.launch.json").read_text(encoding="utf-8"))
                assert box.read_text(encoding="utf-8") == launch["box_token"], "the box carries another claim's token"
            assert len({b.read_text(encoding="utf-8") for b in boxes.values()}) == 2
            proc.send_signal(stop)
            proc.wait(timeout=60)

    for i in ids:
        _wait(lambda i=i: (tmp_path / f"termed-{i}").exists(), timeout=30, what="the child's SIGTERM")
        assert not boxes[i].exists(), "the sweep left a box"
        assert row(dsn, i)["stage"] == "running"


async def test_o7_a_child_that_ignores_sigterm_is_group_killed_after_the_grace(migrated_database, tmp_path):
    """After `stop_grace` the child's whole group is SIGKILLed; the worker's own group is untouched; the row stays `running`. (O7, M8)"""
    dsn, root = migrated_database, tmp_path / "data"
    register_tenant(dsn, T1)
    runs = root / T1 / "runs"
    runs.mkdir(parents=True)
    (tmp_path / "containers").mkdir()
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
    config = _scripted_config(dsn, root, runs, tmp_path, term="ignore", grandchild=True,
                              box_dir=str(tmp_path / "containers"))
    with worker_process(tmp_path, config) as proc:
        seen = tmp_path / "child" / "seen"
        _wait(lambda: len(list(seen.glob("*.json"))) == 1, timeout=60, what="the child")
        record = json.loads(next(seen.glob("*.json")).read_text(encoding="utf-8"))
        child_pid, grandchild_pid = record["pid"], record["grandchild"]
        assert grandchild_pid
        _wait(lambda: list((tmp_path / "containers").glob(f"claims/*/defender-run-{inv.investigation_id}")),
              timeout=30, what="the child's box")
        box = _box_of(tmp_path / "containers", inv.investigation_id)  # the child's box start made it, under its claim
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.5)
        assert not _gone(child_pid), "the child died on SIGTERM although it ignores it: no grace"
        proc.wait(timeout=60)
        elapsed = time.monotonic() - started

    assert elapsed >= 1.0, f"the worker stopped after {elapsed:.1f}s, before the 2s grace"
    _wait(lambda: _gone(child_pid) and _gone(grandchild_pid), timeout=30, what="the group kill")
    assert not box.exists()
    assert row(dsn, inv.investigation_id)["stage"] == "running"


async def test_o7_serve_takes_sigterm_itself_and_returns(migrated_database, tmp_path):
    """`serve()` installs its own SIGTERM handling: the signal stops it (idle, no rows) instead of reaching the process's prior handler. (O7, M8)"""
    import asyncio

    from defender.tests.support.jobs._jobs1342 import StandInContainers, make_worker

    caught: list[int] = []
    previous = {s: signal.signal(s, lambda n, _f: caught.append(n)) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        async with job_store(migrated_database) as store:
            worker = make_worker(store, Path("/nonexistent-root"), lambda launch: [sys.executable],
                                 containers=StandInContainers(tmp_path / "containers"))
            serving = asyncio.create_task(worker.serve())
            await asyncio.sleep(0.5)
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=30)
        assert caught == [], "serve did not take the signal itself"
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)


# --- O6 ------------------------------------------------------------------------------------------

def test_o6_the_default_child_argv_is_the_per_job_host_helper():
    """CONFLICT (was `run.py --job ... --parent-pid`): the worker's default child is the host helper,
    `python -m defender.job_host --kind investigation --job <id> --tenant <T> --parent-pid <pid>`; the
    host-mode `run.py --job` is retired (#1170 A6, H7)."""
    from defender.worker import Launch, run_argv

    launch = Launch(investigation_id="i-1", tenant_id=T1, parent_pid=4242)
    assert run_argv(launch) == [sys.executable, "-m", "defender.job_host", "--kind", "investigation",
                                "--job", "i-1", "--tenant", T1, "--parent-pid", "4242"]
    assert "run.py" not in " ".join(run_argv(launch)), "the retired host-mode job entry is still the child"
