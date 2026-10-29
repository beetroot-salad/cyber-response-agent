"""#1342 across real processes: the death tie when the worker is killed or stopped (O7, M8), a
worker in another process running what this one queued (O15), `serve()`'s own signal handlers, and
the worker's default child argv (O6).

The worker runs as `_worker_proc1342.py` (its own process, `serve()` until SIGTERM/SIGINT). Children
are the scripted stand-in or `_blocking_entry1342.py`, which calls the real job entry (never the real
`run.py`). Every wait is bounded."""
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


def _env(data_root: Path) -> dict[str, str]:
    return {**os.environ, "DEFENDER_DATA_ROOT": str(data_root),
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
        env=_env(Path(config["data_root"])), cwd=str(WORKTREE), stderr=subprocess.PIPE)
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
    """Shared only the database and the data root: the stage moves queued → running → completed, read from here. (O15)"""
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
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        assert inv.stage == "queued"
        config = {"dsn": dsn, "data_root": str(root), "child": "scripted", "where": str(tmp_path / "child"),
                  "runs": str(runs), "wait_for": str(release), "containers": str(tmp_path / "containers"),
                  "files": {"{id}.job-end.json": job_end(), "{id}/report.md": golden}}
        with worker_process(tmp_path, config) as proc:
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

    assert stages[0] == "queued", stages
    assert "running" in stages, stages
    assert stages[-1] == "completed", stages
    final = row(dsn, inv.investigation_id)
    assert (final["disposition"], final["failure_reason"], final["cost_usd"]) == ("inconclusive", None, 0)
    assert final["started_at"] is not None
    assert final["finished_at"] is not None


# --- O7 ------------------------------------------------------------------------------------------

def _blocking_config(dsn: str, root: Path, tmp_path: Path, t, *, stop_grace: float = 10.0) -> dict:
    marks, containers = tmp_path / "marks", tmp_path / "containers"
    containers.mkdir(exist_ok=True)
    (root / t.tenant_id / "runs").mkdir(exist_ok=True)  # R1: tenant setup makes `runs/`
    return {"dsn": dsn, "data_root": str(root), "child": "entry",
            "entry": str(SUPPORT / "_blocking_entry1342.py"), "marks": str(marks), "commit": t.commit,
            "containers": str(containers), "stop_grace": stop_grace}


def _blocked_child(marks: Path, proc: subprocess.Popen) -> int:
    _wait(lambda: (marks / "in-lifecycle").exists() or proc.poll() is not None, timeout=120,
          what="the child's lifecycle")
    assert (marks / "in-lifecycle").exists(), "the child never reached its lifecycle"
    return int((marks / "pid").read_text(encoding="utf-8"))


async def test_o7_killing_the_worker_ends_the_child_through_its_unwind_but_leaves_the_box(
        migrated_database, tmp_path):
    """SIGKILL of the worker: the child exits via the parent-death signal and runs stop-box; the box is not removed (no backstop); the row stays `running`. (O7, M8)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    dsn, root = migrated_database, tmp_path / "data"
    root.mkdir()
    with B.run_tenant(tmp_path, root) as t:
        register_tenant(dsn, t.tenant_id)
        async with job_store(dsn) as store:
            alert = await an_alert(store, t.tenant_id)
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
        config = _blocking_config(dsn, root, tmp_path, t)
        box = tmp_path / "containers" / f"defender-run-{inv.investigation_id}"
        box.touch()
        with worker_process(tmp_path, config) as proc:
            child_pid = _blocked_child(tmp_path / "marks", proc)
            proc.kill()
            proc.wait(timeout=60)

    _wait(lambda: _gone(child_pid), timeout=30, what="the child to exit with its worker")
    assert (tmp_path / "marks" / "stop-box").exists(), "the child's box teardown did not run"
    assert box.exists(), "with the worker killed outright nothing removes the box (r3's residual)"
    assert row(dsn, inv.investigation_id)["stage"] == "running"


async def test_o7_stopping_the_worker_terminates_the_child_removes_the_box_and_leaves_the_row(
        migrated_database, tmp_path):
    """SIGTERM to the worker: SIGTERM to the child, stop-box runs, the backstop removes the box, the row stays `running`. (O7, M8, D3)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    dsn, root = migrated_database, tmp_path / "data"
    root.mkdir()
    with B.run_tenant(tmp_path, root) as t:
        register_tenant(dsn, t.tenant_id)
        async with job_store(dsn) as store:
            alert = await an_alert(store, t.tenant_id)
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
        config = _blocking_config(dsn, root, tmp_path, t)
        box = tmp_path / "containers" / f"defender-run-{inv.investigation_id}"
        box.touch()
        with worker_process(tmp_path, config) as proc:
            child_pid = _blocked_child(tmp_path / "marks", proc)
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=60)

    _wait(lambda: _gone(child_pid), timeout=30, what="the child to exit")
    assert (tmp_path / "marks" / "stop-box").exists(), "the child's box teardown did not run"
    assert not box.exists(), "the backstop left the box"
    assert row(dsn, inv.investigation_id)["stage"] == "running"


def _scripted_config(dsn: str, root: Path, runs: Path, tmp_path: Path, **options) -> dict:
    return {"dsn": dsn, "data_root": str(root), "child": "scripted", "where": str(tmp_path / "child"),
            "runs": str(runs), "wait_for": str(tmp_path / "never"), "containers": str(tmp_path / "containers"),
            "options": options, "stop_grace": 2.0}


@pytest.mark.parametrize("stop", [signal.SIGTERM, signal.SIGINT])
async def test_o7_a_deliberate_stop_sends_sigterm_to_every_child_and_writes_no_row(
        migrated_database, tmp_path, stop):
    """SIGTERM or SIGINT to the worker: each of two children gets SIGTERM, backstops run, both rows stay `running`. (O7, D3)"""
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
            (containers / f"defender-run-{inv.investigation_id}").touch()
        config = _scripted_config(dsn, root, runs, tmp_path, term="mark",
                                  term_mark=str(tmp_path / "termed-{id}"))
        with worker_process(tmp_path, config) as proc:
            seen = tmp_path / "child" / "seen"
            _wait(lambda: len(list(seen.glob("*.json"))) == 2, timeout=60, what="both children")
            proc.send_signal(stop)
            proc.wait(timeout=60)

    for i in ids:
        _wait(lambda i=i: (tmp_path / f"termed-{i}").exists(), timeout=30, what="the child's SIGTERM")
        assert not (containers / f"defender-run-{i}").exists(), "the backstop left a box"
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
    box = tmp_path / "containers" / f"defender-run-{inv.investigation_id}"
    box.touch()
    config = _scripted_config(dsn, root, runs, tmp_path, term="ignore", grandchild=True)
    with worker_process(tmp_path, config) as proc:
        seen = tmp_path / "child" / "seen"
        _wait(lambda: len(list(seen.glob("*.json"))) == 1, timeout=60, what="the child")
        record = json.loads(next(seen.glob("*.json")).read_text(encoding="utf-8"))
        child_pid, grandchild_pid = record["pid"], record["grandchild"]
        assert grandchild_pid
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


async def test_o7_serve_takes_sigterm_itself_and_returns(migrated_database):
    """`serve()` installs its own SIGTERM handling: the signal stops it (idle, no rows) instead of reaching the process's prior handler. (O7, M8)"""
    import asyncio

    from defender.tests.support.jobs._jobs1342 import make_worker

    caught: list[int] = []
    previous = {s: signal.signal(s, lambda n, _f: caught.append(n)) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        async with job_store(migrated_database) as store:
            worker = make_worker(store, Path("/nonexistent-root"), lambda launch: [sys.executable])
            serving = asyncio.create_task(worker.serve())
            await asyncio.sleep(0.5)
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=30)
        assert caught == [], "serve did not take the signal itself"
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)


# --- O6 ------------------------------------------------------------------------------------------

def test_o6_the_default_child_argv_is_run_py_job():
    """The worker's default child is `run.py --job <id> --tenant <T> --parent-pid <pid>`. (O6)"""
    from defender.worker import Launch, run_argv

    launch = Launch(investigation_id="i-1", tenant_id=T1, parent_pid=4242)
    assert run_argv(launch) == [sys.executable, str(DEFENDER / "run.py"), "--job", "i-1",
                                "--tenant", T1, "--parent-pid", "4242"]
