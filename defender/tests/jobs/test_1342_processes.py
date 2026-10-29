"""#1342 across real processes: the death tie on a deliberate worker stop (O7), a worker in another
process running what this one queued (O15), and the real `run.py --job` refusing an id that has no
launch record (O6).

The worker runs as `_worker_proc1342.py` (its own process, `serve()` until SIGTERM). Children are the
scripted stand-in or `_blocking_entry1342.py`, which calls the real job entry. Every wait is bounded."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from defender.tests.support.jobs._jobs1342 import (
    DEFENDER,
    T1,
    WORKTREE,
    an_alert,
    job_end,
    job_store,
    register_tenant,
    row,
    scrub_verdict,
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
    golden = (DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd" / "report.md").read_text(encoding="utf-8")
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        assert inv.stage == "queued"
        config = {"dsn": dsn, "data_root": str(root), "child": "scripted", "where": str(tmp_path / "child"),
                  "runs": str(runs), "wait_for": str(release), "containers": str(tmp_path / "containers"),
                  "files": {"{id}.job-end.json": job_end(), "{id}.scrub-verdict.json": scrub_verdict(ran=True),
                            "{id}/report.md": golden}}
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


# --- O7 ------------------------------------------------------------------------------------------

async def test_o7_a_deliberate_worker_stop_ends_its_child_reaps_its_box_and_leaves_the_row_running(
        migrated_database, tmp_path):
    """SIGTERM to the worker: the child unwinds through stop-box and exits, the leftover box is removed, the row stays `running` (D3). (O7)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    dsn = migrated_database
    root = tmp_path / "data"
    root.mkdir()
    marks = tmp_path / "marks"
    containers = tmp_path / "containers"
    containers.mkdir()
    with B.run_tenant(tmp_path, root) as t:
        register_tenant(dsn, t.tenant_id)
        async with job_store(dsn) as store:
            alert = await an_alert(store, t.tenant_id)
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
        (containers / f"defender-run-{inv.investigation_id}").touch()
        config = {"dsn": dsn, "data_root": str(root), "child": "entry",
                  "entry": str(SUPPORT / "_blocking_entry1342.py"), "marks": str(marks),
                  "commit": t.commit, "containers": str(containers), "stop_grace": 10.0}
        with worker_process(tmp_path, config) as proc:
            _wait(lambda: (marks / "in-lifecycle").exists() or proc.poll() is not None, timeout=120,
                  what="the child's lifecycle")
            assert (marks / "in-lifecycle").exists(), "the child never reached its lifecycle"
            child_pid = int((marks / "pid").read_text(encoding="utf-8"))
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=60)

    _wait(lambda: _gone(child_pid), timeout=30, what="the child to exit")
    assert (marks / "stop-box").exists(), "the child's box teardown did not run"
    assert not (containers / f"defender-run-{inv.investigation_id}").exists(), "the backstop left the box"
    assert row(dsn, inv.investigation_id)["stage"] == "running"


# --- O6 ------------------------------------------------------------------------------------------

def test_o6_the_real_run_py_refuses_a_job_id_with_no_launch_record(tmp_path):
    """`run.py --job <id>` with no `<id>.launch.json`: exit 1 naming the launch record, `setup: refused`, no run folder. (O6)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = tmp_path / "data"
    root.mkdir()
    run_id = str(uuid.uuid4())
    with B.run_tenant(tmp_path, root) as t:
        proc = subprocess.run(  # noqa: S603 — the real run entry
            [sys.executable, str(DEFENDER / "run.py"), "--job", run_id, "--tenant", t.tenant_id,
             "--parent-pid", str(os.getpid())],
            env=_env(root), cwd=str(WORKTREE), capture_output=True, text=True, timeout=180, check=False)
        runs = root / t.tenant_id / "runs"

        assert "unrecognized arguments" not in proc.stderr, proc.stderr
        assert proc.returncode == 1, proc.stderr[-2000:]
        assert "launch" in proc.stderr.lower(), proc.stderr[-2000:]
        assert not (runs / run_id).exists()
        record = json.loads((runs / f"{run_id}.job-end.json").read_text(encoding="utf-8"))
        assert record["setup"] == "refused"


def test_o6_the_default_child_argv_is_run_py_job():
    """The worker's default child is `run.py --job <id> --tenant <T> --parent-pid <pid>`. (O6)"""
    from defender.worker import Launch, run_argv

    launch = Launch(investigation_id="i-1", tenant_id=T1, parent_pid=4242)
    assert run_argv(launch) == [sys.executable, str(DEFENDER / "run.py"), "--job", "i-1",
                                "--tenant", T1, "--parent-pid", "4242"]


def test_o6_sidecar_lists_split_used_within_accepted():
    """Launch and alert files are accepted only; the job-end record is used and accepted. (O6)"""
    from defender.records._layout import ACCEPTED_SIDECAR_SUFFIXES, USED_SIDECAR_SUFFIXES

    assert set(USED_SIDECAR_SUFFIXES) <= set(ACCEPTED_SIDECAR_SUFFIXES)
    for suffix in (".launch.json", ".alert.json"):
        assert suffix in ACCEPTED_SIDECAR_SUFFIXES
        assert suffix not in USED_SIDECAR_SUFFIXES
    assert ".job-end.json" in USED_SIDECAR_SUFFIXES
