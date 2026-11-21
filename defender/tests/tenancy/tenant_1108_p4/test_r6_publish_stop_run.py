"""#1108 P4: a stopped run takes its publish child's group with it (split from test_r6_publish_stop)."""
from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


from defender.tests.tenancy.tenant_1108_p4._r6_support import (  # noqa: F401  (fixtures)
    OID, _alive, _outlives)
from defender.tests.tenancy.tenant_1108_p4._support import current_commit  # noqa: F401


# --- the run process stopped while it waits: the child's group goes with it ---------------------

_WAITING_CHILD = '''
import pathlib, subprocess, sys, time
grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
pathlib.Path(sys.argv[1]).write_text(f"{__import__('os').getpid()} {grandchild.pid}")
time.sleep(60)
'''

_RUN_START_PUBLISHING = '''
import functools, pathlib, sys, types
from defender import run, tenancy
from defender.investigation.publish_launch import launch_publish
publish = functools.partial(launch_publish, budget=60.0,
                            command=[sys.executable, "-c", sys.argv[1], sys.argv[2]])
run._publish_report(publish, types.SimpleNamespace(id="r6-tenant"),
                    tenancy.data_root_from_path(pathlib.Path(sys.argv[3])), None)
print("the publish returned", flush=True)
'''


def test_r6_a_run_start_stopped_while_its_publish_runs_takes_the_childs_group_with_it(tmp_path, child_env):
    """Teardown SIGTERMs the recorded run process while the launch-time publish runs: the run exits non-zero and the
    publish child's whole process group (its own session) is gone, so nothing keeps writing into the tenant's folder
    that teardown is removing (PR #1350 review)."""
    pidfile = tmp_path / "child.pids"
    parent = subprocess.Popen([sys.executable, "-c", _RUN_START_PUBLISHING, _WAITING_CHILD, str(pidfile), str(tmp_path)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pids: list[int] = []
    try:
        deadline = time.monotonic() + 30
        while not (pidfile.exists() and len(pidfile.read_text().split()) == 2):
            assert parent.poll() is None, parent.communicate()
            assert time.monotonic() < deadline, "the publish child never started"
            time.sleep(0.02)
        pids = [int(p) for p in pidfile.read_text().split()]
        assert all(_alive(p) for p in pids), "control: the child and its grandchild run while the publish waits"
        parent.send_signal(signal.SIGTERM)
        out, err = parent.communicate(timeout=20)
        assert parent.returncode != 0, (out, err)
        assert b"the publish returned" not in out, "a stopped run went on past its publish"
        for pid in pids:
            assert not _outlives(pid), f"process {pid} of the publish child's group outlived the stopped run"
    finally:
        if parent.poll() is None:
            parent.kill()
        for pid in pids:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)



def test_1379_a_run_start_stopped_while_its_publish_will_not_stop_kills_it_after_the_grace(tmp_path, child_env):
    """A publish child in its network phase that ignores the run's stop is killed after the launcher's grace, with
    its whole group, and the run exits non-zero: the run never waits on it without limit. (#1379 r3 O3)"""
    from defender.investigation import publish_launch

    pidfile = tmp_path / "child.pids"
    stubborn = "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN)\n" + _WAITING_CHILD
    parent = subprocess.Popen([sys.executable, "-c", _RUN_START_PUBLISHING, stubborn, str(pidfile), str(tmp_path)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pids: list[int] = []
    try:
        deadline = time.monotonic() + 30
        while not (pidfile.exists() and len(pidfile.read_text().split()) == 2):
            assert parent.poll() is None, parent.communicate()
            assert time.monotonic() < deadline, "the publish child never started"
            time.sleep(0.02)
        pids = [int(p) for p in pidfile.read_text().split()]
        parent.send_signal(signal.SIGTERM)
        out, err = parent.communicate(timeout=publish_launch._STOP_GRACE + 10)
        assert parent.returncode != 0, (out, err)
        assert b"the publish returned" not in out, "a stopped run went on past its publish"
        for pid in pids:
            assert not _outlives(pid), f"process {pid} of the publish child's group outlived the stopped run"
    finally:
        if parent.poll() is None:
            parent.kill()
        for pid in pids:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)


def test_r6_the_publish_wait_puts_back_the_sigterm_handler_it_found():
    """The run's publish wait turns SIGTERM into its own unwinding only while it waits: the handler it found is back
    afterwards, and a launcher that returns normally is read as before."""
    from defender import run, tenancy

    def mine(*_a: object) -> None:
        return None

    seen: list[object] = []

    def publish(*_a: object, **_k: object) -> str:
        seen.append(signal.getsignal(signal.SIGTERM))
        return f"fresh {OID}"

    before = signal.signal(signal.SIGTERM, mine)
    try:
        report = run._publish_report(publish, type("T", (), {"id": "r6-tenant"})(),
                                     tenancy.data_root_from_path(Path("/nonexistent")), None)
        assert signal.getsignal(signal.SIGTERM) is mine, "the publish wait did not put back the handler it found"
    finally:
        signal.signal(signal.SIGTERM, before)
    assert seen, "the publish was not called"
    assert seen[0] is not mine, "SIGTERM was not taken over while the publish ran"
    assert not report.unreadable, report
