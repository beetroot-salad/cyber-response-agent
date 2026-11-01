"""#1108 P4: how the launcher stops a publish child and how the child takes a stop, each case a
wrong-but-green production variant. Real processes, real signals, the real tenant lock."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, current_commit
import contextlib

WORKTREE = Path(__file__).resolve().parents[4]
OID = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture
def child_env(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        yield t


# --- the child is asked to end, and given time to unwind, before it is killed -------------------

_UNWINDS = '''
import pathlib, signal, sys, time
marker = pathlib.Path(sys.argv[1])
def stopped(*_):
    time.sleep(1.5)  # unwinding its network calls takes a moment
    marker.write_text("unwound")
    sys.exit(143)
signal.signal(signal.SIGTERM, stopped)
(marker.parent / "ready").write_text("1")
time.sleep(60)
'''


def test_r6_a_child_that_ends_when_asked_is_given_time_to_unwind_before_any_kill(tmp_path):
    marker = tmp_path / "marker"
    line = B.launcher()("r6-tenant", data_root=tmp_path, budget=2.0,
                        command=[sys.executable, "-c", _UNWINDS, str(marker)])
    assert B.outcome_class(line) == "stale:transient", line
    assert marker.read_text() == "unwound", (
        "the child was killed instead of asked to end and given time to unwind")


# --- a kill takes the child's whole process group ----------------------------------------------

_STUBBORN = '''
import pathlib, signal, subprocess, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(25)"])
pathlib.Path(sys.argv[1]).write_text(str(grandchild.pid))
time.sleep(60)
'''


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):  # reaped between the kill(0) and the read
        return False
    return stat[stat.rindex(")") + 2] != "Z"


def _outlives(pid: int) -> bool:
    """Still alive after 2 seconds? A SIGKILL is delivered asynchronously: the launch returns
    once the group's pipes close, which can be a moment before the grandchild's exit."""
    deadline = time.monotonic() + 2.0
    while _alive(pid):
        if time.monotonic() > deadline:
            return True
        time.sleep(0.02)
    return False


def test_r6_a_killed_child_takes_its_grandchildren_and_the_launch_does_not_wait_on_them(tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    started = time.monotonic()
    try:
        line = B.launcher()("r6-tenant", data_root=tmp_path, budget=1.0,
                            command=[sys.executable, "-c", _STUBBORN, str(pidfile)])
        elapsed = time.monotonic() - started
        grandchild = int(pidfile.read_text())
        assert B.outcome_class(line) == "stale:transient", line
        assert elapsed < 15, f"the launch waited {elapsed:.1f}s on a grandchild holding its pipes"
        assert not _outlives(grandchild), "the child's grandchild outlived the kill"
    finally:
        if pidfile.exists():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(pidfile.read_text()), signal.SIGKILL)


# --- a child that takes the lock while being stopped is never killed ---------------------------

_LOCKS_WHEN_ASKED = '''
import pathlib, signal, sys, time
from defender.learning.author.version_control import tenant_lock
from defender.tenancy._tenant import data_root_from_path, requested_tenant
marks = pathlib.Path(sys.argv[1])
asked = []
signal.signal(signal.SIGTERM, lambda *_: asked.append(1))
tenant = requested_tenant(data_root_from_path(pathlib.Path(sys.argv[4])), sys.argv[2])
(marks / "ready").write_text("1")
while not asked:
    time.sleep(0.02)
with tenant_lock(tenant):
    (marks / "locked").write_text("1")
    time.sleep(7.5)  # past the launcher's whole grace for a stop
    (marks / "finished").write_text("1")
print("fresh " + sys.argv[5])
'''


def test_r6_a_child_that_takes_the_lock_after_being_asked_to_stop_is_let_finish(
        tenant, tmp_path, child_env):
    marks = tmp_path / "marks"
    marks.mkdir()
    code = _LOCKS_WHEN_ASKED.replace("sys.argv[5]", repr(OID))
    line = B.launcher()(tenant.tenant_id, data_root=tenant.data_root, budget=1.5,
                        command=[sys.executable, "-c", code, str(marks)])
    assert (marks / "finished").exists(), "a child holding the tenant lock was killed"
    # The child's own report is the outcome, however the wait ended: it published, so calling
    # the run stale would be false.
    assert B.outcome_class(line) == "fresh", line


# --- a child in its locked phase ignores SIGTERM and finishes -----------------------------------

def test_r6_a_real_child_in_its_locked_phase_ignores_sigterm_and_finishes(
        tenant, tmp_path, child_env):
    merged = tenant.merge(B.MERGE_FILES)
    command, _spec, marks = B.child_command(tenant, tmp_path, network_timeout=60.0,
                                            locked_sleep=3.0)
    proc = subprocess.Popen([*command, tenant.tenant_id, "--data-root", str(tenant.data_root)],  # noqa: S603
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 60
        while not (marks / "locked").exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert (marks / "locked").exists(), "premise: the child never reached its locked phase"
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert (marks / "locked-done").exists(), f"SIGTERM cut the locked phase short: {err[-500:]}"
    assert proc.returncode == 0, (proc.returncode, err[-500:])
    assert out.strip().splitlines()[-1] == f"fresh {merged}", out
    assert current_commit(tenant.tenant) == merged


# --- the child's signal state is its own to restore --------------------------------------------

def test_r6_the_child_entry_restores_the_sigterm_handler_and_clears_its_locked_flag(
        tenant, tmp_path):
    from defender.learning.author import version_control as vc
    from defender.learning.author.version_control import publish

    before = signal.getsignal(signal.SIGTERM)
    for _ in range(2):
        rc = vc.publish_child_main(
            [tenant.tenant_id, "--data-root", str(tenant.data_root)], directory=tenant.directory,
            client=tenant.forge.client, identity=tenant.vault.identity(), network_timeout=30.0)
        assert rc == 0
        assert signal.getsignal(signal.SIGTERM) is before
        assert publish._LOCKED.held is False


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
