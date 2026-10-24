"""#1108 P4 round 6 — how the launcher stops a publish child and how the child takes a stop
(each case was a wrong-but-green production variant): the child is asked to end (SIGTERM) and
given time to unwind before it is killed; a kill takes its whole process group; a child that
takes the tenant lock while being stopped is never killed; a child already in its locked phase
ignores SIGTERM and finishes. Real processes, real signals, the real tenant lock."""
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
    stat = Path(f"/proc/{pid}/stat").read_text() if Path(f"/proc/{pid}/stat").exists() else "Z"
    return stat[stat.rindex(")") + 2] != "Z"


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
        assert not _alive(grandchild), "the child's grandchild outlived the kill"
    finally:
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


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
    assert B.outcome_class(line) == "stale:transient", line  # it did not finish within the budget


# --- a child in its locked phase ignores SIGTERM and finishes (B02) -----------------------------

def test_r6_a_real_child_in_its_locked_phase_ignores_sigterm_and_finishes(
        tenant, tmp_path, child_env):
    merged = tenant.merge(B.MERGE_FILES)
    config = B.write_issuer_config(tmp_path / "operator")
    command, _spec, marks = B.child_command(tenant, tmp_path, config, network_timeout=60.0,
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


# --- the child's signal state is its own to restore (B04, B05) ----------------------------------

def test_r6_the_child_entry_restores_the_sigterm_handler_and_clears_its_locked_flag(
        tenant, tmp_path):
    from defender.learning.author import version_control as vc
    from defender.learning.author.version_control import publish

    config = B.write_issuer_config(tmp_path / "operator")
    before = signal.getsignal(signal.SIGTERM)
    for _ in range(2):
        rc = vc.publish_child_main(
            [tenant.tenant_id, "--data-root", str(tenant.data_root)], issuer_config=config,
            client=tenant.forge.client, identity=tenant.vault.identity(), network_timeout=30.0)
        assert rc == 0
        assert signal.getsignal(signal.SIGTERM) is before
        assert publish._LOCKED.held is False
