"""#1379: a stopped run waits for a lock-holding publish child (split from test_r6_publish_stop)."""
from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import time

import pytest

from defender.tests.tenancy.tenant_1108_p4._r6_support import (  # noqa: F401  (fixtures)
    OID, _alive, _outlives)
from defender.tests.tenancy.tenant_1108_p4._support import current_commit  # noqa: F401


_LOCKED_WHEN_THE_RUN_IS_STOPPED = '''
import os, pathlib, signal, sys, time
marks = pathlib.Path(sys.argv[1])
# Ignored, as the real child does while locked; noted only when it comes while the lock is held (a stop
# that comes first, while it still imports, is the launcher's to send).
signal.signal(signal.SIGTERM, lambda *_: (marks / "locked").exists() and (marks / "asked").write_text("1"))
(marks / "pid").write_text(str(os.getpid()))
from defender.learning.author.version_control import tenant_lock
from defender.tenancy._tenant import data_root_from_path, requested_tenant
tenant = requested_tenant(data_root_from_path(pathlib.Path(sys.argv[4])), sys.argv[2])
with tenant_lock(tenant):
    (marks / "locked").write_text("1")
    time.sleep(float(sys.argv[6]))
    (marks / "finished").write_text("1")
print("fresh " + sys.argv[5])
'''

_RUN_START_PUBLISHING_FOR = '''
import functools, pathlib, sys, types
from defender import run, tenancy
from defender.investigation.publish_launch import launch_publish
publish = functools.partial(launch_publish, budget=float(sys.argv[5]),
                            command=[sys.executable, "-c", sys.argv[1], sys.argv[2]])
run._publish_report(publish, types.SimpleNamespace(id=sys.argv[4]),
                    tenancy.data_root_from_path(pathlib.Path(sys.argv[3])), None)
print("the publish returned", flush=True)
'''


def _stop_a_run_whose_publish_holds_the_lock(tenant, tmp_path, *, budget, locked_for, stops, after_lock=0.0,
                                             child=_LOCKED_WHEN_THE_RUN_IS_STOPPED):
    """Run start with a publish child that takes the tenant lock at once and holds it `locked_for` seconds (ignoring
    SIGTERM, as the real child does while locked); once it holds the lock and `after_lock` has passed, the run is sent
    SIGTERM `stops` times. Returns the marks folder and the run's (returncode, out, err)."""
    marks = tmp_path / "marks"
    marks.mkdir()
    code = child.replace("sys.argv[5]", repr(OID)).replace("sys.argv[6]", repr(str(locked_for)))
    parent = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", _RUN_START_PUBLISHING_FOR, code, str(marks), str(tenant.data_root),
         tenant.tenant_id, str(budget)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 30
        while not (marks / "locked").exists():
            assert parent.poll() is None, parent.communicate()
            assert time.monotonic() < deadline, "premise: the publish child never took the lock"
            time.sleep(0.02)
        time.sleep(after_lock)
        for _ in range(stops):
            parent.send_signal(signal.SIGTERM)
            time.sleep(0.3)
        out, err = parent.communicate(timeout=30)
    finally:
        if parent.poll() is None:
            parent.kill()
        with contextlib.suppress(OSError, ValueError):  # never leave a lock holder behind on a failure
            os.kill(int((marks / "pid").read_text()), signal.SIGKILL)
    return marks, (parent.returncode, out, err)


@pytest.mark.parametrize(("budget", "after_lock", "stops"), [
    pytest.param(60.0, 0.0, 1, id="stopped within the budget"),
    pytest.param(1.0, 1.5, 1, id="stopped after the budget ran out"),
    pytest.param(60.0, 0.0, 3, id="stopped again while it waits"),
])
def test_1379_a_run_start_stopped_while_its_publish_holds_the_lock_waits_for_it_to_finish(
        tenant, tmp_path, child_env, budget, after_lock, stops):
    """However the run's stop arrives (within the publish budget, after it ran out, or repeated), a publish child
    holding the tenant lock is never signalled and finishes its locked phase (O-BUDGET) before the run exits; the run
    then exits as stopped and never goes on. (#1379 r3 O3)"""
    from defender.investigation import publish_launch

    marks, (returncode, out, err) = _stop_a_run_whose_publish_holds_the_lock(  # held past the launcher's grace
        tenant, tmp_path, budget=budget, locked_for=publish_launch._STOP_GRACE + 2 + after_lock, stops=stops,
        after_lock=after_lock)
    assert (marks / "finished").exists(), f"the run's stop cut a lock-holding publish child: {err[-500:]!r}"
    assert not (marks / "asked").exists(), "a publish child holding the lock was signalled"
    assert returncode == 128 + signal.SIGTERM, (out, err)
    assert b"the publish returned" not in out, "a stopped run went on past its publish"


_PAST_THE_LOCK = '''
import os, pathlib, signal, sys, time
marks = pathlib.Path(sys.argv[1])
(marks / "pid").write_text(str(os.getpid()))
from defender.learning.author.version_control import tenant_lock
from defender.tenancy._tenant import data_root_from_path, requested_tenant
tenant = requested_tenant(data_root_from_path(pathlib.Path(sys.argv[4])), sys.argv[2])
signal.signal(signal.SIGTERM, signal.SIG_IGN)  # ignored while locked, as the real child does
with tenant_lock(tenant):
    pass
signal.signal(signal.SIGTERM, signal.SIG_DFL)  # the real child's flag clears with the lock
(marks / "locked").write_text("1")  # released: what remains is recording and printing its report
time.sleep(float(sys.argv[6]))
(marks / "finished").write_text("1")
print("fresh " + sys.argv[5])
'''


def test_1379_a_publish_child_past_its_locked_phase_is_not_signalled_while_it_reports(tenant, tmp_path, child_env):
    """A publish child that has left its locked phase, but still records and prints its report, is not signalled by
    the run's stop: its fresh publish is not turned into a failure. (#1379 r3 O3, review of PR #1395)"""
    marks, (returncode, out, err) = _stop_a_run_whose_publish_holds_the_lock(
        tenant, tmp_path, budget=60.0, locked_for=2.0, stops=1, child=_PAST_THE_LOCK)
    assert (marks / "finished").exists(), f"the run's stop cut a publish child reporting its publish: {err[-500:]!r}"
    assert returncode == 128 + signal.SIGTERM, (out, err)


