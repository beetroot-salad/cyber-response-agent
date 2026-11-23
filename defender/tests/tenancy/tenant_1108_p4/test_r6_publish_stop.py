"""#1108 P4 r6 and #1379 r3, ported to #1618 flow 1: how the launcher stops a fetch child and how a run's fetch wait takes a
stop, each case a wrong-but-green production variant. Real processes, real signals.

One fetch is one process group (the child's own session): however the child ends, nothing of its group outlives the launch;
a child asked to end gets `_STOP_GRACE` to unwind before its group is killed; a run stopped while it waits ends non-zero and
never goes on. Each launch here runs in its own driver process bounded from outside, so a launcher that never kills (or never
returns) fails the case instead of hanging it.

Retired (K1: there is no lock, so no locked phase in which a child ignores a stop and is waited for):
`test_r6_a_child_that_takes_the_lock_after_being_asked_to_stop_is_let_finish`,
`test_r6_a_real_child_in_its_locked_phase_ignores_sigterm_and_finishes`,
`test_1379_a_run_start_stopped_while_its_publish_holds_the_lock_waits_for_it_to_finish` (3 cases),
`test_1379_a_publish_child_past_its_locked_phase_is_not_signalled_while_it_reports`, and the locked-flag half of
`test_r6_the_child_entry_restores_the_sigterm_handler_and_clears_its_locked_flag`.
"""
from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from defender.tests.tenancy.knowledge_1618 import _support as K

WORKTREE = Path(__file__).resolve().parents[4]
OID = "0123456789abcdef0123456789abcdef01234567"
#: How long a case waits for a driver that should be done within the launcher's own grace (5 s) and budget.
OUTSIDE_BOUND = 40.0


@pytest.fixture
def child_env(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")


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
    """Still alive after 2 seconds? A SIGKILL is delivered asynchronously."""
    deadline = time.monotonic() + 2.0
    while _alive(pid):
        if time.monotonic() > deadline:
            return True
        time.sleep(0.02)
    return False


def _kill_all(pids: list[int]) -> None:
    for pid in pids:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGKILL)


#: A process that runs the production launcher once (`argv`: a JSON list of the child's command, the budget, the folder),
#: printing the line it returned: the case bounds it from outside.
_LAUNCH = '''
import json, sys
from pathlib import Path
from defender.investigation.publish_launch import launch_publish
command, budget, folder = json.loads(sys.argv[1]), float(sys.argv[2]), Path(sys.argv[3])
dest = folder / "dest"
dest.mkdir(exist_ok=True)
print("LINE " + launch_publish("r6-tenant", data_root=folder, dest=dest, budget=budget, command=command), flush=True)
'''


def _launch_bounded(tmp_path: Path, code: str, *args: str, budget: float) -> tuple[str | None, float]:
    """The launch's line (None if the driver did not return within `OUTSIDE_BOUND`) and how long it took."""
    started = time.monotonic()
    driver = subprocess.Popen(  # noqa: S603 — the test's own driver
        [sys.executable, "-c", _LAUNCH, json.dumps([sys.executable, "-c", code, *args]), str(budget), str(tmp_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True, cwd=WORKTREE)
    try:
        out, _err = driver.communicate(timeout=OUTSIDE_BOUND)
    except subprocess.TimeoutExpired:
        os.killpg(driver.pid, signal.SIGKILL)
        driver.communicate()
        return None, time.monotonic() - started
    lines = [line[len("LINE "):] for line in out.splitlines() if line.startswith("LINE ")]
    return (lines[-1] if lines else ""), time.monotonic() - started


# --- the child is asked to end, and given time to unwind, before it is killed -------------------

_UNWINDS = '''
import pathlib, signal, sys, time
marker = pathlib.Path(sys.argv[1])
def stopped(*_):
    time.sleep(1.5)  # unwinding its network calls takes a moment
    marker.write_text("unwound")
    sys.exit(143)
signal.signal(signal.SIGTERM, stopped)
time.sleep(60)
'''


def test_r6_a_child_that_ends_when_asked_is_given_time_to_unwind_before_any_kill(tmp_path, child_env):
    marker = tmp_path / "marker"
    line, _took = _launch_bounded(tmp_path, _UNWINDS, str(marker), budget=2.0)
    assert line is not None, "the launch never returned"
    assert line.startswith("refused transient "), line
    assert marker.read_text() == "unwound", "the child was killed instead of asked to end and given time to unwind"


# --- a kill takes the child's whole process group ----------------------------------------------

_STUBBORN = '''
import pathlib, signal, subprocess, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(25)"])
pathlib.Path(sys.argv[1]).write_text(str(grandchild.pid))
time.sleep(60)
'''


def test_r6_a_child_that_will_not_end_is_killed_after_the_grace_with_its_grandchildren(tmp_path, child_env):
    """A child that ignores the request to end is killed once the grace is over, its grandchild with it, and the launch
    returns `refused transient` instead of waiting on them. (O-BUDGET; was
    `test_r6_a_killed_child_takes_its_grandchildren_and_the_launch_does_not_wait_on_them`)"""
    pidfile = tmp_path / "grandchild.pid"
    try:
        line, took = _launch_bounded(tmp_path, _STUBBORN, str(pidfile), budget=1.0)
        assert line is not None, f"the launch never killed a child that ignores its stop (still waiting after {took:.0f}s)"
        assert line.startswith("refused transient "), line
        assert took < 20, f"the launch waited {took:.1f}s on a child that ignores its stop"
        assert not _outlives(int(pidfile.read_text())), "the child's grandchild outlived the kill"
    finally:
        if pidfile.exists():
            _kill_all([int(pidfile.read_text())])


_REPORTS_AND_LEAVES_A_GRANDCHILD = f'''
import pathlib, subprocess, sys
grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
pathlib.Path(sys.argv[1]).write_text(str(grandchild.pid))
print("ok {OID}")
'''


def test_1618_a_child_that_reported_and_exited_takes_its_process_group_with_it(tmp_path, child_env):
    """A child that printed its line and exited 0, leaving a process in its group (one that holds none of its pipes), has
    that process gone once the launch returns: one fetch is one process group, whatever the child left running ends with
    the launch, however the child ended. Control: the child's own line is the answer. (Flow 1, O-BUDGET)"""
    pidfile = tmp_path / "grandchild.pid"
    try:
        line, _took = _launch_bounded(tmp_path, _REPORTS_AND_LEAVES_A_GRANDCHILD, str(pidfile), budget=30.0)
        assert line == f"ok {OID}", line
        assert not _outlives(int(pidfile.read_text())), "a process of the fetch child's group outlived the launch"
    finally:
        if pidfile.exists():
            _kill_all([int(pidfile.read_text())])


# --- the child's signal state is its own to restore --------------------------------------------

def test_r6_the_child_entry_restores_the_sigterm_handler(tmp_path, data_root):
    """`fetch_child_main` takes SIGTERM over only while it runs: the handler it found is back after each call."""
    from defender.learning.author.version_control.fetch import fetch_child_main

    with K.scene(tmp_path, data_root) as t:
        before = signal.getsignal(signal.SIGTERM)
        for n in range(2):
            dest = K.owned_dest(K.tenant_root(t) / "run-knowledge", f"entry{n}")
            rc = fetch_child_main([t.tenant_id, "--data-root", str(K.tenant_root(t).parent), "--dest", str(dest)],
                                  directory=t.directory, identity=t.vault.identity(), network_timeout=30.0)
            assert rc == 0
            assert signal.getsignal(signal.SIGTERM) is before
            assert sorted(os.listdir(dest)) == ["agent", "settings"], "control: the entry fetched"


# --- the run process stopped while it waits: the child's group goes with it ---------------------

_WAITING_CHILD = '''
import pathlib, subprocess, sys, time
grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
pathlib.Path(sys.argv[1]).write_text(f"{__import__('os').getpid()} {grandchild.pid}")
time.sleep(60)
'''

#: A run's fetch wait (`run_knowledge.fetch_report`, what run start calls) over the production launcher.
_RUN_START_FETCHING = '''
import pathlib, sys
from defender import tenancy
from defender.tenancy import run_knowledge
from defender.investigation.publish_launch import launch_publish

def fetch(tenant_id, dest, *, data_root, commit=None, **named):  # `default_fetch`'s shape, with a stand-in child
    return launch_publish(tenant_id, data_root=data_root, dest=dest, commit=commit, budget=60.0,
                          command=[sys.executable, "-c", sys.argv[1], sys.argv[2]], **named)
root = pathlib.Path(sys.argv[3])
(root / "dest").mkdir(exist_ok=True)
run_knowledge.fetch_report(fetch, "r6-tenant", root / "dest", tenancy.data_root_from_path(root))
print("the fetch returned", flush=True)
'''


def _stop_a_run_fetching(tmp_path: Path, child: str) -> tuple[subprocess.Popen, list[int], bytes, bytes]:
    pidfile = tmp_path / "child.pids"
    parent = subprocess.Popen([sys.executable, "-c", _RUN_START_FETCHING, child, str(pidfile), str(tmp_path)],  # noqa: S603
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, cwd=WORKTREE)
    pids: list[int] = []
    try:
        deadline = time.monotonic() + 30
        while not (pidfile.exists() and len(pidfile.read_text().split()) == 2):
            assert parent.poll() is None, parent.communicate()
            assert time.monotonic() < deadline, "the fetch child never started"
            time.sleep(0.02)
        pids = [int(p) for p in pidfile.read_text().split()]
        assert all(_alive(p) for p in pids), "control: the child and its grandchild run while the fetch waits"
        parent.send_signal(signal.SIGTERM)
        try:
            out, err = parent.communicate(timeout=OUTSIDE_BOUND)
        except subprocess.TimeoutExpired:
            os.killpg(parent.pid, signal.SIGKILL)
            out, err = parent.communicate()
            pytest.fail(f"a stopped run still waited on its fetch child after {OUTSIDE_BOUND:.0f}s")
        return parent, pids, out, err
    except BaseException:
        if parent.poll() is None:
            parent.kill()
        _kill_all(pids)
        raise


def test_r6_a_run_start_stopped_while_its_fetch_runs_takes_the_childs_group_with_it(tmp_path, child_env):
    """Teardown SIGTERMs the run process while its fetch runs: the run exits non-zero and never goes on, and the fetch
    child's whole process group is gone, so nothing keeps writing into the tenant's folder teardown is removing."""
    parent, pids, out, err = _stop_a_run_fetching(tmp_path, _WAITING_CHILD)
    try:
        assert parent.returncode == 128 + signal.SIGTERM, (out, err)
        assert b"the fetch returned" not in out, "a stopped run went on past its fetch"
        for pid in pids:
            assert not _outlives(pid), f"process {pid} of the fetch child's group outlived the stopped run"
    finally:
        _kill_all(pids)


def test_1379_a_run_start_stopped_while_its_fetch_will_not_stop_kills_it_after_the_grace(tmp_path, child_env):
    """A fetch child that ignores the run's stop is killed after the launcher's grace, with its whole group, and the run
    exits non-zero: the run never waits on it without limit. (#1379 r3 O3)"""
    stubborn = "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN)\n" + _WAITING_CHILD
    parent, pids, out, err = _stop_a_run_fetching(tmp_path, stubborn)
    try:
        assert parent.returncode != 0, (out, err)
        assert b"the fetch returned" not in out, "a stopped run went on past its fetch"
        for pid in pids:
            assert not _outlives(pid), f"process {pid} of the fetch child's group outlived the stopped run"
    finally:
        _kill_all(pids)


def test_r6_the_fetch_wait_puts_back_the_sigterm_handler_it_found(tmp_path):
    """The run's fetch wait turns SIGTERM into its own unwinding only while it waits, and so does the launcher: the handler
    each found is back afterwards, and a seam that returns normally is read as before."""
    from defender import tenancy
    from defender.investigation.publish_launch import launch_publish
    from defender.tenancy import run_knowledge

    def mine(*_a: object) -> None:
        return None

    seen: list[object] = []

    def fetch(*_a: object, **_k: object) -> str:
        seen.append(signal.getsignal(signal.SIGTERM))
        return f"ok {OID}"

    dest = tmp_path / "dest"
    dest.mkdir()
    before = signal.signal(signal.SIGTERM, mine)
    try:
        report = run_knowledge.fetch_report(fetch, "r6-tenant", dest, tenancy.data_root_from_path(tmp_path))
        assert signal.getsignal(signal.SIGTERM) is mine, "the fetch wait did not put back the handler it found"
        line = launch_publish("r6-tenant", data_root=tmp_path, dest=dest, budget=30.0,
                              command=[sys.executable, "-c", f"print('ok {OID}')"])
        assert signal.getsignal(signal.SIGTERM) is mine, "the launcher did not put back the handler it found"
    finally:
        signal.signal(signal.SIGTERM, before)
    assert seen, "the fetch was not called"
    assert seen[0] is not mine, "SIGTERM was not taken over while the fetch ran"
    assert not report.unreadable, report
    assert line == f"ok {OID}", line
