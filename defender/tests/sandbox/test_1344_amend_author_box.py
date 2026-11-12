"""#1344 amendment 2 (from #1278, owner-approved 2026-11-07): the drain's author box ends with its worker.

A request-lane box (the drain's batch box, the oracle's) is created with its input open and its main process
reading it. Its first start (the probes) is plain; the drain stops it before work, and each `BoxRuns.run` window
starts it attached, its input held by this process for the window and closed at its end. So, as for the run box
(#1343 B10), a window's box runs only while its holder lives. Fake-daemon cases observe the seam; the real-daemon case kills a window's holder and watches the box
stop."""
from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from defender import box as box_mod
from defender.box import _lifecycle
from defender.tests.e2e._box665 import RecordingDocker
from defender.tests.e2e._spec771 import requires_real_box
from defender.tests.sandbox.test_run_box import _batch, _exec, _status, live_worktree_base  # noqa: F401 — a fixture
from defender.tests.support.sandbox import _box1195 as X
from defender.tests.support.sandbox._box1279 import request_lane
from defender.tests.support.sandbox._box1343 import input_open

WORKTREE = Path(__file__).resolve().parents[3]


class _Windows(RecordingDocker):
    """A healthy daemon over one stop/start box: an attached start lands it (`running`), a stop leaves it `exited`."""

    def __call__(self, argv, **kw):  # noqa: ANN001
        out = super().__call__(argv, **kw)
        if list(argv)[1:2] == ["stop"]:
            self.phase = "exited"
        if list(argv) == ["docker", "start", self.create_argv[self.create_argv.index("--name") + 1]
                          if self.create_argv else ""]:
            self.phase = "running"  # the probes' plain start
        return out

    def _landed(self, argv: list[str]) -> None:
        if self.phase in ("created", "exited"):
            self.phase = "starting"


def _attached(rec: RecordingDocker, name: str) -> list:
    return [a for a in rec.asks if a.argv == ["docker", "start", "-a", "-i", name]]


def test_a2_the_request_box_is_created_reading_its_input(tmp_path: Path):
    """`docker create -i` (no `--detach`, no `--rm`) with `cat` as the main process, then one plain start for the
    probes; no attached start until a window opens. (amendment 2)"""
    rec = _Windows()
    box = box_mod.start_box(request_lane(tmp_path).request(require_sandbox=True), docker=rec)
    try:
        argv = rec.create_argv or []
        assert argv[:3] == ["docker", "create", "-i"], argv[:4]
        assert "--detach" not in argv, argv
        assert "--rm" not in argv, argv
        assert argv[-3:] == ["sh", "-c", _lifecycle._LANE_BOX_MAIN]
        assert "cat" in _lifecycle._LANE_BOX_MAIN
        assert "sleep" not in _lifecycle._LANE_BOX_MAIN
        assert rec.calls.count(["docker", "start", box.name]) == 1, "the probes' start is one plain start"
        assert _attached(rec, box.name) == [], "an attached start was made outside a window"
        assert not box.auto_removed, "a stop/start box does not remove itself"
    finally:
        box_mod.stop_box(box)
    assert ["docker", "rm", "-f", box.name] in rec.calls, "the box is removed by its owner"


def test_a2_each_window_attaches_and_closes_its_input_at_its_end(tmp_path: Path):
    """`BoxRuns.run`: an attached start whose input is open inside the window and ended after it, with the proven
    stop; two windows, two starts. (amendment 2)"""
    rec = _Windows()
    box = box_mod.start_box(request_lane(tmp_path).request(require_sandbox=True), docker=rec)
    try:
        runs = box_mod.BoxRuns(box)
        runs.stop()
        for n in (1, 2):
            with runs.run():
                window = _attached(rec, box.name)[-1]
                assert len(_attached(rec, box.name)) == n
                assert input_open(window.read_fd), f"window {n}'s input is not held while it is open"
            assert window.returncode is not None, f"window {n}'s attached start outlived it"
            assert rec.calls.count(["docker", "stop", "-t", "0", box.name]) == 1 + n, "a window ended without the proven stop"
        assert rec.calls.count(["docker", "start", box.name]) == 1, "a window started the box plainly"
    finally:
        box_mod.stop_box(box)


def test_a2_a_window_whose_box_never_runs_is_a_box_fault_and_its_start_is_ended(tmp_path: Path):
    """The attached start exits before the box reports running: the window refuses, nothing is yielded, and its
    start is ended. (amendment 2)"""
    rec = _Windows()
    box = box_mod.start_box(request_lane(tmp_path).request(require_sandbox=True), docker=rec)
    try:
        runs = box_mod.BoxRuns(box)
        runs.stop()
        rec.starter_exit = (1, b"Error response from daemon: boom")
        entered = []
        with pytest.raises(box_mod.BoxFault, match="could not start the box"), runs.run():
            entered.append(True)
        assert entered == []
        assert _attached(rec, box.name)[-1].returncode is not None
    finally:
        rec.starter_exit = None
        box_mod.stop_box(box)


_HOLDER = textwrap.dedent("""
    import os, sys, time
    from defender import box as box_mod
    from defender.box._spec import BoxExecutor, BoxSpec, _DockerTransport

    name = sys.argv[1]
    spec = BoxSpec.from_env(os.environ)
    box = BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name, docker=box_mod.run_docker)
    with box_mod.BoxRuns(box).run():
        print("open", flush=True)
        time.sleep(600)
""")


@requires_real_box
@pytest.mark.box
def test_a2_a_drain_box_stops_when_its_window_s_holder_is_killed(live_worktree_base: Path, monkeypatch):  # noqa: F811 — the imported fixture
    """A real drain box (`Batch.box_request()`): a window opened by another process keeps it running; SIGKILL that
    process (not the attached docker client it started) and the box stops on its own, its input closed. (amendment 2,
    O9: nothing outlives its worker)"""
    X.clear_opt_out(monkeypatch)
    with contextlib.ExitStack() as stack:
        batch, _tenant = stack.enter_context(_batch(live_worktree_base))
        box = box_mod.start_box(batch.box_request())
        stack.callback(box_mod.stop_box, box)
        box_mod.BoxRuns(box).stop()
        assert _status(box.name) == "exited", "premise: the batch's box is stopped between windows"

        env = {**os.environ, "PYTHONPATH": str(WORKTREE)}
        holder = subprocess.Popen([sys.executable, "-c", _HOLDER, box.name], stdout=subprocess.PIPE, env=env)
        try:
            assert holder.stdout is not None
            assert holder.stdout.readline().strip() == b"open", "the window did not open"
            assert _status(box.name) == "running"
            time.sleep(1.0)
            assert _status(box.name) == "running", "control: an open window keeps the box running"
            holder.send_signal(signal.SIGKILL)
            holder.wait(timeout=10)
            deadline = time.monotonic() + 15
            while _status(box.name) == "running" and time.monotonic() < deadline:
                time.sleep(0.1)
            assert _status(box.name) == "exited", "the box outlived its window's holder"
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=10)


@requires_real_box
@pytest.mark.box
def test_a2_a_drain_box_reached_over_the_relay_runs_only_inside_its_windows_on_a_real_daemon(
        live_worktree_base: Path, monkeypatch):  # noqa: F811 — the imported fixture
    """#1170 review of PR #1467: the drain's batch box as a job container reaches it. The helper's side (`relay_window`,
    `relay_halt`, `relay_exec`, `relay_stop` over the real daemon) answers the job's side (`BoxRuns` over a
    `RelayTransport`), in one process: the box is stopped before the work, runs inside each of two windows,
    is `exited` between and after them, and is gone after its teardown."""
    X.clear_opt_out(monkeypatch)
    with contextlib.ExitStack() as stack:
        batch, _tenant = stack.enter_context(_batch(live_worktree_base))
        held = box_mod.start_box(batch.box_request())
        stack.callback(lambda: _status(held.name) and box_mod.stop_box(held))
        windows = box_mod.BoxRuns(held)

        def helper(name: str, **fields):  # noqa: ANN202 — the helper's answers, as `job_host` gives them
            if name == "box.exec":
                return box_mod.relay_exec(held, box_mod.run_docker, fields["frame"], cwd=fields["cwd"],
                                          timeout=fields["timeout"])
            if name == "box.window":
                return box_mod.relay_window(windows)
            if name == "box.halt":
                return box_mod.relay_halt(windows)
            if name == "box.stop":
                return box_mod.relay_stop(held, box_mod.run_docker, windows)
            raise AssertionError(name)

        relayed = box_mod.BoxExecutor(name=held.name, transport=box_mod.RelayTransport(helper, "h-live"))
        runs = box_mod.BoxRuns(relayed)
        runs.stop()
        assert _status(held.name) == "exited", "the batch's box ran before its first window"
        for n in (1, 2):
            with runs.run() as box:
                assert _status(held.name) == "running", f"window {n} did not start the box"
                assert box is relayed
                # This fixture's code tree carries no in-box command helper, so the box is proven usable by a plain exec.
                assert _exec(held, "echo", f"window-{n}") == (0, f"window-{n}\n"), f"window {n}'s box ran nothing"
            assert _status(held.name) == "exited", f"the box outlived window {n}"
        box_mod.stop_box(relayed)
        assert _status(held.name) == "", "the teardown over the relay left the box"
