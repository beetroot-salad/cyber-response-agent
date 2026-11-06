"""#1343 B10: the run box dies with the process that started it (T6). Fake-daemon cases observe the
create and the attached start at the docker seam's `.popen` capability (r5 item 15); real-daemon cases (`box`) observe the deaths."""
from __future__ import annotations

import gc
import inspect
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from defender import box as box_mod
from defender.box import _lifecycle
from defender.box._docker import resolve_rootfs
from defender.box._spec import _DockerTransport
from defender.tests.e2e._box665 import DEFENDER, RecordingDocker, reaped_after_create
from defender.tests.e2e._spec771 import requires_real_box
from defender.tests.support.sandbox._box1279 import request_lane, run_lane
from defender.tests.support.sandbox._box1343 import input_open
from defender.tests.support.sandbox._docker import dood_anchor, is_dood
from defender.tests.support.sandbox._spec1092 import make_run_dir
from defender.tests.support.tenancy._host1214 import TEST_TENANT

WORKTREE = Path(__file__).resolve().parents[3]
BoxFault = box_mod.BoxFault


# ---- fake-daemon cases: what the run box's start asks of the daemon and of the attached-start seam ----

def _start(rec: RecordingDocker, run_dir: Path, within: float = 20.0, **knobs: Any) -> Any:
    """`start_box` on the run lane through the seam, failing (not hanging) when it does not return."""
    out: dict[str, Any] = {}

    def go() -> None:
        try:
            out["box"] = box_mod.start_box(run_dir, DEFENDER, docker=rec,
                                           tenant_id=TEST_TENANT, require_sandbox=True, **knobs)
        except BaseException as e:  # noqa: BLE001 — handed back to the test thread
            out["raised"] = e

    worker = threading.Thread(target=go, daemon=True)
    worker.start()
    worker.join(within)
    assert not worker.is_alive(), "start_box did not return: it waits on a box that will never run"
    if "raised" in out:
        raise out["raised"]
    return out["box"]


def _index(calls: list[list[str]], pred: Callable[[list[str]], bool]) -> int:
    return next(i for i, c in enumerate(calls) if pred(c))


def test_b10_the_run_box_is_created_for_an_attached_start_with_its_hardening_unchanged(tmp_path: Path):
    """CONFLICT-UPDATED (#1343 review; was a bare `cat`): run-box create = `docker create -i --rm … <image> sh -c <the reaping `cat`>`, same name, labels, runtime and limits. (B10, r5 8a)"""
    rec = RecordingDocker()
    _start(rec, make_run_dir(tmp_path))
    argv = rec.create_argv or []
    assert argv[:2] == ["docker", "create"], argv[:3]
    assert argv[-3:] == ["sh", "-c", _lifecycle._RUN_BOX_MAIN], argv[-4:]
    assert "sleep" not in argv, argv[-4:]
    assert "--detach" not in argv, argv[-4:]
    image_at = len(argv) - 4
    assert argv.index("-i") < image_at, "-i must be an option, before the image"
    assert argv.index("--rm") < image_at, "--rm must be an option, before the image"
    name = argv[argv.index("--name") + 1]
    assert name.startswith("defender-run-")
    labels = [argv[i + 1] for i, a in enumerate(argv) if a == "--label"]
    assert any(label.startswith(f"{box_mod.START_TOKEN_LABEL}=") and len(label) > 30 for label in labels), labels
    assert any(label.startswith("defender.tenant=") for label in labels), labels
    for flag, value in (("--network", "none"), ("--runtime", box_mod.BoxSpec.from_env(os.environ).runtime)):
        assert argv[argv.index(flag) + 1] == value
    assert "--read-only" in argv
    assert "--pull=never" in argv
    assert any(a.startswith("fsize=") for a in argv)
    assert sum(1 for a in argv if a == "--mount") >= 4, "the run box keeps its mounts"


def test_b10_the_attached_start_follows_the_create_and_precedes_every_probe(tmp_path: Path):
    """One `docker start -a -i <name>` through the seam, after the create and before any exec into the box. (B10, r5 8a)"""
    rec = RecordingDocker()
    _start(rec, make_run_dir(tmp_path))
    name = (rec.create_argv or [])[(rec.create_argv or []).index("--name") + 1]
    assert [a.argv for a in rec.asks] == [["docker", "start", "-a", "-i", name]]
    calls = rec.calls
    create_at = _index(calls, lambda c: c[:2] == ["docker", "create"])
    start_at = _index(calls, lambda c: c[:2] == ["docker", "start"])
    probes = [i for i, c in enumerate(calls) if c[:2] == ["docker", "exec"]]
    assert probes, "premise: the start-up probes exec into the box"
    assert create_at < start_at < min(probes)


def test_b10_start_up_probes_wait_until_the_box_reports_running(tmp_path: Path):
    """The box reports `created` for three reads after the start landed: no probe runs before it says running. (B10, r5 8b)"""
    rec = RecordingDocker()
    rec.start_lag = 3
    _start(rec, make_run_dir(tmp_path))
    assert rec.running_seen_at is not None, "the start never confirmed the box running"
    first_probe = _index(rec.calls, lambda c: c[:2] == ["docker", "exec"])
    assert first_probe >= rec.running_seen_at, "a probe ran into a box that had not reported running"


def test_b10_the_box_input_stays_open_for_the_life_of_the_executor(tmp_path: Path):
    """The attached start is given a piped input, and that starter is kept (not collected) while the executor lives. (B10)"""
    rec = RecordingDocker()
    box = _start(rec, make_run_dir(tmp_path))
    gc.collect()
    [ask] = rec.asks
    assert ask.kwargs.get("stdin") == subprocess.PIPE, f"the box's input was not asked for as a pipe: {ask.kwargs}"
    [starter] = rec.held_starters()   # only the executor can be holding it: the fake keeps it weakly
    assert input_open(ask.read_fd), "the box's input was closed (collected) while its executor lives"
    assert starter.poll() is None, "the starter was ended while its executor lives"
    assert box.name


@pytest.mark.parametrize("exits", [(125, b"docker: Error response from daemon: the start was refused\n"), (0, b"")],
                         ids=["rc125", "rc0-silent"])
@pytest.mark.parametrize("owner", ["self", "another-lane"])
def test_b10_a_starter_that_exits_before_the_box_runs_is_a_start_fault_reaped_by_token(
        tmp_path: Path, exits: tuple[int, bytes], owner: str):
    """Starter dead before running: BoxFault with rc and stderr, did-not-run marker, reap by owned token only. (B10, r5 8b)"""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker(existing_token=owner)
    rec.starter_exit = exits
    with pytest.raises(BoxFault) as raised:
        _start(rec, run_dir)
    text = str(raised.value)
    assert f"{exits[0]}" in text, text
    if exits[1]:
        assert exits[1].decode().strip() in text, text
    verdict = box_mod.verdict_path(run_dir)
    assert verdict.is_file()
    assert '"ran": false' in verdict.read_text(encoding="utf-8").replace('":false', '": false')
    assert verdict.read_text(encoding="utf-8").count(str(exits[0])) >= 1
    assert not [c for c in rec.calls if c[:2] == ["docker", "exec"]], "probes ran against a box that never ran"
    assert reaped_after_create(rec.calls) is (owner == "self"), "the reap must follow the start token's owner"


def test_b10_the_wait_for_a_running_box_is_bounded_at_thirty_seconds_by_default():
    """The run box's wait-until-running bound is a `start_box` knob defaulting to 30 s. (B10, r5 16)"""
    assert inspect.signature(box_mod.start_box).parameters["running_wait"].default == 30.0


def test_b10_a_box_that_never_reports_running_while_its_starter_lives_is_a_start_fault_after_the_bound(tmp_path: Path):
    """Starter alive, box stuck `created`: after the bound a start fault, marker, token reap, starter ended. (B10, r5 16)"""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    rec.lands = False
    began = time.monotonic()
    with pytest.raises(BoxFault):
        _start(rec, run_dir, within=20, running_wait=1.0)
    assert 0.9 < time.monotonic() - began < 15, "the wait was not bounded by `running_wait`"
    [ask] = rec.asks
    assert ask.returncode is not None, "the starter was left alive after the start fault"
    assert '"ran": false' in box_mod.verdict_path(run_dir).read_text(encoding="utf-8").replace('":false', '": false')
    assert not [c for c in rec.calls if c[:2] == ["docker", "exec"]], "probes ran against a box that never ran"
    assert reaped_after_create(rec.calls), "the box was not reaped by its token"


def test_b10_a_run_lane_start_through_a_docker_without_the_attached_start_fails_loudly_and_starts_nothing(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A docker seam lacking `.popen`: an error naming it, and no real `docker start` (never a fall-back to the daemon). (B10, r5 15)"""

    class NoAttachedStart(RecordingDocker):
        """A healthy daemon (create, inspect, rm all answer) whose object has no `.popen`: the loud error
        comes wherever the capability is first used, not from a fault on the way."""

        def __getattribute__(self, name: str):
            if name == "popen":
                raise AttributeError("'NoAttachedStart' object has no attribute 'popen'")
            return super().__getattribute__(name)

    log = tmp_path / "real-docker-calls"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    shim = fake_bin / "docker"
    shim.write_text(f'#!/bin/sh\necho "$@" >> {log}\nexit 1\n', encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")   # a real `docker` would land here
    seam = NoAttachedStart()
    with pytest.raises((AttributeError, TypeError), match="popen"):
        _start(seam, make_run_dir(tmp_path))
    started = [c for c in seam.calls if c[:2] == ["docker", "start"]]
    assert not started, "a `docker start` was issued without the seam's attached-start capability"
    assert "start" not in (log.read_text() if log.exists() else ""), "a real `docker start` was issued"


def test_b10_teardown_of_a_run_box_that_is_being_removed_is_clean_and_the_scrub_runs(tmp_path: Path):
    """Stop then scrub on a clean end, whatever the auto-remove race shows (removal in progress, then gone). (B10)"""

    class Removing(RecordingDocker):
        def __call__(self, argv, **kw):  # noqa: ANN001
            argv = list(argv)
            sub = argv[1] if len(argv) > 1 else ""
            if sub in ("rm", "wait"):
                self.calls.append(argv)
                if sub == "wait":
                    self.phase = None
                    return subprocess.CompletedProcess(argv, 0, "0\n", "")
                gone = self.phase is None
                self.phase = None if gone else "removing"
                err = "Error response from daemon: No such container\n" if gone else \
                    "Error response from daemon: removal of container is already in progress\n"
                return subprocess.CompletedProcess(argv, 1, "", err)
            return super().__call__(argv, **kw)

    run_dir = make_run_dir(tmp_path)
    rec = Removing()
    box = _start(rec, run_dir)
    scrubbed: list[Path] = []
    box_mod.stop_and_scrub(box, run_dir, stop_box=box_mod.stop_box,
                           scrub_tree=lambda tree: (scrubbed.append(tree), box_mod.scrub(tree))[0],
                           in_flight=False)
    assert scrubbed == [run_dir], "the scrub did not run after the stop"
    assert box_mod.tree_verified(run_dir)
    assert rec.phase is None


class _Overflowing(_DockerTransport):
    """A box transport whose command overflowed the output cap: the real fault, injected."""

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> Any:
        raise box_mod.BoxOutputLimitExceeded()


class _StopsInto(RecordingDocker):
    """A daemon whose `stop` leaves the box in `after`: None = already gone (auto-remove), or a status word."""

    def __init__(self, after: str | None, **kw: Any):
        super().__init__(**kw)
        self.after = after

    def __call__(self, argv, **kw):  # noqa: ANN001
        argv = list(argv)
        out = super().__call__(argv, **kw)
        sub = argv[1] if len(argv) > 1 else ""
        if sub == "stop":
            self.status, self.phase = self.after, None
        if sub == "start":
            self.status = "running"
        return out


def _overflow(box: Any) -> BaseException:
    box.transport = _Overflowing(box.name, box.spec)
    with pytest.raises(box_mod.BoxOutputLimitExceeded) as raised:
        box.run_parsed([], command="x", cwd=Path("/runs/current"), timeout=5)
    return raised.value


@pytest.mark.parametrize("after", [None, "removing"], ids=["gone", "removing"])
def test_b10_the_output_limit_stop_of_a_run_box_counts_a_removing_or_gone_box_as_stopped(tmp_path: Path, after):
    """Overflow on a run box: it is stopped and the plain overflow is raised, no 'could not confirm'. (B10 output-limit path)"""
    rec = _StopsInto(after)
    box = _start(rec, make_run_dir(tmp_path))
    overflow = _overflow(box)
    assert getattr(overflow, "__notes__", []) == [], \
        f"a removing/gone run box was read as unconfirmed: {getattr(overflow, '__notes__', None)}"
    assert overflow.__cause__ is None
    assert any(c[1:2] in (["stop"], ["rm"]) and box.name in c for c in rec.calls), "the box was never stopped"


# ---- the stop/start boxes keep today's start and stop (out of scope for B10; guards) ----

def _stop_start_box(tmp_path: Path, rec: RecordingDocker) -> Any:
    lane = request_lane(tmp_path)
    return box_mod.start_box(lane.request(require_sandbox=True), docker=rec)


def test_b10_a_stop_start_box_is_still_started_detached_forever_and_removed_explicitly(tmp_path: Path):
    """A request-lane (learning drain / oracle) box: `docker run --detach … sh -c <the reaping sleep>`, no -i/--rm, no attached start. (B10 scope)"""
    rec = _StopsInto("exited")
    box = _stop_start_box(tmp_path, rec)
    argv = rec.create_argv or []
    assert argv[:3] == ["docker", "run", "--detach"], argv
    assert argv[-3:] == ["sh", "-c", _lifecycle._LANE_BOX_MAIN], argv
    assert "--rm" not in argv
    assert "-i" not in argv
    assert not [c for c in rec.calls if c[:2] == ["docker", "start"]], "a stop/start box was started at its start"
    box_mod.stop_box(box)
    assert ["docker", "rm", "-f", box.name] in rec.calls, "a stop/start box is removed explicitly"


def test_b10_a_stop_start_boxs_window_still_uses_plain_start_and_proven_stop(tmp_path: Path):
    """BoxRuns: `docker start <name>` for the window, `docker stop -t 0` after, no attached start. (B10 scope)"""
    rec = _StopsInto("exited")
    box = _stop_start_box(tmp_path, rec)
    rec.status = "exited"
    with box_mod.BoxRuns(box).run():
        assert ["docker", "start", box.name] in rec.calls
    assert ["docker", "stop", "-t", "0", box.name] in rec.calls
    assert not [c for c in rec.calls if c[:4] == ["docker", "start", "-a", "-i"]]


@pytest.mark.parametrize("after", [None, "removing"], ids=["vanished", "removing"])
def test_b10_a_vanished_or_removing_stop_start_box_is_not_read_as_stopped(tmp_path: Path, after):
    """The removing/gone allowance is the run box's alone: a stop/start box in either state is a BoxFault. (B10, r5 8d)"""
    rec = _StopsInto(after)
    box = _stop_start_box(tmp_path, rec)
    rec.status = "exited"
    with pytest.raises(BoxFault, match="could not stop"):
        box_mod.BoxRuns(box).stop()


@pytest.mark.parametrize("after", [None, "removing"], ids=["vanished", "removing"])
def test_b10_the_output_limit_stop_of_a_stop_start_box_still_reports_an_unconfirmed_stop(tmp_path: Path, after):
    """Overflow on a stop/start box whose stop cannot be confirmed: the overflow carries the 'could not confirm' note. (B10 scope)"""
    rec = _StopsInto(after)
    box = _stop_start_box(tmp_path, rec)
    rec.status = "exited"
    overflow = _overflow(box)
    assert any("could not confirm the box stopped" in n for n in getattr(overflow, "__notes__", [])), \
        "an unconfirmed stop/start box was read as stopped"



# ---- review follow-ups: the attached start's own error text, and removal of a box removing itself ----

def test_b10_a_start_fault_reports_the_attached_starts_own_error_text():
    """Through a real process: what the start itself says on its error output reaches the fault's text. (#1343 review, B10)"""
    from defender.box import _lifecycle

    class ShellStart:
        def popen(self, argv, **kw):  # noqa: ANN001
            return subprocess.Popen(["sh", "-c", "echo the start was refused >&2; exit 3"], **kw)

    starter = _lifecycle._attach(ShellStart(), "box-x")  # type: ignore[arg-type]
    starter.wait(timeout=10)
    assert _lifecycle._end_starter(starter) == (3, "the start was refused")


class _RemovingItself:
    """A daemon holding one owned container that is removing itself (`--rm`): every `rm -f` answers that
    the removal is already in progress, and its status reads `removing` until the daemon finishes."""

    def __init__(self, name: str, token: str) -> None:
        self.name, self.token, self.calls = name, token, []
        self.status = "running"

    def __call__(self, argv, **_kw):  # noqa: ANN001
        argv = list(argv)
        self.calls.append(argv)
        ok = lambda out="": subprocess.CompletedProcess(argv, 0, out, "")  # noqa: E731
        if argv[:2] == ["docker", "inspect"]:
            fmt = argv[argv.index("-f") + 1]
            return ok(f"{self.status}\n" if "State.Status" in fmt else f"{self.token}\n")
        if argv[:2] == ["docker", "ps"]:
            return ok(f"{self.name}\n")
        if argv[:3] == ["docker", "rm", "-f"]:
            self.status = "removing"
            return subprocess.CompletedProcess(
                argv, 1, "", "Error response from daemon: removal of container is already in progress\n")
        if argv[:2] == ["docker", "wait"]:
            return ok("0\n")
        return ok()


def test_a_container_already_removing_itself_counts_as_removed_for_the_worker_backstop_and_the_tenant_teardown():
    """Every removal site, not only the run box's teardown, reads a container the daemon is already removing as gone: the worker's token reap removes it, the tenant teardown reports nothing left. (#1343 review, B10)"""
    from defender.box._docker import Reaped, reap_if_owned, remove_tenant_containers

    daemon = _RemovingItself("defender-run-x", "tok")
    assert reap_if_owned(daemon, daemon.name, "tok") == Reaped.REMOVED
    assert any(c[:3] == ["docker", "rm", "-f"] for c in daemon.calls), "premise: the reap tried to remove it"
    assert remove_tenant_containers("t", docker=_RemovingItself("defender-run-y", "tok")) is None

# ---- real daemon: the run box dies with its starter (runc here; CI's shards run it under runsc) ----

#: The starter: starts a run box on the run lane under `argv[1]` (as `run.py` does), prints its name,
#: then holds on (`hold`) or ends by returning (`exit`) with no teardown.
_STARTER = textwrap.dedent("""
    import dataclasses, sys, time, uuid
    from pathlib import Path
    from defender import box as box_mod
    from defender.tests.support.sandbox._box1279 import run_lane

    lane = run_lane(Path(sys.argv[1]))
    own = lane.run_dir.rename(lane.run_dir.with_name(f"inv-1343-{uuid.uuid4().hex[:12]}"))  # a name no other test uses
    box = dataclasses.replace(lane, run_dir=own).start(box_mod.run_docker, require_sandbox=True)
    print(box.name, flush=True)
    if sys.argv[2] == "hold":
        time.sleep(600)
""")


@pytest.fixture
def base(tmp_path: Path) -> Iterator[Path]:
    """The run lane's sources, on the daemon-visible shared mount under DooD (as test_1195_run_box_live)."""
    if not is_dood():
        yield tmp_path
        return
    anchor = dood_anchor()
    assert anchor is not None, "the real-box guard requires a shared repo mount under DooD"
    where = anchor / f"t1343-{uuid.uuid4().hex[:12]}"
    where.mkdir(parents=True)
    try:
        yield where
    finally:
        shutil.rmtree(where, ignore_errors=True)


def _state(name: str) -> str | None:
    """The container's status, or None when there is no such container."""
    found = box_mod.run_docker(["docker", "ps", "-a", "--filter", f"name=^/{name}$", "--format", "{{.Status}}"])
    return found.stdout.strip() or None


def _gone_within(name: str, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while _state(name) is not None and time.monotonic() < deadline:
        time.sleep(0.2)
    return _state(name) is None


def _starter(base: Path, tmp_path: Path, mode: str) -> tuple[subprocess.Popen, str]:
    script = tmp_path / "starter.py"
    script.write_text(_STARTER, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(WORKTREE), os.environ.get("PYTHONPATH", "")])}
    env.pop("DEFENDER_ALLOW_UNSANDBOXED", None)
    proc = subprocess.Popen([sys.executable, str(script), str(base), mode], stdout=subprocess.PIPE, text=True,
                            env=env, start_new_session=True)
    name = (proc.stdout.readline() if proc.stdout else "").strip()
    assert name.startswith("defender-run-"), f"the starter did not start a run box (rc={proc.poll()})"
    return proc, name


@requires_real_box
@pytest.mark.box
@pytest.mark.parametrize("ending", ["sigkill-alone", "sigkill-group", "sigterm", "clean-exit"])
def test_b10_the_run_box_is_removed_within_seconds_however_its_starter_ends(base: Path, tmp_path: Path, ending: str):
    """Starter ended any way, no teardown: within 10 s no container has the box's name. (B10, T6)"""
    starter, name = _starter(base, tmp_path, "exit" if ending == "clean-exit" else "hold")
    try:
        if ending != "clean-exit":
            assert (_state(name) or "").startswith("Up"), "premise: the box runs while its starter lives"
        if ending == "sigkill-alone":
            os.kill(starter.pid, signal.SIGKILL)
        elif ending == "sigkill-group":
            os.killpg(os.getpgid(starter.pid), signal.SIGKILL)
        elif ending == "sigterm":
            os.kill(starter.pid, signal.SIGTERM)
        starter.wait(timeout=15)
        assert _gone_within(name, 10), f"the run box outlived its starter ({ending}): {_state(name)}"
    finally:
        if starter.poll() is None:
            starter.kill()
        box_mod.run_docker(["docker", "rm", "-f", name])


@requires_real_box
@pytest.mark.box
def test_b10_the_run_box_keeps_running_while_its_starter_lives(base: Path, tmp_path: Path):
    """Control: with the starter alive and idle the box is still up after 4 s (the input is held, not at EOF). (B10)"""
    starter, name = _starter(base, tmp_path, "hold")
    try:
        time.sleep(4)
        assert (_state(name) or "").startswith("Up"), f"the box died with its starter alive: {_state(name)}"
    finally:
        starter.kill()
        box_mod.run_docker(["docker", "rm", "-f", name])


@pytest.fixture
def live(base: Path) -> Iterator[tuple[Any, Path]]:
    """A run box started in this process (the held starter is this process's), torn down at the end."""
    lane = run_lane(base)
    box = lane.start(box_mod.run_docker, require_sandbox=True)
    try:
        yield box, lane.run_dir
    finally:
        box_mod.run_docker(["docker", "rm", "-f", box.name])


_CWD = Path("/runs/current")


@requires_real_box
@pytest.mark.box
def test_b10_commands_run_one_at_a_time_and_the_normal_teardown_still_stops_then_scrubs(live: tuple[Any, Path]):
    """Sequential commands answer correctly; stop-then-scrub on a clean end leaves no box and a verified scrub. (B10)"""
    from defender.execution import bash_exec

    box, run_dir = live
    for word in ("one", "two"):
        got = box.run_parsed(bash_exec.parse(f"echo {word}"), command=f"echo {word}", cwd=_CWD, timeout=30)
        assert got.out == f"{word}\n".encode()
    box_mod.stop_and_scrub(box, run_dir, stop_box=box_mod.stop_box, scrub_tree=box_mod.scrub, in_flight=False)
    assert _state(box.name) is None
    assert box_mod.tree_verified(run_dir)


@requires_real_box
@pytest.mark.box
def test_b10_what_a_program_writes_to_the_main_processs_output_never_reaches_the_host(live: tuple[Any, Path]):
    """A program in the box writes 2 MB into PID 1's output, more than an unread pipe holds: it goes nowhere, the box stays up, and the attached start's error output stays empty. (#1343 review, B10)"""
    box, _ = live
    wrote = box_mod.run_docker(["docker", "exec", box.name, "sh", "-c",
                                "head -c 2000000 /dev/zero > /proc/1/fd/2 && head -c 2000000 /dev/zero > /proc/1/fd/1"])
    assert wrote.returncode == 0, wrote.stderr
    assert box.starter.poll() is None, "the box's attached start ended"
    time.sleep(1)  # anything forwarded would have reached the start's pipe by now
    _, err = _lifecycle._end_starter(box.starter)
    assert err == "", f"the box's output reached the host: {err[:200]!r}"


@requires_real_box
@pytest.mark.box
def test_b10_output_past_the_limit_stops_and_removes_the_run_box_with_the_plain_overflow(live: tuple[Any, Path]):
    """Overflow on a live run box: the box is gone and no 'could not confirm' note is attached. (B10 output-limit path)"""
    from defender.execution import bash_exec

    box, _ = live
    # A process writing to the helper's own stdout (a bypass), the only thing that still trips the
    # fence: a cooperating command now gets exit 75 and the box lives (#1421 O5, decision 2).
    command = ("python3 -c \"import os; f = os.open(f'/proc/{os.getppid()}/fd/1', os.O_WRONLY); "
               f"[os.write(f, bytes(1 << 20)) for _ in range({(box_mod.BOX_OUTPUT_LIMIT >> 20) + 1})]\"")
    with pytest.raises(box_mod.BoxOutputLimitExceeded) as raised:
        box.run_parsed(bash_exec.parse(command), command=command, cwd=_CWD, timeout=60)
    assert getattr(raised.value, "__notes__", []) == []
    assert _gone_within(box.name, 10), f"the overflowed run box remains: {_state(box.name)}"


# ---- r5 8(e): a starter killed between the create and the attached start landing ----

_CREATE_THEN_START = textwrap.dedent("""
    import subprocess, sys, time
    name, image, runtime = sys.argv[1:4]
    subprocess.run(["docker", "create", "-i", "--rm", "--pull=never", "--runtime", runtime, "--network", "none", "--name", name,
                    image, "sh", "-c", "exec cat >/dev/null 2>&1"], check=True, stdout=subprocess.DEVNULL)
    print("created", flush=True)
    held = subprocess.Popen(["docker", "start", "-a", "-i", name], stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(600)
""")


@requires_real_box
@pytest.mark.box
@pytest.mark.parametrize("kill", ["alone", "group"])
@pytest.mark.parametrize("delay", [0.0, 0.01, 0.05])
def test_b10_a_starter_killed_between_the_create_and_the_start_never_leaves_a_running_box(
        tmp_path: Path, kill: str, delay: float):
    """Killed right after `docker create` returns: the box ends gone or `Created` (inert), never running. (B10, r4 item 1)"""
    spec = box_mod.BoxSpec.from_env(os.environ)
    image = resolve_rootfs(spec.rootfs, DEFENDER).image
    script = tmp_path / "create_then_start.py"
    script.write_text(_CREATE_THEN_START, encoding="utf-8")
    name = f"t1343-{uuid.uuid4().hex[:10]}"
    child = subprocess.Popen([sys.executable, str(script), name, image, spec.runtime], stdout=subprocess.PIPE, text=True,
                             start_new_session=True)
    try:
        assert child.stdout.readline().strip() == "created"
        time.sleep(delay)
        if kill == "group":
            os.killpg(os.getpgid(child.pid), signal.SIGKILL)
        else:
            os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=10)
        time.sleep(3)
        state = _state(name)
        assert state is None or state.startswith("Created"), f"a box was left running untied: {state}"
    finally:
        if child.poll() is None:
            child.kill()
        box_mod.run_docker(["docker", "rm", "-f", name])
