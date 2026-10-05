"""Shared fakes for the #1195 box-per-run rows (both drain lanes). NOT a test module.

The design under test (`gh issue view 1195`, amendment 2026-10-06): every agent run of a drain
lane gets its own box, started just before the run and removed just after it, through
`runtime.box.BoxSource(request, *, start_box=, stop_box=, docker=)`:

- `.run()` is a context manager: `start_box(request)`, yield the executor, `stop_box(executor)`
  on every exit; a teardown `BoxFault` is raised with nothing in flight and logged under an
  in-flight exception; every start failure surfaces as a `BoxFault` (`AliasBanNotInForce`
  chained as its `__cause__`).
- `.teardown()` is the batch-end proof the box is gone: no docker call unless a run produced a
  sandboxed executor; otherwise the container's status, and `docker rm -f` unless it is absent.
- `runtime.box.box_for_run(source)` yields `None` for `None`, else `source.run()`'s executor.

Every name the design adds is reached at call time (`box_source`, `box_for_run`), so the
modules importing this one collect before it exists and fail at the row that needs it.

Fakes enter through the seams only (`start_box=`, `stop_box=`, `docker=`, a `docker` program
first on `PATH`); none is patched onto a module.
"""
from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender import _git
from defender.runtime import box as box_mod
from defender.runtime.box import BoxExecutor, BoxFault, BoxRequest, BoxSpec, Mount, _DockerTransport
from defender.tests import _daemon1195 as daemon_mod

DEFENDER = Path(__file__).resolve().parents[1]

#: The three files the box image's name is a function of (`runtime.box.image_tag`): a drain
#: request leaves `spec.rootfs` unset, so a real `start_box` over a worktree resolves the image
#: from these under `<wt>/defender`.
IMAGE_INPUTS = ("box.Dockerfile", "uv.lock", "pyproject.toml")


# ---------------------------------------------------------------------------------------
# The design's new names, reached at call time
# ---------------------------------------------------------------------------------------


def box_source(request: BoxRequest, **seams: Any) -> Any:
    """`runtime.box.BoxSource(request, **seams)`, imported at call time."""
    from defender.runtime.box import BoxSource

    return BoxSource(request, **seams)


def box_for_run(source: Any) -> contextlib.AbstractContextManager[Any]:
    """`runtime.box.box_for_run(source)`, imported at call time."""
    from defender.runtime.box import box_for_run as _box_for_run

    return _box_for_run(source)


def request(name: str = "defender-drain-t1195", *, writable: Path | None = None,
            rootfs: str | None = "defender-box:t1195") -> BoxRequest:
    """A request for one batch's box: `writable` (a real folder) mounted rw at its own path,
    `rootfs` named outright so a real `start_box` reads no image inputs off any tree."""
    mounts: tuple[Mount, ...] = ()
    workdir = Path("/")
    if writable is not None:
        mounts = (Mount(source=writable, target=writable, writable=True),)
        workdir = writable
    return BoxRequest(name=name, mounts=mounts, workdir=workdir, env={},
                      spec=BoxSpec(runtime="runc", rootfs=rootfs))


def sandboxed(name: str) -> BoxExecutor:
    """An executor as `start_box` hands one back for a started container: the docker transport,
    so `sandboxed` is true, named as its container. Nothing is started."""
    spec = BoxSpec()
    return BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name)


def head_mode(repo: Path, rel: str) -> str:
    """The git mode `rel` is committed with at HEAD (`100644`, `100755`, `120000` a link)."""
    # The code under test runs no `ls-tree`; this reads HEAD as a git user would.
    return _git.git(["ls-tree", "HEAD", "--", rel], cwd=repo).split(" ", 1)[0]  # lint-oracle: ok — not the code under test's query


def chain(exc: BaseException | None) -> list[BaseException]:
    """`exc`, then its `__cause__`/`__context__` links, in order."""
    out: list[BaseException] = []
    while exc is not None and exc not in out:
        out.append(exc)
        exc = exc.__cause__ or exc.__context__
    return out


def carries(got: BaseException, fault: BaseException) -> bool:
    """`got` is `fault`, or a `BoxFault` raised from it (the drain re-raises a `BoxFault` escaping
    its work with the cut commit appended, chained to the original)."""
    return got is fault or (isinstance(got, BoxFault) and got.__cause__ is fault)


def caught(fn: Callable[[], object]) -> BaseException | None:
    """What `fn` raised, any `BaseException` included, or `None`: an interrupt a body raises is
    judged by the row, never left to abort the session."""
    try:
        fn()
    except BaseException as e:  # noqa: BLE001 — judged by the caller, whatever its class
        return e
    return None


# ---------------------------------------------------------------------------------------
# A recorded start/stop pair
# ---------------------------------------------------------------------------------------


@dataclasses.dataclass(eq=False)
class RunBox:
    """What a recorded start hands back, one per start: identity is what a row asserts on.
    `sandboxed` is false unless asked, so the batch-end teardown asks no daemon about it."""

    name: str
    n: int
    sandboxed: bool = False


class Runs:
    """An injectable `start_box`/`stop_box` pair, logging into a shared `log`.

    `start(request)` logs `("enter", *state())`, raises the start fault configured for this
    start (`start_faults`, by ordinal from 1) if any, else hands back a fresh `RunBox` named as
    the request and runs `on_start` (the box's first act, once up). `stop(box)` runs `on_stop`
    (the box's last act, still up), logs `("exit", *state())`, then raises the stop fault
    configured for this stop if any, leaving that box up; else the box is down.

    `state` is the row's snapshot (HEAD, the queues): a commit or a rotation made while a box
    was up shows as a change between an `enter` and its `exit`."""

    def __init__(self, log: list | None = None, *,  # noqa: PLR0913 — one seam pair, every fault a row varies
                 state: Callable[[], tuple] = tuple,
                 start_faults: dict[int, BaseException] | None = None,
                 stop_faults: dict[int, BaseException] | None = None,
                 on_start: Callable[[RunBox], object] | None = None,
                 on_stop: Callable[[RunBox], object] | None = None,
                 sandboxed: bool = False) -> None:
        self.log = log if log is not None else []
        self.state = state
        self.start_faults = dict(start_faults or {})
        self.stop_faults = dict(stop_faults or {})
        self.on_start, self.on_stop = on_start, on_stop
        self.sandboxed = sandboxed
        self.requests: list[Any] = []
        self.boxes: list[RunBox] = []
        self.stopped: list[Any] = []
        self.down: list[RunBox] = []

    def start(self, request: Any, *_a: Any, **_kw: Any) -> RunBox:
        self.requests.append(request)
        self.log.append(("enter", *self.state()))
        fault = self.start_faults.get(len(self.requests))
        if fault is not None:
            raise fault
        box = RunBox(name=getattr(request, "name", ""), n=len(self.requests),
                     sandboxed=self.sandboxed)
        self.boxes.append(box)
        if self.on_start is not None:
            self.on_start(box)
        return box

    def stop(self, box: Any, *_a: Any, **_kw: Any) -> None:
        self.stopped.append(box)
        if self.on_stop is not None:
            self.on_stop(box)
        self.log.append(("exit", *self.state()))
        fault = self.stop_faults.get(len(self.stopped))
        if fault is not None:
            raise fault
        self.down.append(box)

    @property
    def alive(self) -> list[RunBox]:
        """Boxes started and not (successfully) stopped."""
        return [b for b in self.boxes if not any(d is b for d in self.down)]

    def source(self, name: str = "defender-drain-t1195") -> Any:
        """A `BoxSource` over this pair, for a request named `name`."""
        return box_source(request(name), start_box=self.start, stop_box=self.stop)


def windows(log: list) -> list[tuple[int, int]]:
    """Each run's `(enter, exit)` indices in `log`, in order: no run inside another, and every
    run that was entered has exited."""
    kinds = [e[0] for e in log]
    out: list[tuple[int, int]] = []
    start: int | None = None
    for i, kind in enumerate(kinds):
        if kind == "enter":
            assert start is None, f"a box was started inside another's run: {kinds}"
            start = i
        elif kind == "exit":
            assert start is not None, f"a box was stopped that was never started: {kinds}"
            out.append((start, i))
            start = None
    assert start is None, f"a box was started and never stopped: {kinds}"
    return out


def assert_each_run_holds_exactly(log: list, spawns: list[str],
                                  spawn_kinds: tuple[str, ...]) -> list[tuple[int, int]]:
    """One run per spawn, in order, each holding its spawn and nothing else (no host step while
    a box is up); no spawn outside a run; the state the same at each run's exit as at its entry
    (no commit, no rotation beside a live box). Returns the windows."""
    kinds = [e[0] for e in log]
    wins = windows(log)
    assert [kinds[a + 1:b] for a, b in wins] == [[s] for s in spawns], (
        f"each run must hold exactly its spawn: {kinds}")
    assert sum(k in spawn_kinds for k in kinds) == len(spawns), (
        f"a spawn ran outside a box of its own: {kinds}")
    for a, b in wins:
        assert log[b][1:] == log[a][1:], (
            f"the state moved while a box was up (a commit or a rotation beside it): {kinds}")
    return wins


# ---------------------------------------------------------------------------------------
# A fake daemon, in process and as a `docker` program on PATH
# ---------------------------------------------------------------------------------------

_SHIM = '''#!{python}
import runpy, sys
sys.argv = [sys.argv[0], {here!r}, *sys.argv[1:]]
runpy.run_path({module!r}, run_name="__main__")
'''


class FakeDaemon:
    """`_daemon1195` over `<tmp>/daemon1195`: called in process as a `docker=` seam, and, once
    `install`ed, as the `docker` program first on `PATH`, over the same containers."""

    def __init__(self, tmp_path: Path) -> None:
        self.dir = tmp_path / "daemon1195"
        self.dir.mkdir(parents=True)
        daemon_mod.save(self.dir, daemon_mod.fresh_state())

    # -- the seams -------------------------------------------------------------------

    def __call__(self, argv: Any, **_kw: Any) -> subprocess.CompletedProcess:
        argv = [str(a) for a in argv]
        rc, out, err = daemon_mod.handle(self.dir, argv)
        return subprocess.CompletedProcess(argv, rc, out, err)

    def install(self, monkeypatch: Any) -> Path:
        """Put a `docker` program running this daemon first on `PATH`; returns it."""
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        program = bin_dir / "docker"
        program.write_text(_SHIM.format(python=sys.executable, here=str(self.dir),
                                        module=str(Path(daemon_mod.__file__).resolve())),
                           encoding="utf-8")
        program.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
        assert shutil.which("docker") == str(program)
        return program

    # -- faults -----------------------------------------------------------------------

    def _fault(self, key: str, value: Any) -> None:
        state = daemon_mod.load(self.dir)
        state["faults"][key] = value
        daemon_mod.save(self.dir, state)

    def refuse_rm(self, times: int = 1) -> None:
        """The next `times` removals fail and leave the container as it was (-1: every one)."""
        self._fault("rm", times)

    def allow_an_alias(self) -> None:
        """The alias probe reports a banned shape allowed: the start raises
        `AliasBanNotInForce`."""
        self._fault("alias_allowed", True)

    def refuse_create(self) -> None:
        """Every `docker run` fails (rc 125), as a daemon that cannot create the box does."""
        self._fault("create", True)

    def go_down(self) -> None:
        self._fault("down", True)

    def hold(self, name: str, status: str) -> None:
        """A container named `name` in `status`, as if a run had left it."""
        state = daemon_mod.load(self.dir)
        state["containers"][name] = {"status": status, "token": ""}
        daemon_mod.save(self.dir, state)

    # -- observations -----------------------------------------------------------------

    def status(self, name: str) -> str | None:
        box = daemon_mod.load(self.dir)["containers"].get(name)
        return None if box is None else box["status"]

    def names(self) -> list[str]:
        return sorted(daemon_mod.load(self.dir)["containers"])

    def mark(self, label: str) -> None:
        """A test's own step, written into the call log between the docker calls."""
        daemon_mod.log(self.dir, [label])

    def calls(self) -> list[list[str]]:
        log = self.dir / daemon_mod.CALLS
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()
                if line]

    def steps(self, *, of: str | None = None) -> list[str]:
        """The log as one sequence: each mark, and each docker call as `create`, `rm`,
        `status` (an inspect of the status) or its verb. With `of`, only the calls naming that
        container, and the marks."""
        out: list[str] = []
        for argv in self.calls():
            if argv[0] != "docker":
                out.append(argv[0])
                continue
            if of is not None and of not in argv:
                continue
            verb = argv[1] if len(argv) > 1 else ""
            if verb == "run":
                verb = "create"
            elif verb == "inspect" and "-f" in argv and "State.Status" in argv[argv.index("-f") + 1]:
                verb = "status"
            out.append(verb)
        return out

    def created(self) -> list[str]:
        """The name of every container a `docker run` asked for, in order."""
        return [a[a.index("--name") + 1] for a in self.calls() if a[:2] == ["docker", "run"]]


def plant_image_inputs(repo: Path) -> None:
    """Copy this checkout's image inputs under `<repo>/defender`, so a real `start_box` over a
    drain request on `repo` resolves an image name rather than faulting on a missing input."""
    (repo / "defender").mkdir(parents=True, exist_ok=True)
    for name in IMAGE_INPUTS:
        shutil.copyfile(DEFENDER / name, repo / "defender" / name)


def clear_opt_out(monkeypatch: Any) -> None:
    """`DEFENDER_ALLOW_UNSANDBOXED` unset: a start fault must surface, never degrade to a host
    executor (N12)."""
    monkeypatch.delenv(box_mod._ALLOW_UNSANDBOXED, raising=False)
