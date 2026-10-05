"""Shared fakes for the #1195 rows (both drain lanes), design amendment 2. NOT a test module.

The design under test (`gh issue view 1195`, "Design amendment 2 (2026-10-06): one box per
batch, stopped between agent runs"): the drain creates and checks its one box at batch start, as
on main (`start_box`), stops it at once, starts it for each agent run and stops it after, and
removes it at batch end (`stop_box`: `docker rm -f`) before the scan.

- `runtime.box.stop_run_box(box, *, docker=_docker)`: `docker stop -t 0 <name>`, then the status
  must be `exited`, else `BoxFault`. A no-op for `None` and for a box whose `sandboxed` is false;
  a box with no `sandboxed` at all fails closed (`BoxFault`).
- `runtime.box.box_for_run(box, *, docker=_docker)`: the spawn sites' `with`, yielding the same
  box. On enter the status must be `exited` (else a best-effort stop and `BoxFault`, the body
  never runs), then `docker start`, then the status must be `running` (else the same). On every
  exit, `stop_run_box`: its fault is raised with nothing in flight, logged under an in-flight
  exception.

Every name the design adds is reached at call time (`box_for_run`, `stop_run_box`), so the
modules importing this one collect before it exists and fail at the row that needs it.

The spawn sites and the drain's post-create stop use the DEFAULT docker seam, so a lane row
runs with the fake daemon (`FakeDaemon`) installed as the `docker` program first on `PATH`.
Its host steps write into a `Journal`, which marks each into the daemon's own call log and notes
which containers were running at that moment: so a row can split the log into run windows
(between a `docker start` and the next `docker stop`) and see that each holds exactly its spawn,
and that no host step ran beside a running box. Nothing is patched onto a module.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest

from defender.runtime import box as box_mod
from defender.runtime.box import (
    AliasBanNotInForce,
    BoxExecutor,
    BoxFault,
    BoxRequest,
    BoxSpec,
    Mount,
    _DockerTransport,
)
from defender.tests import _daemon1195 as daemon_mod

DEFENDER = Path(__file__).resolve().parents[1]

#: The three files the box image's name is a function of (`runtime.box.image_tag`): a drain
#: request leaves `spec.rootfs` unset, so a real `start_box` over a worktree resolves the image
#: from these under `<wt>/defender`.
IMAGE_INPUTS = ("box.Dockerfile", "uv.lock", "pyproject.toml")

#: The pointer main's batch-start unwind appends to a `BoxFault` (`_unwind_worktree_start_fault`).
POINTER = "origin/main @ "

#: What makes the real `start_box` fail at batch start (the `FakeDaemon` knob), and how main
#: surfaces it: a `BoxFault` with the cut commit appended (`pointed`), or a link ban as
#: `AliasBanNotInForce`, unpointed.
BATCH_START_FAULTS = [
    pytest.param("refuse_create", BoxFault, True, id="create"),
    pytest.param("refuse_sentinel", BoxFault, True, id="sentinel"),
    pytest.param("allow_an_alias", AliasBanNotInForce, False, id="link-ban"),
]


# ---------------------------------------------------------------------------------------
# The design's new names, reached at call time
# ---------------------------------------------------------------------------------------


def box_for_run(box: Any, **seams: Any) -> contextlib.AbstractContextManager[Any]:
    """`runtime.box.box_for_run(box, **seams)`, imported at call time."""
    from defender.runtime.box import box_for_run as _box_for_run

    return _box_for_run(box, **seams)


def stop_run_box(box: Any, **seams: Any) -> None:
    """`runtime.box.stop_run_box(box, **seams)`, imported at call time."""
    from defender.runtime.box import stop_run_box as _stop_run_box

    _stop_run_box(box, **seams)


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
    """An executor as `start_box` hands one back for a created container: the docker transport,
    so `sandboxed` is true, named as its container. Nothing is started."""
    spec = BoxSpec()
    return BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name)


def chain(exc: BaseException | None) -> list[BaseException]:
    """`exc`, then its `__cause__`/`__context__` links, in order."""
    out: list[BaseException] = []
    while exc is not None and exc not in out:
        out.append(exc)
        exc = exc.__cause__ or exc.__context__
    return out


def carries(got: BaseException | None, fault: BaseException) -> bool:
    """`got` is `fault`, or a `BoxFault` raised from it (main's batch-start unwind re-raises a
    `BoxFault` with the cut commit appended, chained to the original)."""
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
# A fake daemon, in process and as a `docker` program on PATH
# ---------------------------------------------------------------------------------------

_SHIM = '''#!{python} -S
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

    # -- state and faults ---------------------------------------------------------------

    def _edit(self, fn: Callable[[dict], object]) -> None:
        state = daemon_mod.load(self.dir)
        fn(state)
        daemon_mod.save(self.dir, state)

    def _fault(self, key: str, value: Any) -> None:
        self._edit(lambda s: s["faults"].__setitem__(key, value))

    def hold(self, name: str, status: str) -> None:
        """A container named `name` in `status`, as if a batch start (or a run) had left it."""
        self._edit(lambda s: s["containers"].__setitem__(name, {"status": status, "token": ""}))

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

    def refuse_sentinel(self) -> None:
        """Every mount answers bytes other than the sentinel the host planted."""
        self._fault("sentinel", True)

    def go_down(self) -> None:
        self._fault("down", True)

    def _verb_fault(self, verb: str, kind: str, at: Iterable[int] | None, times: int) -> None:
        def edit(state: dict) -> None:
            if at is not None:
                ordinals: list = list(at)
            elif times < 0:
                ordinals = ["*"]
            else:
                done = state["counts"][verb]
                ordinals = list(range(done + 1, done + 1 + times))
            state["faults"][verb][kind] += ordinals

        self._edit(edit)

    def refuse_start(self, *, at: Iterable[int] | None = None, times: int = 1) -> None:
        """`docker start` fails (rc 1, the box stays as it was): the starts numbered `at`
        (from 1), else the next `times` (-1: every one)."""
        self._verb_fault("start", "refuse", at, times)

    def start_takes_no_effect(self, *, at: Iterable[int] | None = None, times: int = 1) -> None:
        """`docker start` answers rc 0 and changes nothing (as `refuse_start` picks)."""
        self._verb_fault("start", "noop", at, times)

    def refuse_stop(self, *, at: Iterable[int] | None = None, times: int = 1) -> None:
        """`docker stop` fails (rc 1, the box keeps running), as `refuse_start` picks."""
        self._verb_fault("stop", "refuse", at, times)

    def stop_takes_no_effect(self, *, at: Iterable[int] | None = None, times: int = 1) -> None:
        """`docker stop` answers rc 0 and the box keeps running (as `refuse_start` picks)."""
        self._verb_fault("stop", "noop", at, times)

    def refuse_inspect(self, *, at: Iterable[int]) -> None:
        """The `inspect -f` calls numbered `at` (from 1) answer rc 1, as for no such object."""
        self._verb_fault("inspect", "refuse", at, 0)

    def inspect_count(self) -> int:
        """How many `inspect -f` calls the daemon has answered so far."""
        return int(daemon_mod.load(self.dir)["counts"]["inspect"])

    def _on(self, verb: str, path: Path, text: str | None, *, link: Path | None,  # noqa: PLR0913 — one action, every shape a row picks
            remove: bool, at: int | None) -> None:
        action: dict[str, Any] = {"path": str(path), "at": at}
        if remove:
            action["remove"] = True
        elif link is not None:
            action["link"] = str(link)
        else:
            action["text"] = text
        self._edit(lambda s: s["on"][verb].append(action))

    def on_start(self, path: Path, text: str | None = None, *, link: Path | None = None,
                 remove: bool = False, at: int | None = None) -> None:
        """The box's first act once a start takes (the `at`-th, else every one): `text` at
        `path` through its mount, a symlink there to `link`, or (`remove`) the entry there
        taken away."""
        self._on("start", path, text, link=link, remove=remove, at=at)

    def on_stop(self, path: Path, text: str | None = None, *, link: Path | None = None,
                remove: bool = False, at: int | None = None) -> None:
        """The box's last act while still up, as a stop takes (as `on_start` picks)."""
        self._on("stop", path, text, link=link, remove=remove, at=at)

    # -- observations -----------------------------------------------------------------

    def status(self, name: str) -> str | None:
        box = daemon_mod.load(self.dir)["containers"].get(name)
        return None if box is None else box["status"]

    def names(self) -> list[str]:
        return sorted(daemon_mod.load(self.dir)["containers"])

    def running(self) -> list[str]:
        return sorted(n for n, b in daemon_mod.load(self.dir)["containers"].items()
                      if b["status"] == "running")

    def boots(self) -> int:
        """How many starts took (a container went from stopped to running): a process lives
        only as long as the boot it was started in."""
        return int(daemon_mod.load(self.dir)["counts"]["boot"])

    def mark(self, label: str) -> None:
        """A test's own step, written into the call log between the docker calls."""
        daemon_mod.log(self.dir, [label])

    def calls(self) -> list[list[str]]:
        log = self.dir / daemon_mod.CALLS
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()
                if line]

    def docker_calls(self) -> list[list[str]]:
        return [c for c in self.calls() if c[0] == "docker"]

    def steps(self, *, of: str | None = None) -> list[str]:
        """The log as one sequence: each mark, and each docker call as `create`, `rm`,
        `status` (an inspect of the status), `start`, `stop` or its verb. With `of`, only the
        calls naming that container, and the marks."""
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

    def windows(self) -> list[list[str]]:
        """The marks inside each run window: from a `docker start` to the next `docker stop`."""
        out: list[list[str]] = []
        current: list[str] | None = None
        for step in self.steps():
            if step == "start":
                current = []
            elif step == "stop":
                if current is not None:
                    out.append(current)
                current = None
            elif current is not None and step not in ("status", "inspect"):
                current.append(step)
        if current is not None:
            out.append(current)
        return out


def boxed(tmp_path: Path, monkeypatch: Any, name: str) -> tuple[FakeDaemon, BoxExecutor]:
    """The fake daemon first on `PATH`, holding `name` `exited` (the batch's box after its
    post-create stop), and the executor `start_box` handed back for it."""
    daemon = FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    daemon.hold(name, "exited")
    return daemon, sandboxed(name)


class Journal(list):
    """A lane's shared log: every entry a host seam or a spawn appends is also marked into the
    daemon's call log (by its kind, `entry[0]`), and the containers running at that moment are
    noted (`seen`, parallel to the entries)."""

    def __init__(self, daemon: FakeDaemon) -> None:
        super().__init__()
        self.daemon = daemon
        self.seen: list[list[str]] = []

    def append(self, entry: Any) -> None:
        super().append(entry)
        self.seen.append(self.daemon.running())
        self.daemon.mark(str(entry[0]))

    def assert_runs_hold_exactly(self, spawns: list[str], spawn_kinds: tuple[str, ...]) -> None:
        """One run window per spawn, in order, each holding its spawn and nothing else; every
        spawn saw the box running (the positive control) and every other step saw nothing
        running (no host step beside a running box)."""
        kinds = [str(e[0]) for e in self]
        assert self.daemon.windows() == [[s] for s in spawns], (
            f"each run must hold exactly its spawn: {self.daemon.steps()}")
        for kind, running in zip(kinds, self.seen, strict=True):
            if kind in spawn_kinds:
                assert running, f"a spawn ran with no box running: {kinds}"
            else:
                assert running == [], f"{kind!r} ran beside a running box {running}: {kinds}"


class ScanWatch:
    """A `scrub=` seam over a `FakeDaemon`: for each tree it is asked to walk it records which
    containers the daemon still holds at that moment (`held`), marks the daemon's log `scan`,
    and appends `scrub:<tree>` to `events` when given."""

    def __init__(self, daemon: FakeDaemon, events: list | None = None) -> None:
        self.daemon, self.events = daemon, events
        self.held: list[list[str]] = []

    def __call__(self, tree: Path, *_a: Any, **_kw: Any) -> None:
        self.held.append(self.daemon.names())
        self.daemon.mark("scan")
        if self.events is not None:
            self.events.append(f"scrub:{tree}")

    def assert_scanned_once_the_box_was_gone(self) -> None:
        """The tree was scanned, and only after the batch-end removal: no container was left."""
        assert self.held, "the tree was never scanned"
        assert all(h == [] for h in self.held), f"a tree was scanned beside a box: {self.held}"


class HeldStart:
    """A `start_box=` that registers the request's container, running, with `daemon` (as a
    real create leaves it) and hands back a sandboxed executor naming it: what the real start
    does, minus the probes. `events` gets `start_box`."""

    def __init__(self, daemon: FakeDaemon, events: list | None = None) -> None:
        self.daemon, self.events = daemon, events
        self.requests: list[Any] = []
        self.boxes: list[BoxExecutor] = []

    def __call__(self, req: Any, *_a: Any, **_kw: Any) -> BoxExecutor:
        self.requests.append(req)
        self.daemon.hold(req.name, "running")
        self.daemon.mark("start_box")
        if self.events is not None:
            self.events.append("start_box")
        self.boxes.append(sandboxed(req.name))
        return self.boxes[-1]


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
