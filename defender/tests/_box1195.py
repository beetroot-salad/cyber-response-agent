"""Shared fakes for the #1195 rows (both drain lanes), design amendment 3. NOT a test module.

The design under test (`gh issue view 1195`, "Design amendment 3 (2026-10-06): the stop fault
wins, the box carries its docker, and lanes get a run handle", refining amendment 2): the drain
creates and checks its one box at batch start, as on main (`start_box`), wraps it in a
`runtime.box.BoxRuns` handle, stops it at once (`runs.stop()`), hands the lanes the handle, and
removes the box at batch end (`stop_box`: `docker rm -f`) before the scan.

- `BoxExecutor.docker`: the docker callable the box was created with (`start_box(...,
  docker=...)` stamps it; `compare=False, repr=False`); every lifecycle call on a sandboxed box
  uses it, and a sandboxed box without one fails closed (F2).
- `BoxRuns(box)`: `BoxFault` for an object with no `sandboxed`, or a sandboxed one with no
  `docker` or `name`; an opt-out handle (no docker calls) for an unsandboxed executor.
  `.stop()`: `docker stop -t 0`, proven `exited` or `dead` (F4). `.run()`: proven `exited`,
  `docker start`, proven `running`, yields the executor, and stops it on EVERY exit; a stop
  fault raises even under an in-flight exception, which becomes its `__context__` (F1).
- `box_for_run(handle)`: `None` for `None`, the handle's run otherwise; anything else, a raw
  executor included, is a `BoxFault` (F3, O6).

Every name the design adds is reached at call time (`BoxRuns`, `box_for_run`, the executor's
`docker` field), so the modules importing this one collect before it exists and fail at the
row that needs it.

The fake daemon (`FakeDaemon`) is callable as a docker seam, so an executor can carry it as its
`docker`; called so, it can also raise at a chosen call instead of answering (`seam_raises`: no
binary, a daemon that never answered). A `Tripwire` installed as the `docker` program first on
`PATH` shows that nothing reaches the real one (`no_path_docker`). `fail_stop` makes a chosen
`docker stop` fail each of the ways in `STOP_FAULTS`. A lane's host steps write into a `Journal`, which marks each into the
daemon's own call log and notes which containers were running at that moment: so a row can
split the log into run windows (between a `docker start` and the next `docker stop`) and see
that each holds exactly its spawn, and that no host step ran beside a running box. Nothing is
patched onto a module.
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

#: A batch box's docker calls from its post-create stop on (`FakeDaemon.calls_from_the_first_stop`)
#: when the batch's first run's start is refused: the stop and its proof; the run's check
#: (`exited`), the refused start and its proof; the best-effort stop and its proof; the batch-end
#: removal. Nothing between the post-create stop and the run's check: no call outside a run.
REFUSED_FIRST_RUN = ["stop", "status", "status", "start", "status", "stop", "status", "rm"]

#: What makes the real `start_box` fail at batch start (the `FakeDaemon` knob), and how main
#: surfaces it: a `BoxFault` with the cut commit appended (`pointed`), or a link ban as
#: `AliasBanNotInForce`, unpointed.
BATCH_START_FAULTS = [
    pytest.param("refuse_create", BoxFault, True, id="create"),
    pytest.param("refuse_sentinel", BoxFault, True, id="sentinel"),
    pytest.param("allow_an_alias", AliasBanNotInForce, False, id="link-ban"),
]

#: The ways a stop fails to prove the box stopped (`fail_stop`): refused (rc 1, the box keeps
#: running), answering 0 with the box still running, taking while the status asked after it goes
#: unanswered, or the docker seam raising at it (no binary; a daemon that never answered).
STOP_FAULTS = ["refused", "takes-no-effect", "status-unanswered", "seam-OSError",
               "seam-TimeoutExpired"]


# ---------------------------------------------------------------------------------------
# The design's new names, reached at call time
# ---------------------------------------------------------------------------------------


def box_for_run(handle: Any) -> contextlib.AbstractContextManager[Any]:
    """`runtime.box.box_for_run(handle)`, imported at call time."""
    from defender.runtime.box import box_for_run as _box_for_run

    return _box_for_run(handle)


def box_runs_type() -> type:
    """`runtime.box.BoxRuns`, imported at call time."""
    from defender.runtime.box import BoxRuns

    return BoxRuns


def box_runs(box: Any) -> Any:
    """`runtime.box.BoxRuns(box)`, the lanes' handle on the batch's box."""
    return box_runs_type()(box)


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


def sandboxed(name: str, docker: Any = None) -> BoxExecutor:
    """An executor as `start_box` hands one back for a created container: the docker transport,
    so `sandboxed` is true, named as its container, carrying `docker` as the docker callable it
    was created with (none given: the field is left at its default). Nothing is started."""
    spec = BoxSpec()
    if docker is None:
        return BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name)
    return BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name,
                       docker=docker)  # type: ignore[call-arg]


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

#: The names `FakeDaemon.steps` gives docker calls (anything else in the log is a mark).
_DOCKER_STEPS = frozenset({"create", "rm", "status", "start", "stop", "inspect", "exec"})

def _step_of(argv: list[str]) -> str:
    """A docker call's name in `FakeDaemon.steps`: its verb, `create` for `docker run`, and
    `status` for an inspect of the status."""
    verb = argv[1] if len(argv) > 1 else ""
    if verb == "run":
        return "create"
    if verb == "inspect" and "-f" in argv and "State.Status" in argv[argv.index("-f") + 1]:
        return "status"
    return verb


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
        #: The `Tripwire` on `PATH` beside it, when `boxed` installed one.
        self.tripwire: Tripwire | None = None
        self._seam_faults: list[tuple[str, str, list[int] | None]] = []
        self._seam_counts: dict[str, int] = {}
        self.seam_raised: list[str] = []

    # -- the seams -------------------------------------------------------------------

    def __call__(self, argv: Any, **_kw: Any) -> subprocess.CompletedProcess:
        argv = [str(a) for a in argv]
        self._seam_fault(argv)
        rc, out, err = daemon_mod.handle(self.dir, argv)
        return subprocess.CompletedProcess(argv, rc, out, err)

    def _seam_fault(self, argv: list[str]) -> None:
        """Raise instead of answering, when a `seam_raises` fault is due at this call."""
        step = _step_of(argv)
        self._seam_counts[step] = self._seam_counts.get(step, 0) + 1
        for kind, want, at in self._seam_faults:
            if want in ("*", step) and (at is None or self._seam_counts[step] in at):
                self.seam_raised.append(step)
                if kind == "OSError":
                    raise FileNotFoundError(2, "No such file or directory", "docker")
                raise subprocess.TimeoutExpired(cmd=argv, timeout=120)

    def seam_raises(self, kind: str, *, step: str, at: Iterable[int] | None = None) -> None:
        """Called in process, the daemon raises `kind` instead of answering (`OSError`: no
        docker binary; `TimeoutExpired`: a daemon that never answered): at the `step` calls (as
        `steps` names them, or `"*"` for any) numbered `at` (from 1, counted per step from this
        daemon's creation), else every one. The call never reaches the daemon's log;
        `seam_raised` lists each step that raised."""
        self._seam_faults.append((kind, step, None if at is None else list(at)))

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

    def forget(self, name: str) -> None:
        """No container named `name` any more, as if something removed it."""
        self._edit(lambda s: s["containers"].pop(name, None))

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

    def stop_leaves_it_dead(self, *, at: Iterable[int] | None = None, times: int = 1) -> None:
        """`docker stop` takes, and the container is left `dead` rather than `exited` (as
        `refuse_start` picks): nothing runs in it either way."""
        self._verb_fault("stop", "dead", at, times)

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
            out.append(_step_of(argv))
        return out

    def calls_from_the_first_stop(self, name: str) -> list[str]:
        """The docker calls naming `name`, as `steps` names them (marks left out), from its first
        `docker stop` on: for a drained batch, its post-create stop, then every status ask,
        start, stop and removal after it. A row compares the whole sequence, so a call outside a
        run (an extra stop and its proof between two runs) shows."""
        calls = [s for s in self.steps(of=name) if s in _DOCKER_STEPS]
        return calls[calls.index("stop"):] if "stop" in calls else calls

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


class Tripwire:
    """A `docker` program first on `PATH` that records every argv it is handed and answers rc 97:
    a lifecycle call that falls back on the real docker reaches it, and fails."""

    def __init__(self, tmp_path: Path) -> None:
        self.dir = tmp_path / "tripwire1195"
        self.dir.mkdir(parents=True)
        self.log = self.dir / "argv.log"

    def install(self, monkeypatch: Any) -> Tripwire:
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        program = bin_dir / "docker"
        program.write_text(
            f"#!{sys.executable} -S\nimport sys\n"
            f"open({str(self.log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
            "sys.stderr.write('tripwire: the docker on PATH was called\\n')\nsys.exit(97)\n",
            encoding="utf-8")
        program.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
        assert shutil.which("docker") == str(program)
        return self

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []


def boxed(tmp_path: Path, monkeypatch: Any, name: str
          ) -> tuple[FakeDaemon, BoxExecutor, Any]:
    """The fake daemon holding `name` `exited` (the batch's box after its post-create stop), the
    executor `start_box` handed back for it, carrying the daemon as its docker, and the lanes'
    handle on it. A `Tripwire` is the `docker` on `PATH` (`daemon.tripwire`), so a call that
    does not go through the carried docker fails, and shows."""
    daemon = FakeDaemon(tmp_path)
    daemon.tripwire = Tripwire(tmp_path).install(monkeypatch)
    daemon.hold(name, "exited")
    box = sandboxed(name, docker=daemon)
    return daemon, box, box_runs(box)


def no_path_docker(daemon: FakeDaemon) -> None:
    """Nothing reached the `docker` on `PATH` (the daemon's `Tripwire`): every lifecycle call
    went through the docker the box carries."""
    assert daemon.tripwire is not None, "no tripwire on PATH, so the check is vacuous"
    assert daemon.tripwire.calls() == [], (
        f"a call reached the docker on PATH: {daemon.tripwire.calls()}")


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
    real create leaves it) and hands back a sandboxed executor naming it and carrying `daemon`
    as its docker: what the real start does, minus the probes. `events` gets `start_box`."""

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
        self.boxes.append(sandboxed(req.name, docker=self.daemon))
        return self.boxes[-1]


def fail_stop(daemon: FakeDaemon, stop: str, *, at: int, inspect_at: int) -> None:
    """The `at`-th `docker stop` fails as `stop` (one of `STOP_FAULTS`) names; for
    `status-unanswered`, the stop takes and the `inspect_at`-th `inspect -f` (the status asked
    after it) goes unanswered."""
    if stop == "refused":
        daemon.refuse_stop(at=[at])
    elif stop == "takes-no-effect":
        daemon.stop_takes_no_effect(at=[at])
    elif stop == "status-unanswered":
        daemon.refuse_inspect(at=[inspect_at])
    else:
        daemon.seam_raises(stop.removeprefix("seam-"), step="stop", at=[at])


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
