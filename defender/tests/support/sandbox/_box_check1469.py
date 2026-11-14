"""#1469 D1: a fake daemon's answer to the box check, driven through the real host listener.

Test-only. The box check is two short `docker run --rm` containers (the box runtime's, then a control under `--runtime
runc`), each trying one stream connect to `/run/box-check/s` through a bound check folder. A fake that stubbed the verdict
would test nothing: this one finds the bind's host folder in the run's argv and CONNECTS to the socket the production
listener made there (as the container would), so the listener's own accept is what the verdict reads. What it prints is
the container's marker: `connected`, or `refused <errno>` (the marker's wording is a pick of this contract, see the
tests' report); nothing about how the box check judges is decided here."""
from __future__ import annotations

import contextlib
import os
import socket
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Where the check folder sits in the check container (D1), and the socket's name in it.
CHECK_TARGET = "/run/box-check"
SOCKET_NAME = "s"

#: What the container prints (`marker`): the word `connected`, `refused 111` (ECONNREFUSED), nothing, or what the daemon does
#: instead of running it: it could not start the container (rc 125) or the client outlives the host's timeout.
CONNECTED, REFUSED, NONE, DOES_NOT_START, TIMES_OUT = "connected", "refused", "none", "does-not-start", "times-out"
MARKERS = (CONNECTED, REFUSED, NONE, DOES_NOT_START, TIMES_OUT)


@dataclass(frozen=True)
class Cell:
    """One run's behaviour, its two independent axes: the `marker` it prints and whether the production listener
    `accept`ed a connection during it. `accept=True` is a REAL connect to the listener's socket (the verdict reads the
    listener's own accept); `accept=False` never touches the socket. So a marker may disagree with the accept either way:
    `connected` printed with no accept, or `refused` printed over a connection that was accepted."""

    marker: str
    accept: bool

    def __str__(self) -> str:
        return f"{self.marker}-{'accept' if self.accept else 'no-accept'}"


#: Named cells the other contracts use.
SANDBOXES = Cell(REFUSED, False)  # refuses the connect: no accept, marker `refused 111`
LEAKS = Cell(CONNECTED, True)  # connects through to the listener: accepted, marker `connected`
ACCEPTS_BUT_SAYS_REFUSED = Cell(REFUSED, True)  # the listener accepts, the marker says `refused`
NO_MARKER = Cell(NONE, False)  # the container ran and printed nothing
START_FAILS = Cell(DOES_NOT_START, False)  # docker could not run the container (rc 125)
HANGS = Cell(TIMES_OUT, False)  # the client outlives the host's timeout (`subprocess.TimeoutExpired`)
CONNECTS = LEAKS  # control: a working run, really connected
REFUSES = SANDBOXES  # control: it did not connect (a host layout that cannot carry sockets)
CELLS = tuple(Cell(m, a) for m in MARKERS for a in (False, True))


def verdict(box: Cell, control: Cell) -> str:
    """D1's rule over what a check saw, written out from the design and not from any implementation: `failed` when the box
    runtime's run printed `connected` or the listener accepted during it; `pass` when it reached its marker (`refused`)
    with no accept AND the control printed `connected` with an accept; `inconclusive` otherwise."""
    if box.marker == CONNECTED or box.accept:
        return "failed"
    if box.marker == REFUSED and control.marker == CONNECTED and control.accept:
        return "pass"
    return "inconclusive"


@dataclass
class CheckPlan:
    """What the daemon does with a box check's two runs. The default is a healthy sandbox: the box runtime refuses, the
    control connects. `daemon_view` is the `(this process's path, the daemon's path)` mount table the start translated its
    binds through, reversed here to find the folder the daemon was told to bind."""

    box: Cell = SANDBOXES
    control: Cell = CONNECTS
    daemon_view: Sequence[tuple[Path, Path]] = ()


@dataclass
class CheckRun:
    """One check container the fake was asked to run, with what stood on the host while it ran."""

    argv: list[str]
    kwargs: dict[str, Any]
    runtime: str
    name: str
    source: str  # the bind's source as the daemon was told it
    folder: Path  # the same folder as this process sees it
    folder_mode: int | None = None
    parent_mode: int | None = None
    socket_mode: int | None = None
    socket_existed: bool = False
    connected: bool | None = None  # None: this run never tried the socket
    marker: str = ""

    @property
    def is_control(self) -> bool:
        return self.runtime == "runc"


def check_bind(argv: Sequence[str]) -> dict[str, str] | None:
    """The `--mount` of a `docker run` that binds the check folder (target `/run/box-check`), parsed; else None."""
    argv = list(argv)
    for i, tok in enumerate(argv[:-1]):
        if tok == "--mount":
            parts = dict(p.split("=", 1) for p in argv[i + 1].split(",") if "=" in p)
            if parts.get("target") == CHECK_TARGET:
                return parts
    return None


def is_check_run(argv: Sequence[str]) -> bool:
    return len(argv) > 1 and argv[1] == "run" and check_bind(argv) is not None


def flag_value(argv: Sequence[str], flag: str) -> str | None:
    argv = list(argv)
    return argv[argv.index(flag) + 1] if flag in argv else None


def _local(source: str, view: Sequence[tuple[Path, Path]]) -> Path:
    path = Path(source)
    for here, there in view:
        if path.is_relative_to(there):
            return here / path.relative_to(there)
    return path


def _connect(folder: Path) -> tuple[bool, int | None]:
    """One stream connect to `<folder>/s` by a short descriptor path (a long folder cannot be named in a socket address),
    as the container's own connect would: `(connected, errno)`. A connected stream is then read until the listener closes
    it or a second passes, so the listener has had its accept when this returns."""
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as e:
        return False, e.errno
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            try:
                s.connect(f"/proc/self/fd/{fd}/{SOCKET_NAME}")
            except OSError as e:
                return False, e.errno
            s.settimeout(1.0)
            with contextlib.suppress(OSError):
                s.recv(1)
            return True, None
    finally:
        os.close(fd)


def _mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.lstat().st_mode)
    except OSError:
        return None


def answer(argv: list[str], plan: CheckPlan, kwargs: dict[str, Any], runs: list[CheckRun]) -> subprocess.CompletedProcess:
    """The daemon's answer to one check container, recorded in `runs`."""
    bind = check_bind(argv)
    assert bind is not None, argv
    folder = _local(bind["source"], plan.daemon_view)
    run = CheckRun(argv=list(argv), kwargs=dict(kwargs), runtime=flag_value(argv, "--runtime") or "",
                   name=flag_value(argv, "--name") or "", source=bind["source"], folder=folder)
    runs.append(run)
    run.folder_mode, run.parent_mode = _mode(folder), _mode(folder.parent)
    run.socket_mode = _mode(folder / SOCKET_NAME)
    run.socket_existed = (folder / SOCKET_NAME).exists()
    what = plan.control if run.is_control else plan.box

    def done(rc: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess:
        run.marker = out.strip()
        return subprocess.CompletedProcess(argv, rc, out, err)

    if what.accept:  # a real connect to the production listener's socket, so its own accept is what the verdict reads
        run.connected, _code = _connect(folder)
    else:
        run.connected = False
    if what.marker == DOES_NOT_START:
        return done(125, "", "docker: Error response from daemon: the check container could not be started\n")
    if what.marker == TIMES_OUT:
        raise subprocess.TimeoutExpired(argv, float(kwargs.get("timeout") or 30))
    return done(0, {CONNECTED: "connected\n", REFUSED: "refused 111\n", NONE: ""}[what.marker])


@dataclass
class CheckLedger:
    """The check containers a fake daemon ran, and the plan it ran them by."""

    plan: CheckPlan = field(default_factory=CheckPlan)
    runs: list[CheckRun] = field(default_factory=list)

    def box_runs(self) -> list[CheckRun]:
        return [r for r in self.runs if not r.is_control]

    def control_runs(self) -> list[CheckRun]:
        return [r for r in self.runs if r.is_control]
