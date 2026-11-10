"""#1343 B10 fakes: a stand-in for the held attached `docker start -a -i` process of a run box.

Test-only. The run box's attached start goes through the docker seam object itself (r5 item 15): the
object passed as `docker=` carries a `.popen(argv, **kw)` capability, as production's real docker does.
`AttachedStartSeam` gives a docker fake that capability. It records what the box executor asks for and
models the one observable consequence of a landed start (the container reports `running`); it decides
nothing about the policy under test (created `-i --rm`, started attached, waited on, input kept open).
Evidence from it is about wiring at the seam; the real-daemon tests carry the rest."""
from __future__ import annotations

import contextlib
import io
import os
import signal
import subprocess
import weakref
from typing import Any


class StarterLedger:
    """What the seam saw of one attached start; plain data, so it outlives a collected starter."""

    def __init__(self, argv: list[str], kwargs: dict[str, Any], read_fd: int, returncode: int | None):
        self.argv = argv
        self.kwargs = kwargs
        self.read_fd = read_fd          # read end of the starter's input pipe: only the test holds it
        self.returncode = returncode    # None while the starter lives


def input_open(read_fd: int) -> bool:
    """True while nothing has closed the starter's input (a read would block); False at EOF."""
    try:
        return os.read(read_fd, 1) != b""
    except BlockingIOError:
        return True


class _Input(io.FileIO):
    """The starter's stdin: closing it (or dropping the last reference) ends the starter, as `cat` ends at EOF."""

    ledger: StarterLedger

    def close(self) -> None:
        if self.ledger.returncode is None:
            self.ledger.returncode = 0
        super().close()


class FakeStarter:
    """A `subprocess.Popen`-shaped stand-in for the attached start. Collected when its holder drops it."""

    def __init__(self, ledger: StarterLedger, write_fd: int, stderr: bytes):
        self.ledger = ledger
        self.args = ledger.argv
        self.pid = 4_000_000 + os.getpid() % 1000
        self.stdin = _Input(write_fd, "wb")
        self.stdin.ledger = ledger
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(stderr)

    @property
    def returncode(self) -> int | None:
        return self.ledger.returncode

    def poll(self) -> int | None:
        return self.ledger.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.ledger.returncode is None:
            raise subprocess.TimeoutExpired(self.args, timeout or 0)
        return self.ledger.returncode

    def communicate(self, input: bytes | None = None, timeout: float | None = None) -> tuple[bytes, bytes]:
        return b"", self.stderr.read()

    def send_signal(self, sig: int) -> None:
        self.ledger.returncode = -int(sig)

    def terminate(self) -> None:
        self.send_signal(signal.SIGTERM)

    def kill(self) -> None:
        self.send_signal(signal.SIGKILL)

    def __enter__(self) -> FakeStarter:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def _close_fds(fds: list[int]) -> None:
    for fd in fds:
        with contextlib.suppress(OSError):
            os.close(fd)


class AttachedStartSeam:
    """Mixin: gives a docker fake the attached-start capability. The fake implements `_record(argv)`
    (log the call as it logs its others) and `_landed(argv)` (the container now reports running; or, a
    daemon that models start faults, the starter's `(rc, stderr)` when the start did not hold)."""

    starter_exit: tuple[int, bytes] | None = None   # (rc, stderr): the starter dies before the box ran
    lands = True                                    # False: the start never lands (the box never runs)

    def _attached_state(self) -> None:
        self.asks: list[StarterLedger] = []
        self._starters: list[weakref.ref] = []
        self._read_fds: list[int] = []
        weakref.finalize(self, _close_fds, self._read_fds)   # the test's read ends go with the fake

    def popen(self, argv, **kw):  # noqa: ANN001 — Popen's own signature
        argv = list(argv)
        self._record(argv)
        read, write = os.pipe()
        os.set_blocking(read, False)
        rc, err = self.starter_exit if self.starter_exit is not None else (None, b"")
        if self.starter_exit is None and self.lands:
            ended = self._landed(argv)
            if ended is not None:   # the daemon refused the start, or it took no effect
                rc, err = ended[0], ended[1].encode()
        ledger = StarterLedger(argv, dict(kw), read, rc)
        starter = FakeStarter(ledger, write, err)
        self.asks.append(ledger)
        self._read_fds.append(read)
        self._starters.append(weakref.ref(starter))   # held weakly: an executor that drops it frees it
        return starter

    def held_starters(self) -> list[FakeStarter]:
        """The starters still referenced by anything (the box executor, in a run that holds its input)."""
        return [s for s in (ref() for ref in self._starters) if s is not None]
