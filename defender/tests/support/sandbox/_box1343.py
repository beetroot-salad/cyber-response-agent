"""#1343 B10 fakes: a stand-in for the held attached `docker start -a -i` process of a run box.

Test-only. The fake records what the box executor asks the seam to start and models the daemon's
observable consequence (the container reports `running` once the start landed); it decides nothing
about the policy under test (that a run box is created `-i --rm`, started attached, waited on, and its
input kept open). Evidence from it is about wiring at the seam; the real daemon tests carry the rest."""
from __future__ import annotations

import io
import os
import signal
from typing import Any


class FakeStarter:
    """A `subprocess.Popen`-shaped stand-in: `stdin` is the write end of a real pipe, whose read end
    only the test holds, so "the box's input is still open" is observable as "that read end sees no EOF"
    and a garbage-collected or closed `stdin` shows up as EOF."""

    def __init__(self, argv: list[str], kwargs: dict[str, Any], *, exits: tuple[int, bytes] | None = None):
        self.args = list(argv)
        self.kwargs = dict(kwargs)
        self.pid = 4_000_000 + os.getpid() % 1000
        read, write = os.pipe()
        os.set_blocking(read, False)
        self._read = read
        self.stdin = os.fdopen(write, "wb", buffering=0)
        self.stdout = io.BytesIO(b"")
        self.returncode: int | None = None
        self.stderr = io.BytesIO(b"")
        if exits is not None:
            self.returncode, err = exits
            self.stderr = io.BytesIO(err)

    # -- what the test reads
    def input_open(self) -> bool:
        """True while nothing has closed the starter's input (a read would block); False at EOF."""
        try:
            return os.read(self._read, 1) != b""
        except BlockingIOError:
            return True

    def close_probe(self) -> None:
        os.close(self._read)

    # -- the Popen surface a holder may use
    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise TimeoutError("the fake starter was never given an exit")
        return self.returncode

    def communicate(self, input: bytes | None = None, timeout: float | None = None) -> tuple[bytes, bytes]:
        return b"", self.stderr.read()

    def send_signal(self, sig: int) -> None:
        self.returncode = -int(sig)

    def terminate(self) -> None:
        self.send_signal(signal.SIGTERM)

    def kill(self) -> None:
        self.send_signal(signal.SIGKILL)

    def __enter__(self) -> "FakeStarter":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None
