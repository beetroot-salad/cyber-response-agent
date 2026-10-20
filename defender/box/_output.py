"""Bound the bytes a Docker exec can return to the host (#1205)."""
from __future__ import annotations

import os
import selectors
import subprocess
import time
from collections.abc import Callable, Sequence

from defender.execution.box_codec import BoxFault, RawExec

# A transport budget, independent of file-read and model-display limits.
BOX_OUTPUT_LIMIT = 64 * 1024 * 1024
_CHUNK = 64 * 1024
_REAP_TIMEOUT = 5.0


class BoxOutputLimitExceeded(BoxFault):
    """Fatal: the response exceeded its budget and its box must no longer run."""

    def __init__(self, limit: int = BOX_OUTPUT_LIMIT) -> None:
        self.limit = limit
        super().__init__(f"box output exceeded the {limit}-byte limit; ending the run")


def _exchange(  # noqa: C901 — one selector loop owns the request and both response streams
    proc: subprocess.Popen[bytes], argv: Sequence[str], frame: bytes, *,
    timeout: float, deadline: float, limit: int,
) -> RawExec:
    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    sent = 0
    received = 0

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise subprocess.TimeoutExpired(argv, timeout)
        return left

    with selectors.DefaultSelector() as selector:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
        if frame:
            selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            proc.stdin.close()
        selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            for key, _events in selector.select(remaining()):
                if key.data == "stdin":
                    sent = _send(key.fd, frame, sent)
                    if sent == len(frame):
                        selector.unregister(key.fileobj)
                        proc.stdin.close()
                    continue
                try:
                    chunk = os.read(key.fd, min(_CHUNK, limit - received + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                received += len(chunk)
                if received > limit:
                    raise BoxOutputLimitExceeded(limit)
                output[key.data].extend(chunk)
        rc = proc.wait(timeout=remaining())
    return RawExec(rc=rc, stdout=bytes(output["stdout"]), stderr=bytes(output["stderr"]))


def _send(fd: int, frame: bytes, sent: int) -> int:
    try:
        return sent + os.write(fd, memoryview(frame)[sent:sent + _CHUNK])
    except BlockingIOError:
        return sent
    except BrokenPipeError:
        return len(frame)


def capture_bounded(
    argv: Sequence[str], frame: bytes, *, timeout: float,
    limit: int = BOX_OUTPUT_LIMIT,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
) -> RawExec:
    """Exchange one request while bounding the aggregate raw stdout and stderr bytes."""
    deadline = time.monotonic() + timeout
    proc = popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE, bufsize=0)
    failure: BaseException | None = None
    try:
        return _exchange(proc, argv, frame, timeout=timeout, deadline=deadline, limit=limit)
    except BaseException as exc:
        failure = exc
        raise
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
        if proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=_REAP_TIMEOUT)
            except (OSError, subprocess.SubprocessError) as cleanup:
                if failure is None:
                    raise
                failure.add_note(f"could not reap the local Docker client: {cleanup}")
