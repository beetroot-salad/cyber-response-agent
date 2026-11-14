"""The job socket's wire and its client (#1170): what a job container's processes and the per-job host helper
(`defender.job_host`) say to each other, one request and one answer per connection.

Low in the import order and standard library only, so every in-container caller (the investigation entry, learning's
pre-flight and siblings, the post-step, the box relay) can ask the helper whatever package it lives in. The helper's
server is `defender.job_host`, which re-exports these names.

The wire: a unix stream socket; each message is a 4-byte big-endian length and that many bytes of UTF-8 JSON. A request
is `{"request": name, "fields": {...}}`, its answer `{"ok": {...}}` or `{"refused": {"code": ..., "reason": ...}}`.
`bytes` travel as `{"$bytes": "<base64>"}` and come back as `bytes` (a box frame is bytes)."""
from __future__ import annotations

import base64
import functools
import json
import logging
import math
import os
import signal
import socket as _socket
import struct
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

__all__ = [
    "FORGE_TOKEN_CAP", "HELPER_LABEL", "IMAGE_ENV", "JOB_LABEL", "MAX_MESSAGE", "NETWORK_ENV", "SOCKET_ENV", "Refused", "ask",
    "from_environ", "read_message", "sigterm_on_stdin_eof", "write_message",
]

#: The in-container variable naming the job socket's path (the same path inside and on the host: the socket's folder is
#: bound at its own path).
SOCKET_ENV = "DEFENDER_JOB_SOCKET"
#: The label every job container carries (its value: the job's kind), beside the tenant's and the claim's: the worker's
#: start sweep removes every container carrying it (#1170 A5).
JOB_LABEL = "defender.job"
#: The label naming the helper that holds a job container (its `tenancy.process_mark`): the worker's start sweep spares
#: a container whose helper still runs, so a worker on a shared daemon never removes another worker's live jobs.
HELPER_LABEL = "defender.job-host"
#: The setting naming the docker network job containers join (#1170 N5): judged once, at the worker's start
#: (`worker._start.check_job_network`), and only joined by the helper.
NETWORK_ENV = "DEFENDER_JOB_NETWORK"
#: The setting naming the job container's image (#1170 A7).
IMAGE_ENV = "DEFENDER_JOB_IMAGE"

#: The longest validity a forge token is asked for and minted (C25: the network timeout, 120 s, plus 30 s of skew): the
#: container clamps its ask to it and the helper refuses past it.
FORGE_TOKEN_CAP = 150.0

#: The largest message either side reads: a box frame is at most the box output limit (64 MiB), base64 adds a third.
MAX_MESSAGE = 96 * 1024 * 1024
_LENGTH = struct.Struct(">I")
_BYTES = "$bytes"
#: How long a client waits on an answer that names no command timeout of its own; a box start runs its probes first.
_ANSWER_WAIT = 300.0
#: Beyond a command's own timeout, what a `box.exec` client allows the helper for the exchange around it.
_EXEC_MARGIN = 60.0


class Refused(Exception):  # noqa: N818 — named for what it reports
    """The helper's typed refusal of a request: `code` names the kind of refusal (`unknown-request`, `not-for-kind`,
    `bad-fields`, `unknown-id`, `unknown-handle`, `signalled`, `no-grant`, `sign-fault`, `box-start`, `confinement`,
    `peer`, `internal`, ...), `str()` the helper's reason."""

    def __init__(self, reason: str, code: str = "refused") -> None:
        super().__init__(reason)
        self.code = code


def _encode_value(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {_BYTES: base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, Mapping):
        return {str(k): _encode_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode_value(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _decode(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {_BYTES} and isinstance(value[_BYTES], str):
            return base64.b64decode(value[_BYTES].encode("ascii"), validate=True)
        return {k: _decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value


def write_message(sock: _socket.socket, message: Any) -> None:
    """Send one message (`bytes` anywhere in it encoded as the wire says)."""
    data = json.dumps(_encode_value(message), separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_MESSAGE:
        raise ValueError(f"a job socket message of {len(data)} bytes is over the {MAX_MESSAGE}-byte limit")
    sock.sendall(_LENGTH.pack(len(data)) + data)


def _read_exactly(sock: _socket.socket, n: int) -> bytes:
    chunks, got = [], 0
    while got < n:
        chunk = sock.recv(min(n - got, 1 << 20))
        if not chunk:
            raise ConnectionResetError("the job socket closed before a whole message arrived")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def read_message(sock: _socket.socket) -> Any:
    """Read one message; `ConnectionResetError` when the peer closes first, `ValueError` for one that is not ours."""
    (length,) = _LENGTH.unpack(_read_exactly(sock, _LENGTH.size))
    if length > MAX_MESSAGE:
        raise ValueError(f"a job socket message of {length} bytes is over the {MAX_MESSAGE}-byte limit")
    try:
        return _decode(json.loads(_read_exactly(sock, length).decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as bad:
        raise ValueError(f"an unreadable job socket message: {bad}") from None


def _wait_for(request: str, fields: Mapping[str, Any]) -> float:
    timeout = fields.get("timeout")
    if request == "box.exec" and isinstance(timeout, (int, float)) and math.isfinite(timeout) and timeout > 0:
        return float(timeout) + _EXEC_MARGIN
    return _ANSWER_WAIT


def ask(socket: str | Path, request: str, **fields: Any) -> dict[str, Any]:
    """Ask the helper at `socket` one `request` and return its answer. A typed refusal raises `Refused`; a socket that
    is gone, or a helper that ends or goes silent before answering, raises `OSError` (`TimeoutError` included); an
    answer that is not the wire's raises `ValueError`."""
    with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as sock:
        sock.settimeout(_wait_for(request, fields))
        sock.connect(str(socket))
        write_message(sock, {"request": request, "fields": fields})
        answer = read_message(sock)
    if isinstance(answer, dict) and isinstance(answer.get("ok"), dict) and len(answer) == 1:
        return answer["ok"]
    refused = answer.get("refused") if isinstance(answer, dict) else None
    if isinstance(refused, dict):
        raise Refused(str(refused.get("reason", "refused")), str(refused.get("code", "refused")))
    raise ValueError(f"the helper's answer to {request!r} is not the job socket's: {type(answer).__name__}")


def from_environ(environ: Mapping[str, str]) -> Callable[..., dict[str, Any]] | None:
    """The job's client bound to the socket `environ` names (`SOCKET_ENV`), or None outside a job container."""
    path = environ.get(SOCKET_ENV)
    return functools.partial(ask, path) if path else None


def sigterm_on_stdin_eof() -> threading.Thread:
    """The container's death tie (#1170 A5): the per-job host helper holds this process's stdin, so at its end (EOF,
    or a stdin that cannot be read) this process is sent SIGTERM and its entry unwinds exactly as on the helper's stop.
    Read on a daemon thread, so the entry never waits on it; whatever arrives on stdin before the end is discarded.
    Only a container process's own entry point calls this (never an in-process caller, whose stdin is not the
    helper's)."""

    def watch() -> None:
        try:
            while os.read(0, 65536):
                pass
        except OSError as unreadable:
            logging.getLogger(__name__).warning(
                "the job container's stdin cannot be read (%r); ending as on SIGTERM", unreadable)
        os.kill(os.getpid(), signal.SIGTERM)

    thread = threading.Thread(target=watch, name="stdin-eof", daemon=True)
    thread.start()
    return thread
