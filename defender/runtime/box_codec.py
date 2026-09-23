"""The box wire: the request/response frames, and the env a box may carry.

STDLIB ONLY (#1096) — and that is a COST rule, not an availability one. Two rules are easy to
confuse here, so both, in order:

  * #1092 retired the AVAILABILITY rule. The owned box image installs the project's
    dependencies, so pydantic resolves inside a box and the `box` package door is free to use
    it — `BoxSpec` is a `@model` dataclass today, which is that retirement's live pin.
  * #1096 adds the COST rule, which is this module's. One process imports it per `docker
    exec`, and there is one `docker exec` per command an agent issues. Importing the package
    door instead costs roughly SEVEN TIMES this module's import (measured both ways in #1096;
    the absolute figures are host-specific, the ratio is what matters), because the door
    reaches `defender._model` and through it pydantic.

So: everything the in-box entrypoint needs lives here — the codec below and the env allowlist —
and a third-party import added to this module is paid once per agent command, forever.
"""
from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass  # stdlib, deliberately — see the module docstring
from defender.runtime import bash_exec


#: F7 — the positive env allowlist: the keys a box's environment may carry, whether merged
#: from a caller's request env by the `docker run` builders or filtered from the in-box
#: entrypoint's own environment before a command runs. Owned HERE, beside the wire, because
#: the in-box reader is the one that must not pay for the package door to reach it (#1096).
BOX_ENV_ALLOWLIST: tuple[str, ...] = (
    "DEFENDER_DIR",
    "DEFENDER_RUN_DIR",
    "DEFENDER_RUNS_BASE",
    "PATH",
    "PYTHONPATH",
    "LANG",
    "TZ",
    "DEFENDER_BOX",
)

#: M6/JF3 — the in-box mark. Spread into both `docker run` argv builders AFTER every other
#: source of env (a caller's `request.env`, the run-dir lane's derived infra env), so nothing a
#: caller supplies can switch it back off inside a box; both host lanes (`_host_fallback_env`,
#: `run_common.run_env`) strip the key instead of ever setting it.
_BOX_MARK_ENV: dict[str, str] = {"DEFENDER_BOX": "1"}


class BoxFault(Exception):
    pass


@dataclass(frozen=True)
class BoxResult:

    rc: int
    out: bytes
    err: bytes


@dataclass(frozen=True)
class RawExec:

    rc: int
    stdout: bytes
    stderr: bytes


REQUEST_MAGIC = b"DFB1"
RESPONSE_MAGIC = b"DFR1"

_RESPONSE_HEADER = struct.Struct("!4siQQ")
_U32 = struct.Struct("!I")
_U8 = struct.Struct("!B")

_CONNECTORS: tuple[str, ...] = ("first", "&&", "||", ";")
_STDERR_MODES: tuple[str, ...] = ("capture", "devnull", "stdout")


def _encode_text(value: str) -> bytes:
    if "\x00" in value:
        raise ValueError(f"argument contains an embedded NUL and cannot cross the box wire: {value!r}")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValueError(
            f"argument is not valid UTF-8 and will not be transcoded to cross the box wire: {value!r}"
        ) from e
    return _U32.pack(len(raw)) + raw


def encode_request(pipelines: Sequence[bash_exec.Pipeline]) -> bytes:
    body = bytearray(REQUEST_MAGIC)
    body += _U32.pack(len(pipelines))
    for pl in pipelines:
        if pl.connector not in _CONNECTORS:
            raise ValueError(f"unknown pipeline connector {pl.connector!r}")
        body += _U8.pack(_CONNECTORS.index(pl.connector))
        body += _U32.pack(len(pl.stages))
        for stage in pl.stages:
            if stage.stderr not in _STDERR_MODES:
                raise ValueError(f"unknown stage stderr mode {stage.stderr!r}")
            body += _U8.pack(_STDERR_MODES.index(stage.stderr))
            body += _U32.pack(len(stage.argv))
            for arg in stage.argv:
                body += _encode_text(arg)
    return bytes(body)


class _Reader:

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self._at + n > len(self._data):
            raise ValueError("box request frame is truncated or overstates a length")
        chunk = self._data[self._at:self._at + n]
        self._at += n
        return chunk

    def u32(self) -> int:
        return int(_U32.unpack(self.take(_U32.size))[0])

    def index(self, vocabulary: tuple[str, ...]) -> str:
        i = int(_U8.unpack(self.take(1))[0])
        if i >= len(vocabulary):
            raise ValueError(f"box request frame carries an out-of-range index {i}")
        return vocabulary[i]

    def text(self) -> str:
        raw = self.take(self.u32())
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("box request frame carries a non-UTF-8 argument") from e

    def done(self) -> bool:
        return self._at == len(self._data)


def decode_request(frame: bytes) -> list[bash_exec.Pipeline]:
    if not frame.startswith(REQUEST_MAGIC):
        raise ValueError("not a box request frame")
    r = _Reader(frame[len(REQUEST_MAGIC):])
    pipelines: list[bash_exec.Pipeline] = []
    for _ in range(r.u32()):
        connector = r.index(_CONNECTORS)
        stages: list[bash_exec.Stage] = []
        for _ in range(r.u32()):
            mode = r.index(_STDERR_MODES)
            argv = [r.text() for _ in range(r.u32())]
            stages.append(bash_exec.Stage(argv=argv, stderr=mode))
        pipelines.append(bash_exec.Pipeline(connector=connector, stages=stages))
    if not r.done():
        raise ValueError("box request frame has trailing bytes")
    return pipelines


def encode_response(result: BoxResult) -> bytes:
    return _RESPONSE_HEADER.pack(
        RESPONSE_MAGIC, result.rc, len(result.out), len(result.err)
    ) + result.out + result.err


def decode_response(data: bytes) -> BoxResult:
    if len(data) < _RESPONSE_HEADER.size:
        raise BoxFault("no frame on the box's stdout (too short to be a response frame)")
    magic, rc, n_out, n_err = _RESPONSE_HEADER.unpack(data[:_RESPONSE_HEADER.size])
    if magic != RESPONSE_MAGIC:
        raise BoxFault("no frame on the box's stdout (wrong magic)")
    body = data[_RESPONSE_HEADER.size:]
    if n_out + n_err != len(body):
        raise BoxFault("the box's response frame is truncated or overstates a length")
    return BoxResult(rc=rc, out=body[:n_out], err=body[n_out:])
