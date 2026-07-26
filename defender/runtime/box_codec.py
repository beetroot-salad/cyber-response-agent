
from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass

from defender.runtime import bash_exec


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
