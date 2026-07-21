
from __future__ import annotations

import os
import stat
import struct
import subprocess
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Protocol

from defender.runtime import bash_exec



class BoxFault(Exception):
    pass


class RunTainted(Exception):
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


@dataclass(frozen=True)
class BoxSpec:

    runtime: str = "runsc"
    rootfs: str = "python:3.11-slim"
    lifecycle: str = "per_run"
    tmpfs_size: str = "64m"

    ENV_VAR: ClassVar[str] = "DEFENDER_BOX_RUNTIME"
    RUNTIMES: ClassVar[tuple[str, ...]] = ("runsc", "runc")

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> BoxSpec:
        raw = environ.get(cls.ENV_VAR)
        if not raw:
            return cls()
        if raw not in cls.RUNTIMES:
            raise ValueError(
                f"{cls.ENV_VAR}={raw!r} is not a known box runtime "
                f"(expected one of {', '.join(cls.RUNTIMES)})"
            )
        return cls(runtime=raw)



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




class Transport(Protocol):

    def __call__(self, frame: bytes, /, *, cwd: Path, timeout: float) -> RawExec: ...


def _unattached(_frame: bytes, *, cwd: Path, timeout: float) -> RawExec:  # noqa: ARG001
    raise BoxFault(
        "this box has no container attached — the run was never started through start_box"
    )


@dataclass
class BoxExecutor:

    spec: BoxSpec = field(default_factory=BoxSpec)
    transport: Transport = _unattached
    name: str = ""
    sandboxed: bool = True

    def run_parsed(
        self, pipelines: Sequence[bash_exec.Pipeline], *,
        command: str, cwd: Path, timeout: float,
    ) -> BoxResult:
        frame = encode_request(pipelines)
        try:
            raw = self.transport(frame, cwd=cwd, timeout=timeout)
        except BoxFault:
            raise
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            raise BoxFault(f"the box was unreachable while running {command!r}: {e}") from e
        try:
            return decode_response(raw.stdout)
        except BoxFault as e:
            raise BoxFault(f"{e}: {_text(raw.stderr).strip()}") from None

    run = run_parsed


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")



BOX_ENV_ALLOWLIST: tuple[str, ...] = (
    "DEFENDER_DIR",
    "DEFENDER_RUN_DIR",
    "DEFENDER_RUNS_BASE",
    "PATH",
    "PYTHONPATH",
    "LANG",
    "TZ",
)

DEFAULT_SPEC = BoxSpec()

_ALLOW_UNSANDBOXED = "DEFENDER_ALLOW_UNSANDBOXED"
_BOX_PATH = "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
_NAME_PREFIX = "defender-run-"


def container_name(run_id: str) -> str:
    ok = (
        bool(run_id)
        and run_id.isascii()
        and run_id[0].isalnum()
        and all(c.isalnum() or c in "_.-" for c in run_id)
    )
    if not ok:
        raise ValueError(
            f"run id {run_id!r} cannot name a container (allowed: ASCII alphanumerics, "
            "'_', '.', '-', starting alphanumeric)"
        )
    return f"{_NAME_PREFIX}{run_id}"


def _docker(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, capture_output=True, text=True, check=False, timeout=120,
        encoding="utf-8",
        errors="replace",
    )


DockerFn = Callable[..., subprocess.CompletedProcess]


def _is_running(docker: DockerFn, name: str) -> bool:
    proc = docker(["docker", "inspect", "-f", "{{.State.Status}}", name])
    return proc.returncode == 0 and "running" in (proc.stdout or "")


def _create_argv(name: str, run_dir: Path, defender_dir: Path, spec: BoxSpec) -> list[str]:
    env_pairs = {
        "DEFENDER_DIR": str(defender_dir),
        "DEFENDER_RUN_DIR": str(run_dir),
        "DEFENDER_RUNS_BASE": str(run_dir.parent),
        "PATH": f"{defender_dir / 'bin'}:{_BOX_PATH}",
        "PYTHONPATH": str(defender_dir.parent),
        "LANG": "C.UTF-8",
        "TZ": "UTC",
    }
    argv = [
        "docker", "run", "--detach", "--name", name,
        "--runtime", spec.runtime,
        "--network", "none",
        "--read-only",
        "--mount", f"type=bind,source={run_dir},target={run_dir}",
        "--mount", f"type=bind,source={defender_dir},target={defender_dir},readonly",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,mode=1777,size={spec.tmpfs_size}",
        "--workdir", str(run_dir),
    ]
    for key in BOX_ENV_ALLOWLIST:
        argv += ["--env", f"{key}={env_pairs[key]}"]
    argv += [spec.rootfs, "sleep", "infinity"]
    return argv


def _plant_sentinel(run_dir: Path, docker: DockerFn, name: str) -> None:
    token = uuid.uuid4().hex
    sentinel = run_dir / ".box-sentinel"
    sentinel.write_text(token, encoding="utf-8")
    proc = docker(["docker", "exec", name, "cat", str(sentinel)])
    if proc.returncode != 0 or (proc.stdout or "").strip() != token:
        raise BoxFault(
            f"the box could not read back the startup sentinel at {sentinel} — the run dir "
            "is not the same tree inside the box as it is on the host"
        )
    sentinel.unlink(missing_ok=True)


def _start_boxed(
    run_dir: Path, defender_dir: Path, spec: BoxSpec, docker: DockerFn,
) -> BoxExecutor:
    name = container_name(run_dir.name)
    if _is_running(docker, name):
        raise BoxFault(
            f"a LIVE container named {name} already exists — refusing rather than reaping "
            "it, because that box belongs to another run still writing its artifacts"
        )
    docker(["docker", "rm", "-f", name])
    created = docker(_create_argv(name, run_dir, defender_dir, spec))
    if created.returncode != 0:
        raise BoxFault(
            f"could not create the box {name}: {(created.stderr or '').strip()}"
        )
    try:
        _plant_sentinel(run_dir, docker, name)
    except BaseException:
        docker(["docker", "rm", "-f", name])
        raise
    return BoxExecutor(
        spec=spec, transport=_DockerTransport(name, spec), name=name, sandboxed=True,
    )


def start_box(
    run_dir: Path, defender_dir: Path, *,
    spec: BoxSpec = DEFAULT_SPEC, docker: DockerFn = _docker,
) -> BoxExecutor:
    try:
        return _start_boxed(run_dir, defender_dir, spec, docker)
    except BoxFault:
        if os.environ.get(_ALLOW_UNSANDBOXED) != "1":
            raise
    print(
        f"[box] WARNING: {_ALLOW_UNSANDBOXED}=1 — running UNSANDBOXED. The bash lane "
        "executes on the host with no filesystem or network boundary.",
        file=sys.stderr,
    )
    from defender import run_common
    return unboxed_executor(spec, env=run_common.run_env(defender_dir, run_dir))


def stop_box(box: BoxExecutor, *, docker: DockerFn = _docker) -> None:
    if not box.name:
        return
    proc = docker(["docker", "rm", "-f", box.name])
    if proc.returncode != 0:
        raise BoxFault(
            f"could not tear down the box {box.name}: {(proc.stderr or '').strip()}"
        )


@dataclass(frozen=True)
class _DockerTransport:

    name: str
    spec: BoxSpec

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> RawExec:
        proc = subprocess.run(  # noqa: S603
            [
                "docker", "exec", "-i", "-w", str(cwd), self.name,
                "python3", "-m", "defender.runtime.bash_exec",
            ],
            input=frame, capture_output=True, check=False, timeout=timeout,
        )
        return RawExec(rc=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


@dataclass(frozen=True)
class _HostTransport:

    env: dict[str, str]

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> RawExec:
        rc, out, err = bash_exec.run_parsed(
            decode_request(frame), command="", env=self.env, cwd=cwd, timeout=timeout,
        )
        return RawExec(rc=rc, stdout=encode_response(BoxResult(
            rc=rc,
            out=out.encode("utf-8", "replace"),
            err=err.encode("utf-8", "replace"),
        )), stderr=b"")


def unboxed_executor(
    spec: BoxSpec = DEFAULT_SPEC, *, env: Mapping[str, str] | None = None,
) -> BoxExecutor:
    return BoxExecutor(
        spec=spec,
        transport=_HostTransport(dict(env) if env is not None else dict(os.environ)),
        name="", sandboxed=False,
    )





_PERMITTED = (stat.S_ISREG, stat.S_ISDIR)


def _check_entry(entry: Path) -> None:
    st = entry.lstat()
    if not any(pred(st.st_mode) for pred in _PERMITTED):
        raise RunTainted(
            f"{entry.name}: the run dir holds a {stat.filemode(st.st_mode)[0]!r}-type entry "
            f"({entry}) — only regular files and directories may survive a boxed run"
        )
    if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        raise RunTainted(
            f"{entry.name}: {entry} is a hard link with {st.st_nlink} names — a within-bind "
            "hard link aliases another path in the run dir and survives the box's death"
        )


def scrub(run_dir: Path) -> None:
    for parent, dirs, files in os.walk(run_dir):
        for name in (*dirs, *files):
            _check_entry(Path(parent) / name)
