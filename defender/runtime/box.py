
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

from defender._run_id import RUN_ID_ALLOWED, is_valid_run_id
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




@dataclass(frozen=True)
class Mount:

    source: Path
    target: Path
    writable: bool = False


@dataclass(frozen=True)
class BoxRequest:

    name: str
    mounts: tuple[Mount, ...] = ()
    workdir: Path = Path(".")
    env: dict[str, str] = field(default_factory=dict)
    spec: BoxSpec = field(default_factory=BoxSpec)


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

    @property
    def sandboxed(self) -> bool:
        # Derived from the transport (M5/O5), never independently settable: only a
        # transport that actually confines a process may claim the boundary.
        return isinstance(self.transport, _DockerTransport)

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

# The encoding/clock contract every tier's box renders (#589): a `C` locale inside the box
# would decode a granted program's UTF-8 output differently than the host does.
_LOCALE_ENV: dict[str, str] = {"LANG": "C.UTF-8", "TZ": "UTC"}


def container_name(run_id: str) -> str:
    if not is_valid_run_id(run_id):
        raise ValueError(
            f"run id {run_id!r} cannot name a container (allowed: {RUN_ID_ALLOWED})"
        )
    return f"{_NAME_PREFIX}{run_id}"


def infra_env(defender_dir: Path, run_dir: Path) -> dict[str, str]:
    """The infra env every tier's box needs (M2): the shims + package location. One shared
    helper — a caller composing a BoxRequest merges this in (or box.py's own request render
    derives the same shape off the request's workdir, §_render_env)."""
    return {
        "DEFENDER_DIR": str(defender_dir),
        "DEFENDER_RUN_DIR": str(run_dir),
        "DEFENDER_RUNS_BASE": str(run_dir.parent),
        "PATH": f"{defender_dir / 'bin'}:{_BOX_PATH}",
        "PYTHONPATH": str(defender_dir.parent),
    }


def _derived_infra_env(workdir: Path) -> dict[str, str]:
    """The three INFRA keys box.py derives off the request's own workdir — the convention
    every box-carrying role anchors at `defender_dir.parent`. These always win (R11)."""
    defender_dir = Path(workdir) / "defender"
    return {
        "DEFENDER_DIR": str(defender_dir),
        "PATH": f"{defender_dir / 'bin'}:{_BOX_PATH}",
        "PYTHONPATH": str(workdir),
    }


def _render_env(request_env: Mapping[str, str], workdir: Path) -> dict[str, str]:
    """S8: a positive allowlist by key. R11: on a collision with an INFRA key
    (DEFENDER_DIR/PATH/PYTHONPATH, derived off the request's workdir — the convention every
    box-carrying role anchors at `defender_dir.parent`) the derived value wins; any other
    allowlisted key the caller supplies passes through unexamined (value-blind, RF-G).
    `LANG`/`TZ` keep the encoding/clock contract the two-arg `_create_argv` tier has always
    rendered (#589) — supplied as DEFAULTS, so a caller that names them still wins."""
    merged = dict(_LOCALE_ENV)
    merged.update({k: v for k, v in request_env.items() if k in BOX_ENV_ALLOWLIST})
    merged.update(_derived_infra_env(workdir))
    return merged


def _docker(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, capture_output=True, text=True, check=False, timeout=120,
        encoding="utf-8",
        errors="replace",
    )


DockerFn = Callable[..., subprocess.CompletedProcess]


def _call(docker: DockerFn, argv: list[str]) -> subprocess.CompletedProcess:
    try:
        return docker(argv)
    except (OSError, subprocess.SubprocessError) as e:
        # SubprocessError covers `_docker`'s own `timeout=120` (TimeoutExpired), which is NOT
        # an OSError — an unclassified TimeoutExpired would escape both the loud
        # DEFENDER_ALLOW_UNSANDBOXED fallback and orchestrate's _SYSTEMIC_FAULTS classification.
        raise BoxFault(f"could not invoke docker ({argv[:2]}): {e}") from e


def _is_running(docker: DockerFn, name: str) -> bool:
    proc = _call(docker, ["docker", "inspect", "-f", "{{.State.Status}}", name])
    return proc.returncode == 0 and "running" in (proc.stdout or "")


def _create_argv(name: str, run_dir: Path, defender_dir: Path, spec: BoxSpec) -> list[str]:
    env_pairs = {**infra_env(defender_dir, run_dir), **_LOCALE_ENV}
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


def _plant(sentinel: Path, token: str) -> None:
    """Host-side half of a sentinel probe. An unwritable/absent SOURCE is a box-startup fault
    like any other (BoxFault), not a bare OSError that would escape start_box's classification
    and the loud DEFENDER_ALLOW_UNSANDBOXED fallback."""
    try:
        sentinel.write_text(token, encoding="utf-8")
    except OSError as e:
        raise BoxFault(
            f"could not plant the startup sentinel at {sentinel} — the bind source is not "
            f"writable by this process: {e}"
        ) from e


def _probe_sentinel(
    source: Path, target: Path, docker: DockerFn, name: str, sentinel_name: str,
    *, unlink_on_fault: bool,
) -> None:
    token = uuid.uuid4().hex
    sentinel = source / sentinel_name
    _plant(sentinel, token)
    try:
        proc = _call(docker, ["docker", "exec", name, "cat", str(target / sentinel_name)])
        if proc.returncode != 0 or (proc.stdout or "").strip() != token:
            raise BoxFault(
                f"the box could not read back the startup sentinel at {sentinel} — the tree "
                "inside the box does not match the host"
            )
    except BaseException:
        # The run-dir tier deliberately LEAVES its sentinel behind on a fault (pinned by
        # test_540_scrub_lifecycle: the residue is the evidence the probe really wrote); the
        # per-mount tier cleans up, because its sources include the live repo/worktree trees.
        if unlink_on_fault:
            sentinel.unlink(missing_ok=True)
        raise
    sentinel.unlink(missing_ok=True)


def _plant_sentinel(run_dir: Path, docker: DockerFn, name: str) -> None:
    _probe_sentinel(run_dir, run_dir, docker, name, ".box-sentinel", unlink_on_fault=False)


def _check_mount_sentinel(mount: Mount, docker: DockerFn, name: str) -> None:
    """M11 — every mount is individually probed at start, not only the original single rw
    run_dir: a host-planted token, read back through the box, proves the tree inside the
    container is the tree on the host (an absent bind SOURCE is caught earlier, at create —
    DC1; this catches a bind that SUCCEEDED but mapped the wrong/empty tree)."""
    _probe_sentinel(
        Path(mount.source), Path(mount.target), docker, name,
        f".box-sentinel-{uuid.uuid4().hex}", unlink_on_fault=True,
    )


def _start_boxed(
    run_dir: Path, defender_dir: Path, spec: BoxSpec, docker: DockerFn,
) -> BoxExecutor:
    name = container_name(run_dir.name)
    if _is_running(docker, name):
        raise BoxFault(
            f"a LIVE container named {name} already exists — refusing rather than reaping "
            "it, because that box belongs to another run still writing its artifacts"
        )
    _call(docker, ["docker", "rm", "-f", name])
    created = _call(docker, _create_argv(name, run_dir, defender_dir, spec))
    if created.returncode != 0:
        raise BoxFault(
            f"could not create the box {name}: {(created.stderr or '').strip()}"
        )
    try:
        _plant_sentinel(run_dir, docker, name)
    except BaseException:
        _call(docker, ["docker", "rm", "-f", name])
        raise
    return BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name)


def _render_argv(request: BoxRequest) -> list[str]:
    argv = [
        "docker", "run", "--detach", "--name", request.name,
        "--runtime", request.spec.runtime,
        "--network", "none",
        "--read-only",
    ]
    for m in request.mounts:
        spec_str = f"type=bind,source={m.source},target={m.target}"
        if not m.writable:
            spec_str += ",readonly"
        argv += ["--mount", spec_str]
    argv += [
        "--tmpfs", f"/tmp:rw,noexec,nosuid,mode=1777,size={request.spec.tmpfs_size}",
        "--workdir", str(request.workdir),
    ]
    env = _render_env(request.env, Path(request.workdir))
    for key in sorted(env):
        argv += ["--env", f"{key}={env[key]}"]
    argv += [request.spec.rootfs, "sleep", "infinity"]
    return argv


def _start_boxed_request(request: BoxRequest, docker: DockerFn) -> BoxExecutor:
    if not is_valid_run_id(request.name):
        raise BoxFault(
            f"composed container name {request.name!r} fails the run-id grammar "
            f"(allowed: {RUN_ID_ALLOWED})"
        )
    if _is_running(docker, request.name):
        raise BoxFault(
            f"a LIVE container named {request.name} already exists — refusing rather than "
            "reaping it, because that box belongs to another batch still writing its artifacts"
        )
    _call(docker, ["docker", "rm", "-f", request.name])
    created = _call(docker, _render_argv(request))
    if created.returncode != 0:
        raise BoxFault(
            f"could not create the box {request.name}: {(created.stderr or '').strip()}"
        )
    try:
        for m in request.mounts:
            _check_mount_sentinel(m, docker, request.name)
    except BaseException:
        _call(docker, ["docker", "rm", "-f", request.name])
        raise
    return BoxExecutor(
        spec=request.spec, transport=_DockerTransport(request.name, request.spec),
        name=request.name,
    )


def _opt_out_or_raise(fault: BoxFault) -> None:
    """M9: the ONE loud host lane. Without the env var a startup fault aborts; with it, the
    caller degrades to `unboxed_executor` after a greppable warning."""
    if os.environ.get(_ALLOW_UNSANDBOXED) != "1":
        raise fault
    print(
        f"[box] WARNING: {_ALLOW_UNSANDBOXED}=1 — running UNSANDBOXED. The bash lane "
        "executes on the host with no filesystem or network boundary.",
        file=sys.stderr,
    )


def _host_fallback_env(request: BoxRequest) -> dict[str, str]:
    """R8: the unboxed opt-out is a bare HOST subprocess, so it inherits the host env (minus
    provider keys) exactly as `run_common.run_env` does for the two-arg tier — NOT the box's
    key-allowlisted, container-shaped `_render_env` (which carries no HOME and a `_BOX_PATH`
    that does not exist on the host)."""
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    env.update({k: v for k, v in request.env.items() if k in BOX_ENV_ALLOWLIST})
    defender_dir = Path(request.workdir) / "defender"
    env["DEFENDER_DIR"] = str(defender_dir)
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    # PREPENDED like PATH above, not assigned: a bare host subprocess keeps whatever
    # PYTHONPATH the operator's shell set (the whole point of "inherits the host env").
    inherited = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        f"{request.workdir}{os.pathsep}{inherited}" if inherited else str(request.workdir)
    )
    return env


def start_box(
    run_dir_or_request: Path | BoxRequest, defender_dir: Path | None = None, *,
    spec: BoxSpec = DEFAULT_SPEC, docker: DockerFn = _docker,
) -> BoxExecutor:
    if isinstance(run_dir_or_request, BoxRequest):
        request = run_dir_or_request
        # Compared by VALUE, not identity: BoxSpec is a frozen value object and
        # `BoxSpec.from_env({})` legitimately returns a fresh-but-equal default, which an
        # `is not` check would reject as "ambiguous" even though it names nothing.
        if spec != DEFAULT_SPEC:
            raise TypeError(
                "start_box(request, spec=…) is ambiguous — a BoxRequest carries its own spec; "
                "set it on the request (BoxRequest(..., spec=…)) instead of the call"
            )
        if defender_dir is not None:
            raise TypeError(
                "start_box(request, defender_dir) is ambiguous — a BoxRequest carries its own "
                "geography; put the tree in its mounts/workdir instead of the call"
            )
        try:
            return _start_boxed_request(request, docker)
        except BoxFault as e:
            _opt_out_or_raise(e)
        return unboxed_executor(request.spec, env=_host_fallback_env(request))

    run_dir = run_dir_or_request
    if defender_dir is None:
        raise TypeError("start_box(run_dir, defender_dir, ...) needs defender_dir")
    try:
        return _start_boxed(run_dir, defender_dir, spec, docker)
    except BoxFault as e:
        _opt_out_or_raise(e)
    from defender import run_common
    return unboxed_executor(spec, env=run_common.run_env(defender_dir, run_dir))


def stop_box(box: BoxExecutor, *, docker: DockerFn = _docker) -> None:
    if not box.name:
        return
    proc = _call(docker, ["docker", "rm", "-f", box.name])
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
        name="",
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
