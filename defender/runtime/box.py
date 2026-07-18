"""The per-run box: the bash lane's execution boundary (#540).

Model-written bash is the only untrusted code execution left in the system (#611 moved
data sources onto the in-process typed `query` tool), so confining that one lane IS the
containment story. The gate (`permission/bash.py`) turns a model-written string into an
approved token structure; this module confines what that structure can reach. Both, in
that order — the gate alone is a matcher, and a matcher is what this issue exists to stop
relying on.

Three surfaces live here:

* **the wire** — `encode_request`/`decode_request`/`encode_response`, a length-prefixed
  binary framing carrying RAW BYTES in both directions. Not JSON: it cannot carry
  arbitrary bytes without base64, and O7 promises byte-exact-or-fail. Not any
  object-graph serializer that reconstructs types on load: the decode happens on the
  TRUSTED side of the boundary, reading bytes an untrusted process wrote, so the decoder
  must be able to do nothing but build `Pipeline`s. The fault signal is the FRAME'S
  ABSENCE — any unframed stdout is by definition daemon text, never program output.
* **the lifecycle** — `start_box`/`stop_box`/`container_name`, which create, probe and
  tear down the container. Fail closed at start; a mid-run failure is a tool error.
* **the scrub** — `scrub`, the reap-time link-shape check over the frozen run dir.

`scrub` certifies LINK SHAPE ONLY. Nothing here constrains the CONTENT a boxed process
writes into `run_dir` — content provenance is a follow-up (see the #540 spec graph's
`w_scrub_certifies_link_shape_only`).
"""

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

# ─────────────────────────────────────────────────────────────────────────────
# Faults
# ─────────────────────────────────────────────────────────────────────────────


class BoxFault(Exception):
    """An INFRASTRUCTURE failure of the box — the daemon, the container, or the wire.

    Deliberately not a `BoxResult` and not carrying one: a fault is the absence of a
    program result, so there is no exit code to confuse it with. A program that ran and
    failed returns a `BoxResult` with its own non-zero `rc` instead."""


class RunTainted(Exception):
    """The reap-time scrub found a link shape that breaks the run dir's containment.

    Raised, never swallowed: it must reach `run.py main()` uncaught so no downstream
    consumer walks the tainted tree. The message names the offending entry."""


# ─────────────────────────────────────────────────────────────────────────────
# Values crossing the seams
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BoxResult:
    """A program's own result: its exit code and its raw output streams.

    `out`/`err` stay `bytes` all the way to the formatting call site. Decoding here would
    make the boundary lossy in exactly the direction O7 forbids — a program that emits
    non-UTF-8 must reach the model as what it emitted or not at all."""

    rc: int
    out: bytes
    err: bytes


@dataclass(frozen=True)
class RawExec:
    """One transport round-trip, before any framing is interpreted.

    `stdout` is a candidate frame, not a result: `BoxExecutor` decides whether it IS one."""

    rc: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class BoxSpec:
    """The box's three replaceables, plus the tmpfs cap — one dataclass, one env lever.

    `runtime` defaults to gVisor and is the ONLY field an operator can move from outside,
    via `ENV_VAR`. `rootfs` and `lifecycle` are anchored here rather than in the
    environment on purpose: a box whose image or lifetime an ambient variable can retarget
    is not a boundary. The runc floor is a supported alternative — the mounts and
    `--network=none` deliver the boundary there too — so the knob downgrades the
    defence-in-depth tier without opening the boundary itself."""

    runtime: str = "runsc"
    rootfs: str = "python:3.11-slim"
    lifecycle: str = "per_run"
    tmpfs_size: str = "64m"

    ENV_VAR: ClassVar[str] = "DEFENDER_BOX_RUNTIME"
    RUNTIMES: ClassVar[tuple[str, ...]] = ("runsc", "runc")

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> BoxSpec:
        """Build a spec from `environ`, reading `ENV_VAR` and nothing else.

        Every other name is INERT by construction, including plausible-looking ones
        (`DEFENDER_BOX_ROOTFS`, `DEFENDER_SANDBOX`): an operator cannot retarget the image
        or disable the box by guessing a variable name. An unrecognised runtime is a loud
        `ValueError` rather than a silent fall-through to the default — a typo that
        quietly downgraded the tier would be indistinguishable from a working knob."""
        raw = environ.get(cls.ENV_VAR)
        if not raw:
            return cls()
        if raw not in cls.RUNTIMES:
            raise ValueError(
                f"{cls.ENV_VAR}={raw!r} is not a known box runtime "
                f"(expected one of {', '.join(cls.RUNTIMES)})"
            )
        return cls(runtime=raw)


# ─────────────────────────────────────────────────────────────────────────────
# The wire
# ─────────────────────────────────────────────────────────────────────────────

REQUEST_MAGIC = b"DFB1"
RESPONSE_MAGIC = b"DFR1"

_RESPONSE_HEADER = struct.Struct("!4siQQ")   # magic, rc, len(out), len(err) — 24 bytes
_U32 = struct.Struct("!I")
_U8 = struct.Struct("!B")

# Closed vocabularies, encoded as INDICES rather than text. A corrupted index is out of
# range and raises; a corrupted connector *string* could decode to a different valid
# connector, which would silently turn `a && b` into `a || b` on the trusted side.
_CONNECTORS: tuple[str, ...] = ("first", "&&", "||", ";")
_STDERR_MODES: tuple[str, ...] = ("capture", "devnull", "stdout")


def _encode_text(value: str) -> bytes:
    """One length-prefixed UTF-8 string, with the two rejections O7/NO15 demand.

    An embedded NUL and a non-UTF-8 (lone surrogate) argument are both refused HERE, at
    the encoder, with `ValueError` — not `BoxFault`, because nothing has failed yet and
    nothing has crossed. Byte-exact or fail: silently transcoding a hostile argument would
    hand the box a DIFFERENT command from the one the gate approved."""
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
    """Frame the gate-approved pipelines for the box.

    Carries STRUCTURE ONLY — no command string. The box therefore has nothing to re-parse:
    the token decomposition the gate validated is the one that executes, so `$(…)`, globs
    and `$VAR` cannot come back to life on the far side. That is the whole point of
    `shell=False` surviving the move into a container."""
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
    """A strictly bounded cursor over a request frame.

    Every read is bounds-checked and every decode is strict, so a corrupted frame RAISES
    rather than yielding a different-but-valid command. Combined with the exact-consumption
    check in `decode_request`, that is what makes a single flipped byte unable to become a
    different program."""

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
    """Rebuild the pipelines from a request frame, or raise.

    Runs INSIDE the box, on bytes the host wrote — but it is written as if the writer were
    hostile anyway, because the same decoder shape is what keeps the response side honest
    and because a decoder that trusts its input is a decoder nobody can reason about. It
    constructs `Pipeline`/`Stage` and nothing else: there is no type name on the wire, so
    no input can select what gets built."""
    if not frame.startswith(REQUEST_MAGIC):
        raise ValueError("not a box request frame")
    r = _Reader(frame[len(REQUEST_MAGIC):])
    pipelines: list[bash_exec.Pipeline] = []
    for _ in range(r.u32()):
        connector = r.index(_CONNECTORS)
        stages: list[bash_exec.Stage] = []
        for _ in range(r.u32()):
            # Read in the encoder's order — mode, count, argv — one stage at a time.
            mode = r.index(_STDERR_MODES)
            argv = [r.text() for _ in range(r.u32())]
            stages.append(bash_exec.Stage(argv=argv, stderr=mode))
        pipelines.append(bash_exec.Pipeline(connector=connector, stages=stages))
    if not r.done():
        raise ValueError("box request frame has trailing bytes")
    return pipelines


def encode_response(result: BoxResult) -> bytes:
    """Frame a program's result for the trip back out of the box."""
    return _RESPONSE_HEADER.pack(
        RESPONSE_MAGIC, result.rc, len(result.out), len(result.err)
    ) + result.out + result.err


def decode_response(data: bytes) -> BoxResult:
    """Rebuild a `BoxResult` from a response frame, or raise `BoxFault`.

    Strictly LENGTH-DRIVEN: the decoder never scans for `RESPONSE_MAGIC`, because a
    program's own output may legitimately contain those bytes and a scanning decoder would
    resynchronise onto the payload. The lengths must account for every byte present."""
    if len(data) < _RESPONSE_HEADER.size:
        raise BoxFault("no frame on the box's stdout (too short to be a response frame)")
    magic, rc, n_out, n_err = _RESPONSE_HEADER.unpack(data[:_RESPONSE_HEADER.size])
    if magic != RESPONSE_MAGIC:
        raise BoxFault("no frame on the box's stdout (wrong magic)")
    body = data[_RESPONSE_HEADER.size:]
    if n_out + n_err != len(body):
        raise BoxFault("the box's response frame is truncated or overstates a length")
    return BoxResult(rc=rc, out=body[:n_out], err=body[n_out:])


# ─────────────────────────────────────────────────────────────────────────────
# The executor
# ─────────────────────────────────────────────────────────────────────────────


class Transport(Protocol):
    """How a framed request reaches a box and a framed response comes back.

    Deliberately has NO `env` parameter: the box's environment is a positive allowlist the
    container carries (`BOX_ENV_ALLOWLIST`), not something a per-call caller can extend.
    That is what keeps a host secret from riding into the box on an exec."""

    # `frame` is POSITIONAL-ONLY: the transport is chosen by shape, not by parameter name, so
    # an implementation is free to name it whatever reads well at its own call site.
    def __call__(self, frame: bytes, /, *, cwd: Path, timeout: float) -> RawExec: ...


def _unattached(_frame: bytes, *, cwd: Path, timeout: float) -> RawExec:  # noqa: ARG001
    """The default transport: refuses, loudly.

    An executor built by `bind` before any container exists is INERT rather than
    host-executing — binding a role must never be the thing that silently opens an
    unboxed lane. `start_box` is the only place a live transport is attached."""
    raise BoxFault(
        "this box has no container attached — the run was never started through start_box"
    )


@dataclass
class BoxExecutor:
    """The bash lane's execution seam: gate-approved pipelines in, `BoxResult` out.

    Deliberately NOT a tuple: a tuple return invites positional unpacking, and the whole
    contract here is that an infrastructure fault has no result to unpack."""

    spec: BoxSpec = field(default_factory=BoxSpec)
    transport: Transport = _unattached
    name: str = ""
    sandboxed: bool = True

    def run_parsed(
        self, pipelines: Sequence[bash_exec.Pipeline], *,
        command: str, cwd: Path, timeout: float,
    ) -> BoxResult:
        """Execute the pipelines the gate approved, inside the box.

        `command` is carried for diagnostics only and never crosses the wire — the box gets
        structure, never a string to re-interpret.

        An EMPTY pipeline list still crosses. Short-circuiting it here would make the empty
        program the one command that never enters the box, which is exactly the kind of
        special case a boundary cannot afford."""
        frame = encode_request(pipelines)   # ValueError here — nothing has crossed yet
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
            # The frame's ABSENCE is the fault signal, so the daemon's own stderr is the
            # only diagnostic there is. It is carried onto the fault (and never the
            # would-be stdout, which by definition is not program output).
            raise BoxFault(f"{e}: {_text(raw.stderr).strip()}") from None

    # `run` is the same call; both names are in use at the seam.
    run = run_parsed


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


# ─────────────────────────────────────────────────────────────────────────────
# The lifecycle
# ─────────────────────────────────────────────────────────────────────────────

#: The box's environment, as a POSITIVE allowlist. A denylist of secret-looking names is
#: the fragile shape this issue exists to stop trusting: every host variable not named
#: here is ABSENT from the box, so a new credential in the host environment cannot leak by
#: not yet being on a list. `DEFENDER_RUNS_BASE` is present but names a path that is NOT
#: mounted — the box learns where the runs base is and still cannot reach it.
BOX_ENV_ALLOWLIST: tuple[str, ...] = (
    "DEFENDER_DIR",
    "DEFENDER_RUN_DIR",
    "DEFENDER_RUNS_BASE",
    "PATH",
    # `defender` is a PEP-420 NAMESPACE package with no __init__.py, so it resolves only when
    # the mount's PARENT is on sys.path. The entrypoint is reached as `python3 -m
    # defender.runtime.bash_exec`, and -m resolves against sys.path rather than the cwd, so
    # this must be set explicitly — relying on the working directory silently yields
    # `ModuleNotFoundError: No module named 'defender'` as an in-box error nobody can read.
    "PYTHONPATH",
    "LANG",
    "TZ",
)

#: The anchored default spec — one module-level singleton rather than a fresh `BoxSpec()`
#: per call site, so "what the box defaults to" is stated in exactly one place. Safe to
#: share because `BoxSpec` is frozen.
DEFAULT_SPEC = BoxSpec()

_ALLOW_UNSANDBOXED = "DEFENDER_ALLOW_UNSANDBOXED"
_BOX_PATH = "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
_NAME_PREFIX = "defender-run-"


def container_name(run_id: str) -> str:
    """The box's name, derived from the run id — the on-disk half of the box handle.

    Keying on the run id is what makes a crashed driver's box reapable from the run id
    alone. But `run_id` is `--run-id` or `{ts}-{alert.stem}`, and an alert filename is
    attacker-influenced: it can hold spaces, quotes and `--flags`. Docker's name grammar is
    `[a-zA-Z0-9][a-zA-Z0-9_.-]*`, so a hostile id is REFUSED here rather than sanitised —
    a silently rewritten name would let two runs collide on one box, and a name carrying a
    space would split into extra argv words in the create."""
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
    """The real docker seam. Every lifecycle call goes through the injected `docker=`
    parameter, so the tests drive scripted daemon replies rather than a live daemon."""
    return subprocess.run(
        argv, capture_output=True, text=True, check=False, timeout=120,
        encoding="utf-8",   # the daemon's own text, pinned — never the ambient locale
        errors="replace",   # a diagnostic must not raise while reporting a failure
    )


DockerFn = Callable[..., subprocess.CompletedProcess]


def _is_running(docker: DockerFn, name: str) -> bool:
    proc = docker(["docker", "inspect", "-f", "{{.State.Status}}", name])
    return proc.returncode == 0 and "running" in (proc.stdout or "")


def _create_argv(name: str, run_dir: Path, defender_dir: Path, spec: BoxSpec) -> list[str]:
    """The create command line — the mount list IS the boundary.

    Exactly two binds, both at their host absolute paths so a path means the same thing on
    both sides (which is what the startup sentinel then proves): `run_dir` read-write,
    `defender_dir` read-only. Everything else is ABSENT rather than denied — no matcher is
    consulted, so there is no matcher to get wrong. `--network=none` removes egress the
    same way. `/tmp` is a size-capped noexec tmpfs: writable scratch that cannot become a
    staging area for a downloaded binary."""
    env_pairs = {
        "DEFENDER_DIR": str(defender_dir),
        "DEFENDER_RUN_DIR": str(run_dir),
        "DEFENDER_RUNS_BASE": str(run_dir.parent),
        "PATH": _BOX_PATH,
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
        "--tmpfs", f"/tmp:rw,noexec,nosuid,size={spec.tmpfs_size}",
        "--workdir", str(run_dir),
    ]
    for key in BOX_ENV_ALLOWLIST:
        argv += ["--env", f"{key}={env_pairs[key]}"]
    argv += [spec.rootfs, "sleep", "infinity"]
    return argv


def _plant_sentinel(run_dir: Path, docker: DockerFn, name: str) -> None:
    """Prove the host and the box are looking at the SAME `run_dir`, or refuse the run.

    Under docker-outside-of-Docker an absent bind source is silently materialised as an
    EMPTY directory at rc=0, with no error at any stage — so nothing else distinguishes
    "the tree is mounted" from "the tree is gone", and a run would proceed writing into a
    void. Writing a known file on the host and reading it back through the box is the only
    check that catches that AS a failure. Empty and mismatched read-backs both refuse."""
    # A FIXED name carrying FRESH content. The token is what proves identity, so it is minted
    # per attempt; the name is stable so a retried start overwrites its predecessor instead of
    # littering the run dir with one sentinel per attempt.
    token = uuid.uuid4().hex
    sentinel = run_dir / ".box-sentinel"
    sentinel.write_text(token, encoding="utf-8")
    proc = docker(["docker", "exec", name, "cat", str(sentinel)])
    if proc.returncode != 0 or (proc.stdout or "").strip() != token:
        raise BoxFault(
            f"the box could not read back the startup sentinel at {sentinel} — the run dir "
            "is not the same tree inside the box as it is on the host"
        )
    sentinel.unlink(missing_ok=True)   # verified; it is not an artifact of the run


def _start_boxed(
    run_dir: Path, defender_dir: Path, spec: BoxSpec, docker: DockerFn,
) -> BoxExecutor:
    name = container_name(run_dir.name)   # BEFORE any docker call — a hostile id never
    #                                       reaches an argv, not even the pre-create reap.
    if _is_running(docker, name):
        raise BoxFault(
            f"a LIVE container named {name} already exists — refusing rather than reaping "
            "it, because that box belongs to another run still writing its artifacts"
        )
    # Pre-create reap: a STOPPED leftover of the same name collides at rc=125, so clearing
    # it is necessary rather than tidy. Its return code is deliberately ignored — "no such
    # container" is the ordinary case.
    docker(["docker", "rm", "-f", name])
    created = docker(_create_argv(name, run_dir, defender_dir, spec))
    if created.returncode != 0:
        raise BoxFault(
            f"could not create the box {name}: {(created.stderr or '').strip()}"
        )
    _plant_sentinel(run_dir, docker, name)
    return BoxExecutor(
        spec=spec, transport=_DockerTransport(name, spec), name=name, sandboxed=True,
    )


def start_box(
    run_dir: Path, defender_dir: Path, *,
    spec: BoxSpec = DEFAULT_SPEC, docker: DockerFn = _docker,
) -> BoxExecutor:
    """Create the run's box and prove it works, or refuse the run.

    The startup check is a PROBE, not a detection: it creates a container and reads a
    sentinel back through it. Asking whether a binary exists would answer a different
    question — a present `runsc` that cannot actually start a container would pass a
    detection and fail the first exec, mid-investigation, with the run already underway.

    Failing here refuses the run. The ONE way to proceed unboxed is the explicit
    `DEFENDER_ALLOW_UNSANDBOXED=1` operator opt-out, which is loud on stderr; every other
    spelling still refuses, so an ambient or mistyped variable cannot trip it."""
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
    return BoxExecutor(spec=spec, transport=_host_transport, name="", sandboxed=False)


def stop_box(box: BoxExecutor, *, docker: DockerFn = _docker) -> None:
    """Tear the box down. Idempotent, and keyed on the RETURN CODE alone.

    `docker rm -f <missing>` writes `Error response from daemon: No such container` to
    STDERR at rc=0 — the idempotent SUCCESS path writes to stderr, so a reaper that treats
    stderr as failure misfires on exactly the path it exists to make safe.

    Called from a `finally`, so it must also tolerate a box that was never created."""
    if not box.name:
        return
    proc = docker(["docker", "rm", "-f", box.name])
    if proc.returncode != 0:
        raise BoxFault(
            f"could not tear down the box {box.name}: {(proc.stderr or '').strip()}"
        )


@dataclass(frozen=True)
class _DockerTransport:
    """Carries a framed request into a live container and the response back out.

    `-w` re-applies the cwd on EVERY exec: a cwd does NOT persist across `docker exec`
    (only `/tmp` does), so relying on the create's `--workdir` would silently anchor the
    second command somewhere else. `-i` because the frame arrives on stdin — it never
    appears in an argv, where it would be visible in the host's process table."""

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


def _host_transport(frame: bytes, *, cwd: Path, timeout: float) -> RawExec:
    """The UNBOXED transport, reachable only through the loud operator opt-out above.

    It runs the approved pipelines in-process on the host — which is precisely what the box
    exists to prevent, and why it is unreachable without `DEFENDER_ALLOW_UNSANDBOXED=1`."""
    rc, out, err = bash_exec.run_parsed(
        decode_request(frame), command="", env=dict(os.environ), cwd=cwd, timeout=timeout,
    )
    return RawExec(rc=rc, stdout=encode_response(
        BoxResult(rc=rc, out=out.encode("utf-8", "replace"), err=err.encode("utf-8", "replace"))
    ), stderr=b"")


# ─────────────────────────────────────────────────────────────────────────────
# The reap-time scrub
# ─────────────────────────────────────────────────────────────────────────────

#: The only two file types a run dir may contain when the box is dead. An ALLOWLIST, not a
#: denylist of FIFO/socket/device: a type nobody enumerated is refused rather than passed.
_PERMITTED = (stat.S_ISREG, stat.S_ISDIR)


def _check_entry(entry: Path) -> None:
    """Certify one entry's LINK SHAPE. `lstat` only — the entry is never opened.

    Opening is not a neutral act here: a FIFO the box left behind would block the `open`
    forever and the run would never reach the end of the scrub, converting a containment
    check into a hang. `lstat` answers the only question being asked."""
    st = entry.lstat()
    if not any(pred(st.st_mode) for pred in _PERMITTED):
        raise RunTainted(
            f"{entry.name}: the run dir holds a {stat.filemode(st.st_mode)[0]!r}-type entry "
            f"({entry}) — only regular files and directories may survive a boxed run"
        )
    # nlink is meaningful for a REGULAR FILE only: a directory's link count is its
    # subdirectory count on most filesystems and is fs-dependent besides, so testing it
    # unguarded would flag every ordinary nested directory.
    if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        raise RunTainted(
            f"{entry.name}: {entry} is a hard link with {st.st_nlink} names — a within-bind "
            "hard link aliases another path in the run dir and survives the box's death"
        )


def scrub(run_dir: Path) -> None:
    """Certify the frozen run dir's link shape, or raise `RunTainted`.

    Runs at REAP time — after the box is torn down and before the first consumer reads the
    tree — so there is no live writer and no TOCTOU window to argue about. That ordering is
    the scrub's entire soundness argument; `run.py main()` pins it.

    A PURE READER. It removes nothing, rewrites nothing, and resolves no link: sanitising
    would destroy the evidence of what a compromised run did, and a scrub that quietly
    repairs is a scrub whose findings nobody can audit. Sixteen host consumers read this
    tree with symlink-unsafe primitives, so the answer must be refuse-the-tree, not
    fix-the-tree.

    Certifies LINK SHAPE ONLY. A clean scrub licenses no assumption about the CONTENT the
    box wrote — a boxed process can still forge artifacts inside the run dir."""
    for parent, dirs, files in os.walk(run_dir):   # followlinks=False by default
        # `dirs` matters as much as `files`: a symlink to a DIRECTORY lands there, not in
        # `files`, so walking files alone would miss the case that reaches furthest.
        for name in (*dirs, *files):
            _check_entry(Path(parent) / name)
