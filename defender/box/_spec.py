"""What a box IS: the request, the mounts, the executor, and the transports that carry a
command to one.

The two transports live here rather than with the lifecycle because `BoxExecutor`
discriminates on the docker one, and the protocol they implement is declared here.
"""
from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Literal, Protocol, runtime_checkable

from defender._model import model
from defender.execution import bash_exec
from defender.execution.box_codec import (
    REQUEST_MAGIC,  # noqa: F401 — re-exported: test_540_exec_seam.py imports it as `box.REQUEST_MAGIC`
    RESPONSE_MAGIC,  # noqa: F401 — re-exported: test_540_exec_seam.py imports it as `box.RESPONSE_MAGIC`
    BoxFault,
    BoxResult,
    RawExec,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)
from ._clock import write_clock
from ._output import BoxOutputLimitExceeded, capture_bounded
from defender.runtime.model_view import ModelView
from defender.box._scrub import (  # noqa: F401 — re-exported: run.py/drains.py/tests import `box.scrub`, `box.RunTainted`
    Finding,
    RunTainted,
    scrub,
    verdict_path,
    write_did_not_run,
)


# This module is host-only (it pulls in pydantic); nothing inside a box imports it. An unset
# `rootfs` is resolved to `_image.image_tag(tree)` by each `docker run` argv builder, so
# constructing a `BoxSpec` reads nothing off the tree.
@model(frozen=True)
class BoxSpec:

    runtime: str = "runsc"
    rootfs: str | None = None
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




#: The file a `code` mount is checked by at box start (#1108 D7): read back through the box from
#: `<code_dir>/MOUNT_CHECK` and compared with the host's own read. A committed, content-free file
#: the box package owns by this one name; nothing the agent reads names it.
CODE_CHECK_FILE = "MOUNT_CHECK"

#: What a read-only mount holds, which decides how box start checks it (#1108 D7, amendment 2):
#: `code` reads back `CODE_CHECK_FILE` under the request's code root; `data` reads back its first
#: regular file (an empty folder passes, #665 Decision 9); `staged` is the root of a copy the host
#: made (a drain's draft, a run's knowledge), holding only `agent/` (and a run copy's
#: `settings/`), with a fresh token planted at its root and read back for each start. Never
#: inferred from a name or a path. The retired `agent` kind is refused like any other word.
MountKind = Literal["code", "data", "staged"]


@dataclass(frozen=True)
class Mount:

    source: Path
    target: Path
    writable: bool = False
    #: Required of a read-only mount, which box start refuses without one. A writable mount is
    #: checked by a planted sentinel and declares no kind; box start refuses one that does.
    kind: MountKind | None = None


def _code_dir(workdir: Path, explicit: Path | None) -> Path:
    """Resolve the request code root once, retaining legacy checkout geography."""
    return explicit if explicit is not None else workdir / "defender"


@dataclass(frozen=True)
class BoxRequest:

    name: str
    mounts: tuple[Mount, ...] = ()
    workdir: Path = Path(".")
    env: dict[str, str] = field(default_factory=dict)
    #: Explicit product code root; legacy requests derive it from their checkout workdir.
    defender_dir: Path | None = None
    #: Tenant knowledge must never run in the host fallback lane.
    require_sandbox: bool = False
    #: Host geography remains authoritative; only container-facing paths use this view.
    view: ModelView | None = None

    @property
    def model_workdir(self) -> Path:
        return Path(self.view.to_model(self.workdir)) if self.view is not None else self.workdir

    @property
    def model_code_dir(self) -> Path:
        return Path(self.view.to_model(self.code_dir)) if self.view is not None else self.code_dir

    @property
    def code_dir(self) -> Path:
        return _code_dir(self.workdir, self.defender_dir)

    # Resolved here so BoxRequest callers honour DEFENDER_BOX_RUNTIME too.
    spec: BoxSpec = field(default_factory=lambda: BoxSpec.from_env(os.environ))


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
    #: The docker callable this box was created with (#1195): every lifecycle call on it — its
    #: stops, starts and removal — goes through the same daemon. `None` for the unsandboxed
    #: fallback, which has no container.
    docker: Callable[..., subprocess.CompletedProcess] | None = field(
        default=None, compare=False, repr=False,
    )
    #: The run clock's file on the host (#1255 "Into the box"), bound read-only into the box,
    #: where the image's time-faking preload reads it. `None` for a box with no clock mount
    #: (the unsandboxed fallback, a learning-loop box).
    clock_file: Path | None = field(default=None, compare=False)
    #: The run clock's reader (`RunState.now`) once the run has bound it (`follow_clock`).
    _clock_reading: Callable[[], datetime] | None = field(
        default=None, compare=False, repr=False,
    )

    _output_refused: bool = field(default=False, compare=False, repr=False)

    def follow_clock(self, reading: Callable[[], datetime]) -> None:
        """Have the box's programs read the run's clock: before every command, the clock file is
        rewritten from `reading()` (the run clock moves against the wall — it pauses for an
        oracle turn, and an arm's runs ahead of or behind it). A box with no clock file has no
        preload to feed."""
        self._clock_reading = reading

    def _sync_clock(self) -> None:
        if self.clock_file is None or self._clock_reading is None:
            return
        try:
            write_clock(self.clock_file, self._clock_reading())
        except OSError as e:
            raise BoxFault(f"could not set the run clock for the box {self.name}: {e}") from e

    @property
    def sandboxed(self) -> bool:
        # Derived, never settable: only a confining transport may claim the boundary.
        return isinstance(self.transport, _DockerTransport)

    def run_parsed(
        self, pipelines: Sequence[bash_exec.Pipeline], *,
        command: str, cwd: Path, timeout: float,
    ) -> BoxResult:
        if self._output_refused:
            raise BoxOutputLimitExceeded()
        self._sync_clock()
        frame = encode_request(pipelines)
        try:
            raw = self.transport(frame, cwd=cwd, timeout=timeout)
        except BoxOutputLimitExceeded as overflow:
            self._output_refused = True
            # The lifecycle owns the daemon and proof that every box process has stopped.
            from ._lifecycle import BoxRuns

            try:
                BoxRuns(self).stop()
            except Exception as cleanup:
                overflow.add_note(f"could not confirm the box stopped: {cleanup}")
                raise overflow from cleanup
            raise
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


# `@runtime_checkable` because pydantic validates the strict `AgentDeps.box` field with
# `isinstance`. The contract is structural (`run_parsed` is all production calls), so test
# doubles need not be a `BoxExecutor`.
@runtime_checkable
class BoxLike(Protocol):

    def run_parsed(
        self, pipelines: Sequence[bash_exec.Pipeline], *,
        command: str, cwd: Path, timeout: float,
    ) -> BoxResult: ...


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")



DEFAULT_SPEC = BoxSpec()

#: The alias-ban seccomp profile (denies exactly `BANNED_SHAPES`), resolved once so every box
#: lane attaches the same value. It lives outside every box's writable mount, or a box could
#: unban the next one. The path is relative to this module; a package move breaks it silently
#: (the box would start with no alias ban).

ALIAS_PROFILE_PATH: Path = (
    Path(__file__).resolve().parent / "seccomp" / "alias-deny.json"
)

BANNED_SHAPES: tuple[str, ...] = ("symlink", "symlinkat", "link", "linkat", "mknod", "mknodat")

_OCI_SECCOMP_FLAG = "--oci-seccomp"
_RUNSC_INSTALL_CMD = "runsc install -- --oci-seccomp"


@dataclass(frozen=True)
class _DockerTransport:

    name: str
    spec: BoxSpec
    popen: Callable[..., subprocess.Popen[bytes]] = field(
        default=subprocess.Popen, compare=False, repr=False,
    )

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> RawExec:
        return capture_bounded(
            [
                "docker", "exec", "-i", "-w", str(cwd), self.name,
                "python3", "-m", "defender.execution.bash_exec",
            ],
            frame, timeout=timeout, popen=self.popen,
        )


@dataclass(frozen=True)
class _HostTransport:

    env: dict[str, str]
    view: ModelView | None = None

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> RawExec:
        pipelines = decode_request(frame)
        if self.view is not None:
            from defender.runtime.permission.grant import PROGRAMS, rm_target_files

            # The permission grammar owns which arguments are paths. A grep pattern or
            # Python string that resembles a workspace path must keep its literal bytes.
            translated = []
            for pipeline in pipelines:
                stages = []
                for stage in pipeline.stages:
                    extract = rm_target_files if stage.argv[0] == "rm" else PROGRAMS[stage.argv[0]]
                    operands = extract(stage.argv) or ()
                    argv = [
                        str(host) if word in operands and Path(word).is_absolute()
                        and (host := self.view.to_host(word)) is not None else word
                        for word in stage.argv
                    ]
                    stages.append(bash_exec.Stage(argv, stage.stderr))
                translated.append(bash_exec.Pipeline(pipeline.connector, stages))
            pipelines = translated
            host_cwd = self.view.to_host(str(cwd))
            if host_cwd is None:
                raise BoxFault(f"working directory is outside the workspace: {cwd}")
            cwd = host_cwd
        rc, out, err = bash_exec.run_parsed(
            pipelines, command="", env=self.env, cwd=cwd, timeout=timeout,
        )
        return RawExec(rc=rc, stdout=encode_response(BoxResult(
            rc=rc,
            out=out.encode("utf-8", "replace"),
            err=err.encode("utf-8", "replace"),
        )), stderr=b"")
