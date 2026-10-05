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
from pathlib import Path
from typing import ClassVar, Protocol, runtime_checkable

from defender._model import model
from defender.runtime import bash_exec
from defender.runtime.box_codec import (
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
from defender.runtime.scrub import (  # noqa: F401 — re-exported: run.py/drains.py/tests import `box.scrub`, `box.RunTainted`
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

    @property
    def sandboxed(self) -> bool:
        # Derived, never settable: only a confining transport may claim the boundary.
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
    Path(__file__).resolve().parent.parent / "seccomp" / "alias-deny.json"
)

BANNED_SHAPES: tuple[str, ...] = ("symlink", "symlinkat", "link", "linkat", "mknod", "mknodat")

_OCI_SECCOMP_FLAG = "--oci-seccomp"
_RUNSC_INSTALL_CMD = "runsc install -- --oci-seccomp"


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
