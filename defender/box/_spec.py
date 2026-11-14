"""What a box IS: the request, the mounts, the executor, and the transports that carry a
command to one.

The two transports live here rather than with the lifecycle because `BoxExecutor`
discriminates on the docker one, and the protocol they implement is declared here.
"""
from __future__ import annotations

import logging
import os
import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, Final, Literal, NoReturn, Protocol, runtime_checkable

from defender._model import model
from defender.execution import bash_exec
from defender.execution.box_codec import (
    KILLED_LINE,
    REQUEST_MAGIC,  # noqa: F401 — re-exported: test_exec_seam.py imports it as `box.REQUEST_MAGIC`
    RESPONSE_MAGIC,  # noqa: F401 — re-exported: test_exec_seam.py imports it as `box.RESPONSE_MAGIC`
    BoxFault,
    BoxResult,
    RawExec,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)
from defender.records.run_end import TRUNCATED_BY_BOX_LOST, TRUNCATED_BY_BOX_OUTPUT_LIMIT
from ._clock import write_clock
from ._docker import _inspect_field
from ._ending import BoxEnding, BoxLost
from ._output import BoxOutputLimitExceeded, capture_bounded
from defender._model_view import ModelView
from defender.box._scrub import (  # noqa: F401 — re-exported: run.py/drains.py/tests import `box.scrub`, `box.RunTainted`
    Finding,
    RunTainted,
    scrub,
    verdict_path,
    write_did_not_run,
)


_logger = logging.getLogger(__name__)

#: `docker exec`'s own code when the process it ran (the in-box helper) was killed (C4, C5).
_EXEC_KILLED = 137
#: The in-box helper's own code for a command that passed its deadline.
_HELPER_DEADLINE = 3
#: The code a command's result carries when the helper itself was killed (rule 2): a kill, as a
#: stage's own kill reads.
_KILLED_RC = -9

#: `classify_unframed`'s answers, one per rule.
NOT_RUNNING: Final = "not-running"
KILLED: Final = "killed"
TIMED_OUT: Final = "timeout"
UNUSABLE: Final = "unusable"
Unframed = Literal["not-running", "killed", "timeout", "unusable"]


def box_status(docker: Any, name: str) -> str | None:
    """The box's status, asked of `docker` once; `None` for no daemon, no answer or a fault asking."""
    if docker is None:
        return None
    try:
        return _inspect_field(docker, name, "{{.State.Status}}")
    except BoxFault:
        return None


def classify_unframed(raw: RawExec | None, failure: Exception | None, status: str | None) -> Unframed:
    """#1421's rule for an exchange that gave no clean frame, on the box's one status answer (`box_status`), in this
    order: the job's own executor (`BoxExecutor._unframed`) and the helper's relay (`relay_exec`) both answer by it.
    1. not `running`, no answer, or a fault asking: the box is lost (`NOT_RUNNING`), whatever else the exchange
       said, a host timeout included: a command past its timeout on a box that died is a lost box, not a timeout;
    2. `running` and exec 137: the in-box helper was killed, the box lives (`KILLED`);
    3. `running` and a host timeout or the in-box helper's own deadline (exec 3): a timeout (`TIMED_OUT`);
    4. `running` and anything else: the box is lost, worded as unusable (`UNUSABLE`)."""
    if status != "running":
        return NOT_RUNNING
    if raw is not None and raw.rc == _EXEC_KILLED:
        return KILLED
    if isinstance(failure, subprocess.TimeoutExpired) or (raw is not None and raw.rc == _HELPER_DEADLINE):
        return TIMED_OUT
    return UNUSABLE


# This module is host-only (it pulls in pydantic); nothing inside a box imports it. An unset
# `rootfs` is resolved to `_image.image_tag(tree)` by each `docker run` argv builder, so
# constructing a `BoxSpec` reads nothing off the tree.
@model(frozen=True)
class BoxSpec:

    runtime: str = "runsc"
    rootfs: str | None = None
    lifecycle: str = "per_run"
    tmpfs_size: str = "64m"
    #: What one box may take from the host, so a command the model runs cannot starve the other
    #: tenants' runs. `/tmp` counts against the memory cap.
    memory: str = "2g"
    cpus: str = "2"
    pids_limit: int = 256

    ENV_VAR: ClassVar[str] = "DEFENDER_BOX_RUNTIME"
    #: The box environment's copy of `memory` (#1421 P5), as written: the in-box SQL tool limits
    #: its own address space to a share of it. Set by both `docker run` builders; never on a host
    #: lane, which has no cap.
    MEMORY_ENV: ClassVar[str] = "DEFENDER_BOX_MEMORY"
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
    #: Which words of a command are paths; required with `view` when the host fallback runs.
    path_operands: Callable[[list[str]], Iterable[str]] | None = None
    #: The tenant the box works for: its container is labelled `defender.tenant=<T>`, so the
    #: tenant's teardown stops it (#1214 O4).
    tenant_id: str = field(kw_only=True)
    #: The data root the caller resolved, where the box check (#1469) makes its folder. Required whatever the runtime
    #: (amendment 2026-11-14), so a caller that forgets it fails at construction, and under mypy, not only on a gVisor
    #: host.
    data_root: Path = field(kw_only=True)

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, str) or not self.tenant_id:
            raise ValueError("a box request names its tenant: teardown finds boxes only by their tenant label")

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

    #: The exit class of the ending that refuses every later command in this box (#1421), or
    #: `None`. The fence's refusal is permanent; a lost box's is lifted only by `readmit`, when a
    #: lane's next window has proven its box started.
    _refusing: str | None = field(default=None, compare=False, repr=False)

    #: The run box's attached `docker start -a -i` (#1343 B10), held here for the run's life: its
    #: input pipe is the box's main process's input, so the box ends when the process holding the
    #: executor ends, by any means. Only the teardown (or a start fault) ends it. `None` for every
    #: other box: a request-lane box is started detached and removed explicitly.
    starter: subprocess.Popen[bytes] | None = field(default=None, compare=False, repr=False)

    @property
    def auto_removed(self) -> bool:
        """The box removes itself once it stops (the run box, `--rm`): one being removed, or
        already gone, is a stopped box."""
        return self.starter is not None

    def follow_clock(self, reading: Callable[[], datetime]) -> None:
        """Have the box's programs read the run's clock: before every command, the clock file is
        rewritten from `reading()` (the run clock moves against the wall — it pauses for an
        oracle turn, and an arm's runs ahead of or behind it). A box with no clock file has no
        preload to feed."""
        self._clock_reading = reading

    def readmit(self) -> None:
        """A lane window started this box again and proved it running: a loss found in an
        earlier window no longer refuses its commands. The fence's refusal stays."""
        if self._refusing == TRUNCATED_BY_BOX_LOST:
            self._refusing = None

    def _sync_clock(self) -> None:
        if self.clock_file is None or self._clock_reading is None:
            return
        try:
            write_clock(self.clock_file, self._clock_reading())
        except OSError as e:
            raise BoxFault(f"could not set the run clock for the box {self.name}: {e}") from e

    @property
    def sandboxed(self) -> bool:
        # Derived, never settable: only a confining transport may claim the boundary. A box reached over the job
        # socket (#1170 A4) is confined by construction: the helper started it, and a relay is never host execution.
        return isinstance(self.transport, (_DockerTransport, RelayTransport))

    def run_parsed(
        self, pipelines: Sequence[bash_exec.Pipeline], *,
        command: str, cwd: Path, timeout: float,
    ) -> BoxResult:
        self._refuse()
        self._sync_clock()
        frame = encode_request(pipelines)
        if isinstance(self.transport, RelayTransport):
            return self._exchange_relayed(frame, command=command, cwd=cwd, timeout=timeout)
        if self.sandboxed:
            return self._exchange_boxed(frame, command=command, cwd=cwd, timeout=timeout)
        return self._exchange_unboxed(frame, command=command, cwd=cwd, timeout=timeout)

    run = run_parsed

    def _refuse(self) -> None:
        """Every command after an ending gets that ending again, with no new exchange."""
        if self._refusing == TRUNCATED_BY_BOX_OUTPUT_LIMIT:
            raise BoxOutputLimitExceeded()
        if self._refusing == TRUNCATED_BY_BOX_LOST:
            raise BoxLost(f"the box {self.name} was found unusable; it runs no further command")

    def _exchange_unboxed(self, frame: bytes, *, command: str, cwd: Path, timeout: float) -> BoxResult:
        """An unsandboxed transport (the host fallback, a test's): outside #1421's rules, its
        faults stay plain `BoxFault`s and no daemon is asked anything."""
        try:
            raw = self.transport(frame, cwd=cwd, timeout=timeout)
        except BoxOutputLimitExceeded as overflow:
            self._end(overflow, command)
        except (BoxFault, subprocess.TimeoutExpired):
            raise
        except Exception as e:
            raise BoxFault(f"the box was unreachable while running {command!r}: {e}") from e
        try:
            return decode_response(raw.stdout)
        except BoxFault as e:
            raise BoxFault(f"{e}: {_text(raw.stderr).strip()}") from None

    def _exchange_boxed(self, frame: bytes, *, command: str, cwd: Path, timeout: float) -> BoxResult:
        """One exchange with a sandboxed box. A clean frame is the command's result, whatever
        its code; anything else asks the box's status once and is classified by `_unframed`."""
        raw: RawExec | None = None
        failure: Exception | None = None
        try:
            raw = self.transport(frame, cwd=cwd, timeout=timeout)
        except BoxOutputLimitExceeded as overflow:
            self._end(overflow, command)
        except Exception as e:  # noqa: BLE001 — every exchange without a frame is classified below
            failure = e
        if raw is not None:
            try:
                return decode_response(raw.stdout)
            except BoxFault as e:
                failure = e
        return self._unframed(raw, failure, command=command, timeout=timeout)

    def _unframed(
        self, raw: RawExec | None, failure: Exception | None, *, command: str, timeout: float,
    ) -> BoxResult:
        """An exchange with no clean frame, classified by #1421's rule (`classify_unframed`) on the box's one
        status answer: lost ends the box, a kill of the in-box helper is a result with the kill line (so the row is
        recorded), a timeout is the timeout and leaves the box usable."""
        status = self._status()
        verdict = classify_unframed(raw, failure, status)
        if verdict == NOT_RUNNING:
            self._end(BoxLost(
                f"the box {self.name} is not running (its status: {status or 'no answer'}); "
                "it can run no command"), command, cause=failure)
        if verdict == KILLED:
            return BoxResult(rc=_KILLED_RC, out=b"", err=KILLED_LINE)
        if verdict == TIMED_OUT:
            if isinstance(failure, subprocess.TimeoutExpired):
                raise failure
            raise subprocess.TimeoutExpired(command, timeout)
        said = f"exec rc {raw.rc}, no frame" if raw is not None else f"{type(failure).__name__}"
        self._end(BoxLost(
            f"the box {self.name} is running but did not answer a command as its helper does "
            f"({said}); it is unusable"), command, cause=failure)
        raise AssertionError("unreachable")  # pragma: no cover — `_end` always raises

    def _exchange_relayed(self, frame: bytes, *, command: str, cwd: Path, timeout: float) -> BoxResult:
        """One exchange over the job socket (#1170 A4): the helper, which holds the daemon, has already classified it
        by #1421's rules, so its answer is mapped to today's outcome here. Only `ok` with a frame that decodes is a
        result; `timeout` is the timeout and leaves the box usable; `output-limit` and `lost` end the box. Anything
        else (a refusal, a helper that cannot be reached, an answer or frame outside the vocabulary) is a lost box:
        the box ends with its helper, so no answer is a loss, never a result."""
        relay = self.transport
        assert isinstance(relay, RelayTransport)
        try:
            answer = relay.exchange(frame, cwd=cwd, timeout=timeout)
        except Exception as unreached:  # noqa: BLE001 — every failure to get an answer is the same loss
            self._end(BoxLost(
                f"the box {self.name} could not be reached through its helper ({type(unreached).__name__}: "
                f"{unreached}); it is unusable"), command, cause=unreached)
        result = answer.get("result") if isinstance(answer, dict) else None
        if result == "ok":
            got = answer.get("frame")
            try:
                if not isinstance(got, bytes):
                    raise BoxFault("the helper's ok answer carries no response frame")
                return decode_response(got)
            except BoxFault as unreadable:
                self._end(BoxLost(f"the box {self.name}'s answer through its helper is not a response frame "
                                  f"({unreadable}); it is unusable"), command, cause=unreadable)
        if result == "timeout":
            raise subprocess.TimeoutExpired(command, timeout)
        if result == "output-limit":
            self._end(BoxOutputLimitExceeded(), command)
        if result == "lost":
            self._end(BoxLost(f"the box {self.name} is not running or did not answer as its helper does "
                              f"(its helper says: {answer.get('class')!r}); it can run no command"), command)
        self._end(BoxLost(f"the box {self.name}'s helper answered outside its vocabulary "
                          f"({type(answer).__name__} {result!r}); it is unusable"), command)

    def _status(self) -> str | None:
        """The box's status, asked once (`box_status`)."""
        return box_status(self.docker, self.name)

    def _end(self, ending: BoxEnding, command: str, *, cause: BaseException | None = None) -> NoReturn:
        """Refuse every later command with `ending`'s class, stop the box, and raise `ending`.
        The ending keeps its identity when the stop cannot be proven, with a note saying so. The
        log names the command; the records carry only the class."""
        self._refusing = ending.exit_class
        _logger.error(f"the box {self.name} ended the run ({ending.exit_class}) while running "
                      f"{command!r}")
        # The box's own lifecycle proves every box process has stopped: its daemon's, or for a relayed box its
        # helper's (`box.halt`).
        from ._lifecycle import BoxRuns

        try:
            BoxRuns(self).stop()
        except Exception as cleanup:
            ending.add_note(f"could not confirm the box stopped: {cleanup}")
            raise ending from cleanup
        if cause is not None:
            raise ending from cause
        raise ending



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


#: The relay's request client: `request(name, **fields) -> dict`, the job's socket client bound to its socket
#: (`job_socket.ask`), raising for a refusal or a socket that is gone.
RelayRequest = Callable[..., Any]


@dataclass(frozen=True)
class RelayTransport:
    """The confining transport of a box reached over the job socket (#1170 A4): the box was started by the per-job
    host helper, which holds the daemon and answers each frame already classified (`box.exec`) and proves each stop
    (`box.stop`). `handle` is the box's handle, as the helper's `box.start` answered it. The job's executor keeps the
    refusal latch, readmit, the run clock and the typed endings; nothing here talks to a daemon."""

    request: RelayRequest = field(compare=False, repr=False)
    handle: str

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> RawExec:
        raise BoxFault("a relayed box is reached through BoxExecutor.run_parsed, never as a raw transport")

    def exchange(self, frame: bytes, *, cwd: Path, timeout: float) -> Any:
        """The helper's answer to one frame: the command's timeout goes as given (the executor's own; no ceiling)."""
        return self.request("box.exec", handle=self.handle, frame=frame, cwd=str(cwd), timeout=timeout)

    # The box's lifecycle (`_lifecycle.BoxLifecycle`), each step asked of the helper that holds its daemon.

    @property
    def managed(self) -> bool:
        return True

    def halt(self) -> None:
        """Stop the box, proven, and keep it for a later window (`box.halt`): the helper stops it and ends the window it
        holds. `BoxFault` (the helper's reason, or why it could not be asked) unless the helper answers `stopped`."""
        self._proven("box.halt", "stopped", ask="stop", proof="stopped")

    def open_window(self, hold: Callable[[subprocess.Popen[bytes]], None]) -> None:  # noqa: ARG002 — the helper holds it
        """Start the stopped box for one window (`box.window`): the helper starts it attached and holds the attached
        start until the window's `halt`, or its own end. `BoxFault` unless the helper answers `open`."""
        self._proven("box.window", "open", ask="start", proof="running")

    def teardown(self) -> None:
        """Remove the box for good (`box.stop`): `BoxFault` unless the helper answers `stopped`."""
        self._proven("box.stop", "stopped", ask="stop", proof="stopped")

    def _proven(self, request: str, word: str, *, ask: str, proof: str) -> None:
        try:
            answer = self.request(request, handle=self.handle)
        except Exception as unreached:  # noqa: BLE001 — a step that cannot be asked is a step not proven
            raise BoxFault(f"could not ask the helper to {ask} the box {self.handle}: "
                           f"{type(unreached).__name__}: {unreached}") from unreached
        if isinstance(answer, dict) and answer.get("result") == word:
            return
        reason = answer.get("reason") if isinstance(answer, dict) else None
        raise BoxFault(f"the helper could not prove the box {self.handle} {proof}: {reason or answer!r}")


@dataclass(frozen=True)
class _HostTransport:

    env: dict[str, str]
    view: ModelView | None = None
    #: Which words of a command are paths; the caller's permission grammar decides.
    path_operands: Callable[[list[str]], Iterable[str]] | None = None

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> RawExec:
        pipelines = decode_request(frame)
        if self.view is not None:
            if self.path_operands is None:
                raise TypeError("a host transport with a model view needs path_operands")
            # The permission grammar owns which arguments are paths. A grep pattern or
            # Python string that resembles a workspace path must keep its literal bytes.
            translated = []
            for pipeline in pipelines:
                stages = []
                for stage in pipeline.stages:
                    operands = self.path_operands(stage.argv)
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
        return RawExec(rc=rc, stdout=encode_response(BoxResult(rc=rc, out=out, err=err)), stderr=b"")
