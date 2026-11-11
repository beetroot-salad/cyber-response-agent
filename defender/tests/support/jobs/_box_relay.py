"""#1170 (r4 A4): doubles and the wire this slice picks for the box relay. Not settled by the design; the target's names are picks.

Job side: `box.RelayTransport(request, handle)` is the confining transport (`BoxExecutor.sandboxed` is true over it); `request(name,
**fields) -> dict` is the job's socket client (`job_host.ask` bound to the socket; it raises `OSError` for a socket that is gone).
`box.stop_box(executor)` over a relay executor asks `box.stop` instead of a daemon the job lacks; an ending's stop and a lane's
`BoxRuns` ask `box.halt` (stopped, kept for a later window) and `box.window` (one window's start).

Wire. `box.exec(handle, frame, cwd, timeout)` answers `{"result": "ok", "frame": <response frame bytes>}` (a command's result, or
the kill line as the response frame of `BoxResult(-9, b"", KILLED_LINE)`), `{"result": "output-limit"}`, `{"result": "timeout"}`
or `{"result": "lost", "class": "box-lost"}`. `box.stop(handle)` and `box.halt(handle)` answer `{"result": "stopped"}` or
`{"result": "fault", "reason": str}`; `box.window(handle)` answers `{"result": "open"}` or a fault.

Helper side: `RelayDocker` is slice A's `ContainerStandIn` plus what the #1421 matrix needs of a daemon (a status that is gone,
mute or raising; a `docker exec` that is any process, or fails to run)."""
from __future__ import annotations

import subprocess
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender import box
from defender.execution import bash_exec
from defender.execution.box_codec import BOX_OUTPUT_LIMIT, KILLED_LINE
from defender.records.run_end import TRUNCATED_BY_BOX_LOST
from defender.tests.support.jobs._job_helper import ContainerStandIn

OUTPUT_LIMIT = {"result": "output-limit"}
TIMEOUT = {"result": "timeout"}
LOST = {"result": "lost", "class": TRUNCATED_BY_BOX_LOST}
STOPPED = {"result": "stopped"}
STOP_FAULT = {"result": "fault", "reason": "could not stop the box"}
OPENED = {"result": "open"}
WINDOW_FAULT = {"result": "fault", "reason": "the box did not start"}
HANDLE = "handle-1170"


def ok(rc: int = 0, out: bytes = b"", err: bytes = b"") -> dict[str, Any]:
    return {"result": "ok", "frame": box.encode_response(box.BoxResult(rc=rc, out=out, err=err))}


KILLED = {"result": "ok", "frame": box.encode_response(box.BoxResult(rc=-9, out=b"", err=KILLED_LINE))}


class ScriptedHelper:
    """The job's `request(name, **fields)`: `box.exec` is answered from `execs` (a dict is an answer, an exception is raised,
    the last repeats), `box.stop` from `stop`, `box.halt` from `halt` (`stop` unless given) and `box.window` from `window`.
    Every ask is kept in `calls`."""

    def __init__(self, *execs: Any, stop: Any = STOPPED, halt: Any = None, window: Any = None) -> None:
        self._execs = list(execs) or [ok()]
        self._stop = stop
        self._halt = stop if halt is None else halt
        self._window = OPENED if window is None else window
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, name: str, **fields: Any) -> Any:
        self.calls.append((name, fields))
        if name == "box.exec":
            n = sum(1 for c in self.calls if c[0] == "box.exec")
            got = self._execs[min(n - 1, len(self._execs) - 1)]
        elif name == "box.stop":
            got = self._stop
        elif name == "box.halt":
            got = self._halt
        elif name == "box.window":
            got = self._window
        else:
            raise AssertionError(f"the job asked the helper for {name!r}, which a box executor has no business asking")
        if isinstance(got, BaseException):
            raise got
        return got

    def asked(self, name: str) -> list[dict[str, Any]]:
        return [f for n, f in self.calls if n == name]


def relay_executor(helper: ScriptedHelper, name: str = "relay-box") -> box.BoxExecutor:
    return box.BoxExecutor(name=name, transport=box.RelayTransport(helper, HANDLE))


# --- helper side --------------------------------------------------------------------------------------------------

EXEC_KILLED = ("sh", "-c", "exit 137")
EXEC_KILLED_WITH_BYTES = ("sh", "-c", "printf 'partial output'; exit 137")
_HALF = box.encode_response(box.BoxResult(rc=0, out=b"x" * 99, err=b""))
EXEC_KILLED_MID_FRAME = (sys.executable, "-c", f"import os, sys\nos.write(1, {_HALF[:len(_HALF) // 2]!r}); sys.exit(137)")
EXEC_SAYS_NO_SUCH_BOX = ("sh", "-c", "echo 'No such container' >&2; exit 1")
NOT_A_FRAME = ("sh", "-c", "printf 'wrong magic, a bypassing writer'")
EXEC_REFUSED_REQUEST = ("sh", "-c", "exit 2")
EXEC_HELPER_DEADLINE = ("sh", "-c", "exit 3")
OVER_THE_FENCE = ("head", "-c", str(BOX_OUTPUT_LIMIT + 1), "/dev/zero")
SLEEPS = ("sleep", "30")

#: A frame whose encoding is exactly the output limit, and the same plus one byte.
_OVERHEAD = len(box.encode_response(box.BoxResult(rc=0, out=b"", err=b"")))
AT_THE_LIMIT = box.encode_response(box.BoxResult(rc=0, out=b"x" * (BOX_OUTPUT_LIMIT - _OVERHEAD), err=b""))
assert len(AT_THE_LIMIT) == BOX_OUTPUT_LIMIT


def printing(frame: bytes, folder: Path | None = None) -> tuple[str, ...]:
    """A command that writes `frame` to its stdout; through a file in `folder` for one too large for an argument."""
    if folder is not None:
        path = folder / f"frame-{len(frame)}"
        path.write_bytes(frame)
        return ("cat", str(path))
    return (sys.executable, "-c", f"import os; os.write(1, {frame!r})")


class RelayDocker(ContainerStandIn):
    """`ContainerStandIn` whose box `docker exec` is `exec_with` (an argv run as a real process, or an exception raised as a
    docker client that cannot run) and whose box status can be put in a state: `running`, `exited`, `gone`, `mute` (the daemon
    answers nothing) or `raises` (asking times out)."""

    def __init__(self, job: Callable[..., int] | None = None, **kw: Any) -> None:
        super().__init__(job, **kw)
        self.exec_with: tuple[str, ...] | BaseException | None = None
        self.mode = "answers"

    def put(self, state: str) -> None:
        self.mode = "answers"
        self.phase = "running" if state == "running" else None
        self.status = {"running": "running", "exited": "exited"}.get(state)
        if state in ("mute", "raises"):
            self.mode = state

    def status_asks(self) -> int:
        return len([c for c in self.calls if len(c) > 1 and c[1] == "inspect" and any("State.Status" in a for a in c)])

    def popen(self, argv, **kw):  # noqa: ANN001
        argv = list(argv)
        if len(argv) > 1 and argv[1] == "exec" and self.exec_with is not None:
            self.calls.append(argv)
            self.log.append(argv)
            if isinstance(self.exec_with, BaseException):
                raise self.exec_with
            return subprocess.Popen(list(self.exec_with), **kw)
        return super().popen(argv, **kw)

    def __call__(self, argv, **kw):  # noqa: ANN001
        argv = list(argv)
        asks_status = len(argv) > 1 and argv[1] == "inspect" and any("State.Status" in a for a in argv)
        if self.mode != "answers" and (asks_status or (self.mode == "mute" and argv[1:2] == ["version"])) \
                and not any(b.name in argv for b in self.boxes):
            self.calls.append(argv)
            if self.mode == "raises":
                raise subprocess.TimeoutExpired(argv, 1)
            return subprocess.CompletedProcess(argv, 1, "", "Cannot connect to the Docker daemon")
        return super().__call__(argv, **kw)


# --- a second helper, as its own process, for O10 ------------------------------------------------------------------

#: Driver for another helper (another job of the same tenant, another claim): its job starts a shell box, asks `box.exec`
#: until told to stop, and records each answer and whether its container was told to stop under `STATE`.
OTHER_HELPER = textwrap.dedent("""\
    import json, sys, time
    from pathlib import Path
    from defender import job_host
    from defender.tests.support.jobs._job_helper import ContainerStandIn
    from defender.tests.support.jobs import _box_relay as R
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    cfg = json.loads(sys.argv[1])
    state = Path(cfg["state"])

    def job(c):
        h = c.request("box.start", kind="shell", id=cfg["inv"])["handle"]
        n = 0
        while not (state / "stop").exists():
            ans = c.request("box.exec", handle=h, frame=R.FRAME, cwd="/runs/current", timeout=5.0)
            (state / "answers.log").open("a").write(json.dumps(ans["result"]) + "\\n")
            n += 1
            if n == 1:
                (state / "ready").write_text("1")
            time.sleep(0.05)
        (state / "stopping").write_text(str(c.stopping.is_set()))
        return 0

    docker = ContainerStandIn(job, exec_writer=[sys.executable, "-c", "import os; os.write(1, " + repr(R.OK_FRAME) + ")"])
    rc = job_host.main(cfg["argv"], docker=docker, signer=A.MarkedSigner(),
                       publish=lambda *a, **k: B.fresh(cfg["commit"]))
    (state / "rc").write_text(str(rc))
    (state / "box-stops").write_text(json.dumps([c for c in docker.calls if c[1] in ("stop", "rm", "kill")]))
""")

FRAME = box.encode_request(bash_exec.parse("echo hello"))
OK_FRAME = box.encode_response(box.BoxResult(rc=0, out=b"hello\n", err=b""))
