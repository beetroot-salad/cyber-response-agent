"""#1170 (r4, slice D): machinery for the in-container job entry (`run.job_main`) driven through the real per-job helper.

The scene is `_job_helper.helper_scene` (its `files=`, `alert_mapping=` and `proxied=` knobs).
`enter(scene, inv, ...)` runs the helper (`job_host.main`, on this thread, over a `ContainerStandIn`) whose job container is
the entry (`run.job_main(argv, environ=<the container's environment>, **seams)`, on the stand-in's `container-*` thread), and
returns what the entry did. `ThreadCalls` counts calls by the thread that made them, so a test can tell what the container's
side did from what the helper's side did in the same process. `HOLD_CHILD` is a real `run.serve_job` process."""
from __future__ import annotations

import contextlib
import inspect
import io
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from defender.tests.support.jobs._job_helper import (
    ContainerStandIn,
    HelperRan,
    HelperScene,
    drive_helper,
)


@dataclass
class Entered:
    """One helper-and-entry run: the helper's outcome, the container stand-in, and what the entry did."""

    helper: HelperRan
    docker: ContainerStandIn
    rc: int | None = None
    job_rc: int | None = None  # the job container's own status, when it ran
    exit: BaseException | None = None  # a SystemExit the entry raised
    raised: BaseException | None = None  # anything else it raised
    out: str = ""
    err: str = ""
    ran: bool = False  # the entry was reached at all
    extra: dict[str, Any] = field(default_factory=dict)


def enter(scene: HelperScene, inv: str, *, signer: Any = None, entry: Callable[..., int] | None = None,
          kind: str = "investigation", docker: ContainerStandIn | None = None, **seams: Any) -> Entered:
    """Run the helper for `inv` over a container whose process is `run.job_main` with `seams` (`entry(container)` instead:
    a custom container process). `docker` is a prebuilt stand-in (a `RelayDocker`, say) to run the job on. Stdout and stderr
    are captured across the whole run."""
    from defender import run as run_py
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    done = Entered(helper=HelperRan(), docker=ContainerStandIn())

    def job(container: Any) -> int:
        done.ran = True
        done.job_rc = run(container)
        return done.job_rc

    def run(container: Any) -> int:
        if entry is not None:
            return entry(container, done)
        try:
            return int(run_py.job_main(["--job", inv, "--tenant", scene.tenant], environ=container.env, **seams))
        except SystemExit as e:
            done.exit = e
            return e.code if isinstance(e.code, int) else 1
        except BaseException as e:  # noqa: BLE001 — kept for the case to name (a KeyboardInterrupt included)
            done.raised = e
            return 99

    done.docker = docker if docker is not None else ContainerStandIn()
    done.docker.job = job
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        done.helper = drive_helper(scene, scene.argv(kind, inv), docker=done.docker,
                                   signer=signer if signer is not None else A.MarkedSigner())
    done.out, done.err = out.getvalue(), err.getvalue()
    # The job's own status when its container ran (the helper exits 0 once it served it, #1170), else the helper's.
    done.rc = done.job_rc if done.job_rc is not None else done.helper.rc
    return done


class ThreadCalls:
    """Calls of watched functions by code object (`counting_calls`' mechanism) with the name of the thread that made each.
    `container(label)` counts those made on a `container-*` thread (the stand-in's job container), `helper(label)` the rest.
    Threads started inside the block are watched too."""

    def __init__(self, functions: dict[str, Callable[..., Any]]) -> None:
        self._labels = {inspect.unwrap(fn).__code__: label for label, fn in functions.items()}
        self.by_thread: dict[str, list[str]] = {label: [] for label in functions}
        self._active = True
        self._previous: tuple[Any, Any] | None = None

    def _hook(self, frame: Any, event: str, _arg: object) -> None:
        if self._active and event == "call" and frame.f_code in self._labels:
            self.by_thread[self._labels[frame.f_code]].append(threading.current_thread().name)

    def container(self, label: str) -> int:
        return sum(name.startswith("container-") for name in self.by_thread[label])

    def helper(self, label: str) -> int:
        return sum(not name.startswith("container-") for name in self.by_thread[label])

    def __enter__(self) -> ThreadCalls:
        self._previous = (sys.getprofile(), threading.getprofile())
        threading.setprofile(self._hook)
        sys.setprofile(self._hook)
        return self

    def __exit__(self, *_exc: object) -> None:
        self._active = False
        assert self._previous is not None
        sys.setprofile(self._previous[0])
        threading.setprofile(self._previous[1])


#: A real `run.serve_job` process (the container's command line, `python run.py --job <id> --tenant <T>`), run with the
#: lifecycle held in the main thread. Marks go in argv[1]: `pid`, `in-lifecycle`, `interrupted` (the exception type that
#: reached the investigation), `stop-box-started`, then `stop-box-done` once `go-on` exists. argv[2:] is the entry's argv.
HOLD_CHILD = r'''
import sys, time
from pathlib import Path
from defender import run as run_py
marks = Path(sys.argv[1])
marks.mkdir(parents=True, exist_ok=True)
(marks / "pid").write_text(str(__import__("os").getpid()))

def lifecycle(**kw):
    (marks / "in-lifecycle").touch()
    try:
        time.sleep(600)
    except BaseException as e:
        (marks / "interrupted").write_text(type(e).__name__)
        (marks / "stop-box-started").touch()
        while not (marks / "go-on").exists():
            time.sleep(0.02)
        (marks / "stop-box-done").touch()
        raise
    return {}

sys.exit(run_py.serve_job(sys.argv[2:], lifecycle=lifecycle, preflight=lambda *a, **k: 0,
                          visualize=lambda *a, **k: None))
'''
