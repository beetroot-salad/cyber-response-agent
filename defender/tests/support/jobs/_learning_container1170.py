"""#1170 (r4, integration I2): machinery for the learning entries inside the job container: the learning job entry
(`job_entry.main`, command `python -m defender.cli.learning.job --job --tenant --source`), the post-step and the family-less
check (`post_step.main`, command `python -m defender.learning.branch.post_step [--job] --tenant`) and the sibling
(`run.main`, command `run.py --tenant --episode --world`, in a container when the job socket variable is set).

Picked names (not settled by the design; same family as slice D's `run.job_main`): each in-process entry takes
`environ=<the container's environment>` and finds the job socket in `environ[job_host.SOCKET_ENV]`; the sibling is in a
container exactly when that variable is set (the selector), operator-run otherwise.

`seen_in_container(scene, kind, entry, ...)` runs the real helper (`job_host.main`) over a `ContainerStandIn` whose process is
`entry(container)` on the stand-in's `container-*` thread and returns what the entry did. The `*_HOLD` programs are real
processes run through the entry's real `__main__` (`runpy`) with one paid step replaced by a hold, started by the
stand-in's container thread with the container's environment and a pipe on stdin (the helper's end)."""
from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests.support.jobs._job_helper import HelperScene, until
from defender.tests.support.jobs._job_helper_learning import KindRan, run_kind
from defender.tests.support.jobs._jobs1342 import WORKTREE


@dataclass
class Seen:
    """What the entry did on the container's thread: its return, a `SystemExit`, anything else it raised."""

    ran: bool = False
    rc: int | None = None
    exit: BaseException | None = None
    raised: BaseException | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    kind: KindRan | None = None


def seen_in_container(scene: HelperScene, kind: str, entry: Callable[[Any, Seen], int], *, job_id: str | None = None,
                      family_less: bool = False, source: str | None = None, signer: Any = None) -> Seen:
    """The helper for `kind` over a container whose process is `entry(container, seen)`; a `SystemExit` or other raise of
    the entry is kept on the result, not raised."""
    seen = Seen()

    def job(container: Any) -> int:
        seen.ran = True
        try:
            seen.rc = int(entry(container, seen) or 0)
        except SystemExit as stop:
            seen.exit = stop
            seen.rc = stop.code if isinstance(stop.code, int) else 1
        except BaseException as caught:  # noqa: BLE001 — kept for the case to name
            seen.raised = caught
            seen.rc = 99
        return seen.rc

    seen.kind = run_kind(scene, kind, job, job_id=job_id, family_less=family_less, source=source, signer=signer)
    return seen


def plant_episode(scene: HelperScene, episode_id: str, source: str, world: str = "b") -> tuple[Path, str]:
    """The learning job's episode `<T>/episodes/<episode_id>` as the job's pre-flight leaves it (its manifest, the source run's
    folder beside the runs, and the arm roster minting a canonical run id per world) and the roster's id for `world`."""
    from defender.tests.storage.ids_1187 import _spec1187 as S
    from defender.tests.support.learning.branch import _triplet_947 as T

    (scene.runs / source).mkdir(exist_ok=True)
    doc = T.family_doc(episode_id=episode_id, source_run_dir=str(scene.runs / source), source_run_id=source)
    ep = T.episode(scene.root, doc=doc, root=scene.root / scene.tenant / "episodes", episode_id=episode_id)
    roster = {T.world_id(ep, w): S.new_id() for w in T.WORLDS}
    S.write_roster(ep, roster)
    return ep, roster[T.world_id(ep, world)]


def process_gone(pid: int, what: str, timeout: float = 30.0) -> None:
    """Wait for `pid` to be gone (or a zombie), or fail naming `what`."""
    from defender.tests.support.jobs._job_helper import pid_alive

    until(lambda: not pid_alive(pid), what, timeout)


def child_environment(container: Any) -> dict[str, str]:
    """The container's environment (unset names dropped) with the checkout on `PYTHONPATH` and `PATH`, for a real process."""
    env = {k: v for k, v in container.env.items() if v is not None}
    env["PYTHONPATH"] = f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"
    env["PATH"] = os.environ["PATH"]
    return env


def hold_how(proc: subprocess.Popen, marks: Path, how: str, done: Seen) -> int:
    """Drive one `*_HOLD` process: wait for its `held` mark, then end it by `how` (`sigterm`; `stdin-eof`: close the
    helper's end of its stdin; `control-no-signal`: nothing for 1.5 s, recorded in `done.extra`, then SIGTERM), wait for
    its `unwound` mark, return its exit code."""
    import signal
    import time

    try:
        until(lambda: (marks / "held").exists() or proc.poll() is not None, "the entry to reach its hold", 120)
        done.extra["reached"] = (marks / "held").exists()
        if not done.extra["reached"]:
            done.extra["stderr"] = proc.stderr.read().decode(errors="replace")[-2500:]
            return 1
        if how == "control-no-signal":
            time.sleep(1.5)
            done.extra["alive_without_signal"] = proc.poll() is None
            proc.send_signal(signal.SIGTERM)
        elif how == "sigterm":
            proc.send_signal(signal.SIGTERM)
        else:
            proc.stdin.close()
        return proc.wait(timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def start_hold(container: Any, program: str, marks: Path, *args: str) -> subprocess.Popen:
    """`python -c program marks args...` in the container's environment with a pipe on stdin."""
    return subprocess.Popen([sys.executable, "-c", program, str(marks), *args],  # noqa: S603
                            env=child_environment(container), cwd=str(WORKTREE), stdin=subprocess.PIPE,
                            stderr=subprocess.PIPE)


#: Common prologue of the hold programs: `marks` is argv[1]; `mark(name, text="")`; `sleeping_child()` starts a sibling-like
#: sleeping process through the launcher's real `_default_spawn` on a thread and marks its pid.
_PROLOGUE = r'''
import os, runpy, sys, threading, time
from pathlib import Path
marks = Path(sys.argv[1]); marks.mkdir(parents=True, exist_ok=True)
def mark(name, text=""):
    (marks / name).write_text(text)
mark("pid", str(os.getpid()))
'''

#: The learning job entry's real `__main__`, its family step (`cli.launch_job`) replaced by a hold that starts one real
#: sibling-like child through the launcher's real `_default_spawn` and waits. `held` once the child is up; `interrupted`
#: holds the type that reached the hold; `unwound` once the launcher returned from terminating the child. argv[2:] is the
#: entry's command line.
LEARNING_JOB_HOLD = _PROLOGUE + r'''
from defender.learning.branch import cli
from defender.learning.branch.endings import ending
def launch_job(**kw):
    try:
        cli._default_spawn([sys.executable, "-c", "import os,sys,time;open(sys.argv[1],'w').write(str(os.getpid()));time.sleep(600)",
                            str(marks / "child.pid")], env=dict(os.environ))
    except BaseException as e:
        mark("interrupted", type(e).__name__)
        raise
cli.launch_job = launch_job
def watch():
    while not (marks / "child.pid").exists():
        time.sleep(0.02)
    mark("held")
threading.Thread(target=watch, daemon=True).start()
sys.argv = ["defender.cli.learning.job", *sys.argv[2:]]
try:
    runpy.run_module("defender.cli.learning.job", run_name="__main__")
finally:
    mark("unwound")
'''

#: The post-step's real `__main__`, the drain's gate (`drains.author_drain`) replaced by a hold that starts one real child
#: through the launcher's real `_default_spawn` (as the gate's tick does) and waits. `held` once the child is up;
#: `interrupted` holds the type that reached the gate; `unwound` once the post-step returned.
POST_STEP_HOLD = _PROLOGUE + r'''
from defender.learning.branch import cli
from defender.learning.core import drains
def author_drain(paths):
    try:
        cli._default_spawn([sys.executable, "-c", "import os,sys,time;open(sys.argv[1],'w').write(str(os.getpid()));time.sleep(600)",
                            str(marks / "child.pid")], env=dict(os.environ))
    except BaseException as e:
        mark("interrupted", type(e).__name__)
        raise
drains.author_drain = author_drain
def watch():
    while not (marks / "child.pid").exists():
        time.sleep(0.02)
    mark("held")
threading.Thread(target=watch, daemon=True).start()
sys.argv = ["defender.learning.branch.post_step", *sys.argv[2:]]
try:
    runpy.run_module("defender.learning.branch.post_step", run_name="__main__")
finally:
    mark("unwound")
'''

#: The sibling's real `run.py` `__main__` with the box start replaced by a hold (the run's defaults are bound when the file
#: is run, so the replacement reaches the lifecycle). `held` once the box is being started; `interrupted` the type.
SIBLING_HOLD = _PROLOGUE + r'''
from defender import box
def start_box(*a, **k):
    mark("held")
    try:
        time.sleep(600)
    except BaseException as e:
        mark("interrupted", type(e).__name__)
        raise
box.start_box = start_box
sys.argv = ["run.py", *sys.argv[2:]]
try:
    runpy.run_module("defender.run", run_name="__main__")
finally:
    mark("unwound")
'''
