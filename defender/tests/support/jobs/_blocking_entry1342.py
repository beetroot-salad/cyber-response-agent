"""#1342 O7's test-entry child: `python _blocking_entry1342.py <marks> <commit> <containers> --job ...`.

Calls the real job entry (`run.job_main`) with a lifecycle whose investigation blocks in a task step
and in a thread call, and a stop-box seam that records it ran. The start-box seam plays the box start:
it must be handed `start_token` (r5 C1) and stamps the stand-in container `<containers>/defender-run-<id>`
with it. Marks: `pid`, `in-lifecycle`, `stop-box`, `start-token`."""
from __future__ import annotations

import asyncio
import functools
import os
import sys
import time
from pathlib import Path

# The child is a bare script: put the checkout root (the parent of `defender/`) on the path from
# this file's own location, so it never relies on the parent's PYTHONPATH or an installed package.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from defender import box as box_mod
from defender import run as run_py

marks, commit, containers, argv = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), sys.argv[4:]
marks.mkdir(parents=True, exist_ok=True)
(marks / "pid").write_text(str(os.getpid()), encoding="utf-8")


def _blocking_thread_call() -> None:
    time.sleep(3)  # a verb call in flight; short, so the 3.11 executor join ends


async def _investigation() -> None:
    (marks / "in-lifecycle").touch()
    await asyncio.gather(asyncio.sleep(600), asyncio.to_thread(_blocking_thread_call))


def investigate(**_kw):
    asyncio.run(_investigation())
    return {"output": "unreachable", "requests": 0}


def _start_box(run_dir, *_a, start_token, **_k):
    """A box start that requires the token the launch record carries and leaves the container it stamps."""
    containers.mkdir(parents=True, exist_ok=True)
    (containers / f"defender-run-{Path(run_dir).name}").write_text(start_token, encoding="utf-8")
    (marks / "start-token").write_text(start_token, encoding="utf-8")
    return box_mod.unboxed_executor()


lifecycle = functools.partial(
    run_py._run_investigation_lifecycle, investigate=investigate,
    start_box=_start_box,
    stop_box=lambda *a, **k: (marks / "stop-box").touch(), scrub=lambda *a, **k: None)

sys.exit(run_py.job_main(argv, lifecycle=lifecycle, preflight=lambda *a, **k: 0,
                         visualize=lambda *a, **k: None, publish=lambda *a, **k: f"fresh {commit}"))
