"""#1342 O7's test-entry child: `python _blocking_entry1342.py <marks> <commit> --job ...`.

Calls the real job entry (`run.job_main`) with a lifecycle whose investigation blocks in a task step
and in a thread call, and a stop-box seam that records it ran. Marks: `pid`, `in-lifecycle`,
`stop-box`."""
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

marks, commit, argv = Path(sys.argv[1]), sys.argv[2], sys.argv[3:]
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


lifecycle = functools.partial(
    run_py._run_investigation_lifecycle, investigate=investigate,
    start_box=lambda *a, **k: box_mod.unboxed_executor(),
    stop_box=lambda *a, **k: (marks / "stop-box").touch(), scrub=lambda *a, **k: None)

sys.exit(run_py.job_main(argv, lifecycle=lifecycle, preflight=lambda *a, **k: 0,
                         visualize=lambda *a, **k: None, publish=lambda *a, **k: f"fresh {commit}"))
