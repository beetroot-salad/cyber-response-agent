"""#1342 O16's test entry: `python _job_entry1342.py <commit> --job <id> --tenant <T> --parent-pid <pid>`.

The real job entry (`run.job_main`) with the replay harness's seams, as `_s_b_support.drive_main`
composes them for `run.main`: production's lifecycle, production's `start_box` in its unsandboxed
opt-out (no daemon), and the real driver over a replay model that writes the golden investigation
and closes `inconclusive`. The environment carries `DEFENDER_DATA_ROOT` and
`DEFENDER_ALLOW_UNSANDBOXED=1` from the worker."""
from __future__ import annotations

import functools
import sys
from pathlib import Path

from defender import box as box_mod
from defender import run as run_py
from defender.tests.e2e import _replay_harness as RH

GOLDEN = Path(RH.__file__).resolve().parents[1] / "fixtures" / "e2e" / "golden-v2sshd"

commit, argv = sys.argv[1], sys.argv[2:]
main = RH.ReplayFn([
    RH.Turn(tool_calls=[("append_block", {"text": (GOLDEN / "investigation.md").read_text(encoding="utf-8")})]),
    RH.Turn(tool_calls=[("close_investigation", {"disposition": "inconclusive"})]),
    RH.Turn(text="Investigation complete."),
])
investigate = functools.partial(run_py._drive_investigation, investigate=RH.investigate_as_handed(main))
lifecycle = functools.partial(
    run_py._run_investigation_lifecycle, investigate=investigate,
    start_box=functools.partial(box_mod.start_box, docker=RH._no_docker_daemon))

sys.exit(run_py.job_main(argv, lifecycle=lifecycle, preflight=lambda *a, **k: 0,
                         visualize=lambda *a, **k: None, publish=lambda *a, **k: f"fresh {commit}"))
