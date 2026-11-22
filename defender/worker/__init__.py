"""The worker (#1342, #1344): runs claimed investigations and learning jobs from the job store as
child processes, on one set of slots, and records how each ended. `python -m defender.worker` is its
deployed start (#1344 O15).

Above the store (`defender.jobs`) and below the job entries, which it never imports: every job is one
child process, the per-job host helper `python -m defender.job_host --kind <investigation|learning|post-step>
[--job <id>] --tenant <T> [--source <run>] --parent-pid <pid>` (#1170), which starts the job's container. Host requests
(#1471, #1546 D7) run the same helper, `--kind readiness|adoption|drain --job <request id>` (adoption adds `--system
<id>`), from a pool of their own."""
from __future__ import annotations

from ._containers import Containers, DockerContainers
from ._start import WorkerStartRefused, refresh_code_copy
from ._worker import (
    AdoptionLaunch,
    DrainLaunch,
    Launch,
    LearningLaunch,
    PostStepLaunch,
    ReadinessLaunch,
    Worker,
    adoption_argv,
    drain_argv,
    job_entry_argv,
    post_step_argv,
    readiness_argv,
    run_argv,
    run_argv_in,
)

__all__ = ["AdoptionLaunch", "Containers", "DockerContainers", "DrainLaunch", "Launch", "LearningLaunch", "PostStepLaunch",
           "ReadinessLaunch", "Worker", "WorkerStartRefused", "adoption_argv", "drain_argv", "job_entry_argv", "post_step_argv",
           "readiness_argv", "refresh_code_copy", "run_argv", "run_argv_in"]
