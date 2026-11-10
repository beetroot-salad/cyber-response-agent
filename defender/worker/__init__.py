"""The worker (#1342, #1344): runs claimed investigations and learning jobs from the job store as
child processes, on one set of slots, and records how each ended. `python -m defender.worker` is its
deployed start (#1344 O15).

Above the store (`defender.jobs`) and below the job entries, which it never imports: every job is one
child process, the per-job host helper `python -m defender.job_host --kind <investigation|learning|post-step>
[--job <id>] --tenant <T> [--source <run>] --parent-pid <pid>` (#1170), which starts the job's container."""
from __future__ import annotations

from ._containers import Containers, DockerContainers
from ._start import WorkerStartRefused, refresh_code_copy
from ._worker import (
    Launch,
    LearningLaunch,
    PostStepLaunch,
    Worker,
    job_entry_argv,
    post_step_argv,
    run_argv,
    run_argv_in,
)

__all__ = ["Containers", "DockerContainers", "Launch", "LearningLaunch", "PostStepLaunch", "Worker",
           "WorkerStartRefused", "job_entry_argv", "post_step_argv", "refresh_code_copy", "run_argv", "run_argv_in"]
