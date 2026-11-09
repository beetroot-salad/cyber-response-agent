"""The words a job-end record uses for the facts the host process recorded (#1342).

Kept apart from `job_lane`, which owns the files: these are values the worker and the job entry
compare against, not record names.
"""

from __future__ import annotations

SETUP_REFUSED, SETUP_CRASHED, SETUP_DONE = "refused", "crashed", "done"
BOX_NOT_STARTED, BOX_START_FAILED, BOX_STARTED = "not_started", "start_failed", "started"

#: The reasons only the worker records on a learning job (#1344; no end record carries them).
EXPIRED, EXITED_WITHOUT_RESULT, WORKER_ERROR, LEASE_LAPSED, RETRY_CAP = (
    "expired", "exited_without_result", "worker_error", "lease_lapsed", "retry_cap")
