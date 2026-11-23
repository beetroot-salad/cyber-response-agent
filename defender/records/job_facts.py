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

#: Why an offboard ended a job (#1360 O5), and the sentence it records beside it: the reason is the offboarding's own,
#: distinct from a user's cancel and from a worker fault. One place, so the store and the API's dev fake agree.
TENANT_OFFBOARDED = "tenant_offboarded"
OFFBOARD_MESSAGE = "its tenant was offboarded"

#: The reasons only the worker or the store records on a host request (#1471 surface §6; no record a helper or container
#: writes carries them): a record present but not of its shape, or no record from a helper that exited 0; the stopping
#: worker's end; the take-over's end of a lapsed one, which is never retried (B2: not `lease_lapsed`, whose words promise
#: a retry).
BAD_RECORD, NO_RECORD, WORKER_STOPPED, WORKER_LOST = "bad_record", "no_record", "worker_stopped", "worker_lost"
#: The words of a lapsed host request's take-over.
WORKER_LOST_MESSAGE = "its worker stopped renewing its lease; a host request is never retried"


# --- evidence object names (#1546 PR8) ------------------------------------------------------------------------------

#: Evidence store object names under a claim: the objects every owner pushes, and the page a rendered run or arm owes.
#: They name stored objects, not the run's or the episode's record files.
BUNDLE = "bundle"
RUN_PAGE = "page/runtime.html"  # lint-run-records: ok — an evidence object's name under its claim, not the run record's
EPISODE_PAGE = "page/learning.html"  # lint-run-records: ok — an evidence object's name, not the episode record's
_ARM_PAGE = "page/runs/{}/runtime.html"  # lint-run-records: ok — an arm page's evidence object name (PR8)


def arm_page(run_id: str) -> str:
    """The evidence object name of the page of the arm `run_id` (PR8)."""
    return _ARM_PAGE.format(run_id)
