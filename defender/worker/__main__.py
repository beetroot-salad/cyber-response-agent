"""The deployed worker (#1344 O15, D8): `python -m defender.worker`.

Reads `DEFENDER_DATABASE_DSN`, `DEFENDER_DATA_ROOT`, `DEFENDER_BUILD_COMMIT`, `DEFENDER_WORKER_SLOTS`
(default 3), `DEFENDER_WORKER_LEARNING_SLOTS` (default min(1, slots - 1)) and
`DEFENDER_WORKER_LEARNING_CHECK_SECONDS` (default 300: how long a tenant goes without a post-step
before a family-less one checks it, #1344 amendment 1). Refuses a build stamp that is not a
commit (empty, a tag, a branch name: the marker reader's grammar), bad settings and a job network
(`DEFENDER_JOB_NETWORK`) that is not a bridge network made for the jobs before any work, refuses a second worker on the same data root without
touching the first one's code copy, replaces the code copy, runs every child from it, and serves
until SIGTERM or SIGINT (exit 0). A refusal is a nonzero exit naming its cause on stderr."""
from __future__ import annotations

import asyncio
import datetime as _dt
import functools
import logging
import os
import sys
from pathlib import Path

from defender import _log
from defender.box import run_docker
from defender.jobs import JobStore
from defender.tenancy import data_root_from_path

from ._start import WorkerStartRefused, check_job_network, hold_start_lock, read_settings, refresh_code_copy
from ._worker import Worker, job_entry_argv, post_step_argv, run_argv_in

_logger = logging.getLogger(__name__)

#: The code tree this worker runs from: the parent of its `defender/`.
_SOURCE = Path(__file__).resolve().parents[2]


#: The store's and the worker's clock.
_CLOCK = functools.partial(_dt.datetime.now, _dt.UTC)


async def _serve_until_stopped(settings, copy: Path) -> None:  # noqa: ANN001 — `_start.Settings`
    store = JobStore(settings.dsn, clock=_CLOCK)
    try:
        worker = Worker(
            store, data_root=data_root_from_path(settings.root), child_argv=run_argv_in(copy),
            slots=settings.slots, clock=_CLOCK, learning_slots=settings.learning_slots,
            learning_argv=job_entry_argv, post_step_argv=post_step_argv, child_cwd=copy,
            learning_check_interval=float(settings.learning_check_seconds))
        _logger.info("the worker serves build %s: %d slot(s), %d for learning, children from %s",
                     settings.build_commit, settings.slots, settings.learning_slots, copy)
        await worker.serve()
    finally:
        await store.close()


def main() -> int:
    try:
        settings = read_settings(os.environ)
        check_job_network(os.environ, run_docker)
        lock = hold_start_lock(settings.root)
        copy = refresh_code_copy(settings.root, source=_SOURCE, environ=os.environ)
    except WorkerStartRefused as refused:
        print(f"defender.worker: refused to start: {refused}", file=sys.stderr)
        return 2
    # Children run from the copy and only from it: no other tree on their path, and no bytecode
    # written into it (its read-only bits do not bind root).
    os.environ.pop("PYTHONPATH", None)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        asyncio.run(_serve_until_stopped(settings, copy))
    finally:
        os.close(lock)
    _logger.info("the worker stopped")
    return 0


if __name__ == "__main__":
    _log.configure_from_env()
    sys.exit(main())
