"""A learning job's post-step (#1344 O8, O14), in its job container (#1170): `python -m
defender.learning.branch.post_step [--job <id>] --tenant <T>`, started by the per-job host helper once a job that started
a family step has ended, whatever its status. Without `--job` it is a family-less post-step (#1344
amendment 1): the worker's check of a tenant whose last post-step left work waiting (amendment 3), so
a reviewer's verdict, a retained delivery, findings at threshold or stranded `pending` findings are not left waiting for the
tenant's next alert. It does the same work; only its record's name differs.

It publishes the findings every pending job of the tenant holds in its episode (the jobs the worker
handed it in `<runs>/<key>.post-step-pending.json`, `JobLane.read_post_step_pending`: the tenant's
`completed` jobs whose findings are not yet published, its own included, so a job whose own post-step
was lost is published by the next; a file, so their number never limits the start), then runs the drain's own gate (threshold and retained
deliveries), even with nothing to publish. Its record (`<runs>/<key>.post-step.json`, the key the job
lane's `post_step_key` names: the job's id, or the tenant's own id without `--job`) tells the worker
which jobs were published and which were refused, and is written before the gate runs, so a gate that
fails cannot make it lie. Once the gate has ended it is written again saying `waiting: false` when the
gate would now find nothing to do (`drains.author_work_waiting`, the gate's own test); a record
without that says work may still wait, and the worker keeps the tenant's check clock running:

- published: every held row reached the queues (or the episode held none: a verdict that graded
  nothing). A republish adds nothing (`finding_id` dedup reads the queue and the consumed ledger).
- refused: a held row fails validation, or the job's episode is gone or its id is not one (nothing
  will bring it back); the job is never retried.
- neither: anything else (the queue cannot be written, the episode cannot be read). The job stays
  pending and the next post-step retries it.

Inside the container it takes no host lock, runs no admission and opens no database: the helper holds the tenant's
lock and admitted it before the container started (P-C). The tenant is accepted by the folder rules alone; the drain's
publish and draft (`batch.start`), its forge tokens (`forge.token`) and its publish outcomes (`record.*`) are the
helper's, asked over the job socket (`container.JobContainer`). With no job socket (a host shell) it does nothing and
exits non-zero (A6). The first SIGTERM is a `KeyboardInterrupt`, so the gate unwinds and anything it started is
terminated; the end of its stdin (the helper's end of the container, A5) is that SIGTERM.
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import signal
import sys
import threading
from collections.abc import Callable, Mapping
from typing import Any

from defender import tenancy
from defender._paths import process_defender_dir
from defender.learning.branch.container import JobContainer, NotInContainer, sigterm_on_stdin_eof
from defender.records.formats import EpisodeRefused, TenantRefused
from defender.records.job_lane import JobLane, JobLaneRefused, PostStepRecord

_logger = logging.getLogger(__name__)

__all__ = ["main", "parse_post_step_args"]


def parse_post_step_args(argv: list[str]) -> argparse.Namespace:
    """`[--job <id>] --tenant <T>`; no `--job` is a family-less post-step (`job` None). A `--parent-pid` (the host
    entry's, retired) is accepted and not read: inside the container the death tie is the stdin's end (A5)."""
    p = argparse.ArgumentParser(prog="python -m defender.learning.branch.post_step",
                                description="A learning job's post-step, run in its job container.")
    p.add_argument("--job", default=None,
                   help="the job whose post-step this is; left out, the worker's family-less check of the tenant")
    p.add_argument("--tenant", required=True, help="the jobs' tenant")
    p.add_argument("--parent-pid", default=None, type=int, help=argparse.SUPPRESS)
    return p.parse_args(argv)


def _interrupt(_signum: int, _frame: Any) -> None:
    """The first SIGTERM is a `KeyboardInterrupt`; every later one is ignored, so the unwind it
    starts is not itself interrupted."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise KeyboardInterrupt


def _default_tick(paths: Any) -> int:
    """The lessons drain's tick; inside the job container it finds the helper by the job socket itself
    (`JobContainer.in_environ`)."""
    from defender.learning.core import drains

    return drains.author_drain(paths)


def _default_waiting(paths: Any) -> bool:
    from defender.learning.core.drains import author_work_waiting

    return author_work_waiting(paths)


def main(argv: list[str], *, author_tick: Callable[..., int] | None = None,  # noqa: PLR0913 — the entry's seams
         directory: Any = None, still_waiting: Callable[..., bool] | None = None,
         environ: Mapping[str, str] | None = None, watch_stdin: bool = False) -> int:
    """Publish the pending jobs' findings, record the outcome, then run the drain's gate; returns the gate's exit.
    In the job container (`environ`, default this process's) the tenant is accepted by the folder rules alone: the
    helper holds its lock for the whole step. With no job socket in `environ` it exits non-zero having done nothing
    (A6). `directory` is accepted for callers that still pass it and is not read. `watch_stdin` (the process's own
    entry point): the end of stdin is a SIGTERM (A5)."""
    del directory
    ns = parse_post_step_args(argv)
    which = f"job {ns.job}" if ns.job is not None else f"tenant {ns.tenant} (no family)"
    try:
        ask = JobContainer.client(environ)
    except NotInContainer as outside:
        sys.exit(f"[post-step] {which}: {outside}; nothing was done")
    on_main = threading.current_thread() is threading.main_thread()
    previous = signal.signal(signal.SIGTERM, _interrupt) if on_main else None
    try:
        if watch_stdin:
            sigterm_on_stdin_eof()
        try:
            JobContainer.connect(ask, tenant=ns.tenant)  # the helper's launch facts name this tenant
            data_root = tenancy.resolve_data_root()
            tenant = tenancy.accept_tenant(data_root, ns.tenant, defender_dir=process_defender_dir())
            lane = JobLane.open(data_root, ns.tenant, make=True)
        except (TenantRefused, JobLaneRefused, OSError, ValueError) as unusable:
            sys.exit(f"[post-step] {which}: the tenant cannot be used: {unusable}")
        with lane:
            tick = author_tick if author_tick is not None else _default_tick
            return _post_step(ns, which, tenant, lane, author_tick=tick,
                              still_waiting=still_waiting if still_waiting is not None else _default_waiting)
    finally:
        if on_main:
            signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)


def _post_step(ns: argparse.Namespace, which: str, tenant: Any, lane: JobLane, *,
               author_tick: Callable[..., int], still_waiting: Callable[..., bool]) -> int:
    from defender.learning.core.config import LoopPaths

    paths = LoopPaths.for_tenant(tenant)
    handed = lane.read_post_step_pending(ns.job)
    if handed is None:
        _logger.warning(f"post-step of {which}: no readable list of pending jobs was handed to it; "
                        "it publishes none, and they stay pending")
    published, refused = _publish_pending(tenant, paths, list(dict.fromkeys(handed or ())))
    # Written before the gate, so a gate that fails still leaves what was published; then again
    # with whether the gate would still find work (amendment 3), which only its end can say.
    lane.write_post_step(ns.job, PostStepRecord.of(published, refused))
    _logger.info(f"post-step of {which}: published {len(published)} job(s), refused {len(refused)}")
    exit_code = author_tick(paths)
    try:
        waiting = still_waiting(paths)
    except Exception:  # noqa: BLE001 — an unknown answer keeps the tenant's checks running
        _logger.warning(f"post-step of {which}: could not tell whether work is still waiting", exc_info=True)
        return exit_code
    if not waiting:
        lane.write_post_step(ns.job, PostStepRecord.of(published, refused, waiting=False))
        _logger.info(f"post-step of {which}: nothing is left waiting for the gate")
    return exit_code


def _publish_pending(tenant: Any, paths: Any, pending: list[str]) -> tuple[list[str], list[str]]:
    """Each pending job's episode, published through the tenant's learning state: the jobs
    published, and those refused for good. A job that is neither stays pending."""
    from defender.learning.core.state import LearningState, StateRefused
    from defender.learning.judge.enqueue import FindingsRefused, publish_episode_findings

    published: list[str] = []
    refused: list[str] = []
    if not pending:
        return published, refused
    runs = tenant.runs_repository()
    with contextlib.ExitStack() as held:
        try:
            state = held.enter_context(LearningState.open(paths))
        except (Exception, StateRefused) as unopened:  # noqa: BLE001 — every job stays pending, retried by the next post-step
            _logger.warning(f"the tenant's learning state cannot be opened ({unopened!r}); "
                            "every pending job stays pending")
            return published, refused
        for job_id in pending:
            try:
                handle = runs.episode_files(job_id)
            except (FileNotFoundError, EpisodeRefused) as gone:
                _logger.warning(f"job {job_id}: its episode is gone or its id is not one ({type(gone).__name__}); "
                                "its findings are refused for good")
                refused.append(job_id)
                continue
            except (Exception, StateRefused) as failed:  # noqa: BLE001 — anything else leaves the job pending, retried later
                _logger.warning(f"job {job_id}: its episode could not be opened now ({failed!r}); it stays pending")
                continue
            try:
                with handle as episode:
                    publish_episode_findings(episode, state=state)
            except FindingsRefused as bad:
                _logger.warning(f"job {job_id}: its findings are refused for good ({bad})")
                refused.append(job_id)
                continue
            except (Exception, StateRefused) as failed:  # noqa: BLE001 — anything else leaves the job pending, retried later
                _logger.warning(f"job {job_id}: its findings could not be published now ({failed!r}); "
                                "it stays pending")
                continue
            published.append(job_id)
    return published, refused


if __name__ == "__main__":
    from defender import _log

    _log.configure_from_env()
    sys.exit(main(sys.argv[1:], watch_stdin=True))
