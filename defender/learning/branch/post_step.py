"""A learning job's post-step (#1344 O8, O14): `python -m defender.learning.branch.post_step [--job <id>]
--tenant <T> --parent-pid <pid>`, the worker's child once a job that started a
family step has ended, whatever its status. Without `--job` it is a family-less post-step (#1344
amendment 1): the worker's periodic check of a tenant no family has followed for a while, so a
reviewer's verdict, a retained delivery, findings at threshold or stranded `pending` findings are not
left waiting for the tenant's next alert. It does the same work; only its record's name differs.

It publishes the findings every pending job of the tenant holds in its episode (the jobs the worker
handed it in `<runs>/<key>.post-step-pending.json`, `JobLane.read_post_step_pending`: the tenant's
`completed` jobs whose findings are not yet published, its own included, so a job whose own post-step
was lost is published by the next; a file, so their number never limits the start), then runs the drain's own gate (threshold and retained
deliveries), even with nothing to publish. Its record (`<runs>/<key>.post-step.json`, the key the job
lane's `post_step_key` names: the job's id, or the tenant's own id without `--job`) tells the worker
which jobs were published and which were refused, and is written before the gate runs, so a gate that
fails cannot make it lie:

- published: every held row reached the queues (or the episode held none: a verdict that graded
  nothing). A republish adds nothing (`finding_id` dedup reads the queue and the consumed ledger).
- refused: a held row fails validation, or the job's episode is gone or its id is not one (nothing
  will bring it back); the job is never retried.
- neither: anything else (the queue cannot be written, the episode cannot be read). The job stays
  pending and the next post-step retries it.

Tied to its worker like the family step; the first SIGTERM is a `KeyboardInterrupt`, so the gate
unwinds and anything it started is terminated.
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import signal
import sys
from collections.abc import Callable
from typing import Any

from defender import tenancy
from defender._parent_tie import require_parent, tie_to_parent
from defender.records.formats import EpisodeRefused, TenantRefused
from defender.records.job_lane import JobLane, JobLaneRefused, PostStepRecord

_logger = logging.getLogger(__name__)

__all__ = ["main", "parse_post_step_args"]


def parse_post_step_args(argv: list[str]) -> argparse.Namespace:
    """`[--job <id>] --tenant <T> --parent-pid <pid>`; no `--job` is a family-less post-step
    (`job` None)."""
    p = argparse.ArgumentParser(prog="python -m defender.learning.branch.post_step",
                                description="A learning job's post-step, run by the worker.")
    p.add_argument("--job", default=None,
                   help="the job whose post-step this is; left out, the worker's family-less check of the tenant")
    p.add_argument("--tenant", required=True, help="the jobs' tenant")
    p.add_argument("--parent-pid", required=True, type=int, help="the worker that started this process")
    return p.parse_args(argv)


def _interrupt(_signum: int, _frame: Any) -> None:
    """The first SIGTERM is a `KeyboardInterrupt`; every later one is ignored, so the unwind it
    starts is not itself interrupted."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise KeyboardInterrupt


def _default_tick(paths: Any) -> int:
    from defender.learning.core.drains import author_drain

    return author_drain(paths)


def main(argv: list[str], *, author_tick: Callable[..., int] | None = None,
         directory: Any = None) -> int:
    """Publish the pending jobs' findings, record the outcome, then run the drain's gate;
    returns the gate's exit. The tenant is accepted here, by the host acceptance (the command
    function of an entry module owns the scope), and held for the whole step."""
    from defender.systems import run_tenant

    ns = parse_post_step_args(argv)
    tie_to_parent()
    require_parent(ns.parent_pid, who="learning post-step")
    which = f"job {ns.job}" if ns.job is not None else f"tenant {ns.tenant} (no family)"
    previous = signal.signal(signal.SIGTERM, _interrupt)
    try:
        try:
            data_root = tenancy.resolve_data_root()
            admitted = run_tenant.host_tenant(data_root, ns.tenant, directory=directory)
            lane = JobLane.open(data_root, ns.tenant, make=True)
        except (TenantRefused, JobLaneRefused) as unusable:
            sys.exit(f"[post-step] {which}: the tenant cannot be used: {unusable}")
        with admitted, lane:
            return _post_step(ns, which, admitted.tenant, lane,
                              author_tick=author_tick if author_tick is not None else _default_tick)
    finally:
        signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)


def _post_step(ns: argparse.Namespace, which: str, tenant: Any, lane: JobLane, *,
               author_tick: Callable[..., int]) -> int:
    from defender.learning.core.config import LoopPaths

    paths = LoopPaths.for_tenant(tenant)
    handed = lane.read_post_step_pending(ns.job)
    if handed is None:
        _logger.warning(f"post-step of {which}: no readable list of pending jobs was handed to it; "
                        "it publishes none, and they stay pending")
    published, refused = _publish_pending(tenant, paths, list(dict.fromkeys(handed or ())))
    lane.write_post_step(ns.job, PostStepRecord.of(published, refused))
    _logger.info(f"post-step of {which}: published {len(published)} job(s), refused {len(refused)}")
    return author_tick(paths)


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
    sys.exit(main(sys.argv[1:]))
