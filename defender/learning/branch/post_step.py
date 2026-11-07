"""A learning job's post-step (#1344 O8, O14): `python -m defender.learning.branch.post_step --job <id>
--tenant <T> --pending <job id>... --parent-pid <pid>`, the worker's child once a job that started a
family step has ended, whatever its status.

It publishes the findings every pending job of the tenant holds in its episode (`--pending`: the
tenant's `completed` jobs whose findings are not yet published, its own included, so a job whose own
post-step was lost is published by the next), then runs the drain's own gate (threshold and retained
deliveries), even with nothing to publish. Its record (`<runs>/<job id>.post-step.json`) tells the
worker which jobs were published and which were refused, and is written before the gate runs, so a
gate that fails cannot make it lie:

- published: every held row reached the queues (or the episode held none: a verdict that graded
  nothing). A republish adds nothing (`finding_id` dedup reads the queue and the consumed ledger).
- refused: a held row fails validation; the job is never retried.
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
from defender.records.formats import TenantRefused
from defender.records.job_lane import JobLane, JobLaneRefused, PostStepRecord

_logger = logging.getLogger(__name__)

__all__ = ["main", "parse_post_step_args"]


def parse_post_step_args(argv: list[str]) -> argparse.Namespace:
    """`--job <id> --tenant <T> --pending <job id>... --parent-pid <pid>`."""
    p = argparse.ArgumentParser(prog="python -m defender.learning.branch.post_step",
                                description="A learning job's post-step, run by the worker.")
    p.add_argument("--job", required=True, help="the job whose post-step this is")
    p.add_argument("--tenant", required=True, help="the jobs' tenant")
    p.add_argument("--pending", nargs="*", default=[],
                   help="the tenant's completed jobs whose findings are not yet published")
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


def main(argv: list[str], *, author_tick: Callable[..., int] | None = None) -> int:
    """Publish the pending jobs' findings, record the outcome, then run the drain's gate;
    returns the gate's exit."""
    ns = parse_post_step_args(argv)
    tie_to_parent()
    require_parent(ns.parent_pid, who="learning post-step")
    previous = signal.signal(signal.SIGTERM, _interrupt)
    try:
        return _post_step(ns, author_tick=author_tick if author_tick is not None else _default_tick)
    finally:
        signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)


def _post_step(ns: argparse.Namespace, *, author_tick: Callable[..., int]) -> int:
    from defender.learning.core.config import LoopPaths

    try:
        data_root = tenancy.resolve_data_root()
        tenant = tenancy.requested_tenant(data_root, ns.tenant)
        lane = JobLane.open(data_root, ns.tenant, make=True)
    except (TenantRefused, JobLaneRefused) as unusable:
        sys.exit(f"[post-step] job {ns.job}: the tenant cannot be used: {unusable}")
    paths = LoopPaths.for_tenant(tenant)
    with lane:
        published, refused = _publish_pending(tenant, paths, list(dict.fromkeys(ns.pending)))
        lane.write_post_step(ns.job, PostStepRecord.of(published, refused))
    _logger.info(f"post-step {ns.job}: published {len(published)} job(s), refused {len(refused)}")
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
                with runs.episode_files(job_id) as episode:
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
