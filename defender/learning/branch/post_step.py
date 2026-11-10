"""A learning job's post-step (#1344 O8, O14): `python -m defender.learning.branch.post_step [--job <id>]
--tenant <T> --parent-pid <pid>`, the worker's child once a job that started a
family step has ended, whatever its status. Without `--job` it is a family-less post-step (#1344
amendment 1): the worker's check of a tenant whose last post-step left work waiting (amendment 3), so
a reviewer's verdict, a retained delivery, findings at threshold or stranded `pending` findings are not left waiting for the
tenant's next alert. It does the same work; only its record's name differs.

It publishes the findings every pending job of the tenant holds in its episode (the jobs the worker
handed it in `<runs>/<key>.post-step-pending.json`, `JobLane.read_post_step_pending`: the tenant's
`completed` jobs whose findings are not yet published, its own included, so a job whose own post-step
was lost is published by the next; a file, so their number never limits the start) into the learning
store at the host's database address (#1278), then runs the drain's own gate, even with nothing to
publish. Its record (`<runs>/<key>.post-step.json`, the key the job lane's `post_step_key` names: the
job's id, or the tenant's own id without `--job`) tells the worker which jobs were published and which
were refused, and is written before the gate runs, so a gate that fails cannot make it lie. Once the
gate has ended it is written again saying `waiting: false` when the store holds nothing this post-step
could act on (#1278 "Wake", amending #1344 O8): no batch of any lane is still to be ended (G-T1: its
lease may lapse and its PR change, so the tenant's checks go on; the post-step reconciles every lane),
and the author drain's gate would find nothing to do (`drains.author_work_waiting`, the gate's own
test: lead-lane items alone are no work of a post-step, D9). A record without it says work may still
wait, and the worker keeps the tenant's check clock running:

- published: every held row reached the store (or the episode held none: a verdict that graded
  nothing). A republish adds nothing (a finding id is the store's for good).
- refused: a held row fails validation (a NUL character included: the store can never hold one), or
  the job's episode is gone or its id is not one (nothing will bring it back); the job is never
  retried.
- neither: anything else (the store cannot be reached, the tenant is not active, the episode cannot
  be read). The job stays pending and the next post-step retries it.

Tied to its worker like the family step; the first SIGTERM is a `KeyboardInterrupt`, so the gate
unwinds and anything it started is terminated.
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import os
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


def _store_dsn() -> str:
    """The learning store's address: the host's database address, as the tenant records'. Unset is
    `RuntimeError`, which every caller here meets as "not now"."""
    variable = tenancy.database_address_variable()
    dsn = os.environ.get(variable, "")
    if not dsn:
        raise RuntimeError(f"{variable} is not set: the learning store cannot be reached")
    return dsn


def _default_waiting(paths: Any, *, tenant_id: str) -> bool:
    """Whether the store holds work this post-step could act on (Wake): a batch of any lane not yet
    ended, or what opens the author drain's gate."""
    from defender.learning.core.drains import author_work_waiting
    from defender.learning.store import blocking

    with blocking(_store_dsn()) as store:
        if any(batch.phase != "ended" for batch in store.batches(tenant_id)):
            return True
    return author_work_waiting(paths)


def main(argv: list[str], *, author_tick: Callable[..., int] | None = None,
         directory: Any = None, still_waiting: Callable[..., bool] | None = None) -> int:
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
                              author_tick=author_tick if author_tick is not None else _default_tick,
                              still_waiting=still_waiting if still_waiting is not None else _default_waiting)
    finally:
        signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)


def _post_step(ns: argparse.Namespace, which: str, tenant: Any, lane: JobLane, *,
               author_tick: Callable[..., int], still_waiting: Callable[..., bool]) -> int:
    from defender.learning.core.config import LoopPaths

    paths = LoopPaths.for_tenant(tenant)
    handed = lane.read_post_step_pending(ns.job)
    if handed is None:
        _logger.warning(f"post-step of {which}: no readable list of pending jobs was handed to it; "
                        "it publishes none, and they stay pending")
    published, refused = _publish_pending(tenant, list(dict.fromkeys(handed or ())))
    # Written before the gate, so a gate that fails still leaves what was published; then again
    # with whether the gate would still find work (amendment 3), which only its end can say.
    lane.write_post_step(ns.job, PostStepRecord.of(published, refused))
    _logger.info(f"post-step of {which}: published {len(published)} job(s), refused {len(refused)}")
    exit_code = author_tick(paths)
    try:
        waiting = still_waiting(paths, tenant_id=str(tenant.id))
    except Exception:  # noqa: BLE001 — an unknown answer keeps the tenant's checks running
        _logger.warning(f"post-step of {which}: could not tell whether work is still waiting", exc_info=True)
        return exit_code
    if not waiting:
        lane.write_post_step(ns.job, PostStepRecord.of(published, refused, waiting=False))
        _logger.info(f"post-step of {which}: nothing is left waiting for the gate")
    return exit_code


def _publish_pending(tenant: Any, pending: list[str]) -> tuple[list[str], list[str]]:
    """Each pending job's episode, published into the learning store for the tenant: the jobs
    published, and those refused for good. A job that is neither stays pending."""
    from defender.learning.judge.enqueue import FindingsRefused, publish_episode_findings
    from defender.learning.store import TenantInactive, blocking

    published: list[str] = []
    refused: list[str] = []
    if not pending:
        return published, refused
    runs = tenant.runs_repository()
    with contextlib.ExitStack() as held:
        try:
            store = held.enter_context(blocking(_store_dsn()))
        except Exception as unopened:  # noqa: BLE001 — every job stays pending, retried by the next post-step
            _logger.warning(f"the learning store cannot be opened ({unopened!r}); every pending job stays pending")
            return published, refused
        for job_id in pending:
            try:
                handle = runs.episode_files(job_id)
            except (FileNotFoundError, EpisodeRefused) as gone:
                _logger.warning(f"job {job_id}: its episode is gone or its id is not one ({type(gone).__name__}); "
                                "its findings are refused for good")
                refused.append(job_id)
                continue
            except Exception as failed:  # noqa: BLE001 — anything else leaves the job pending, retried later
                _logger.warning(f"job {job_id}: its episode could not be opened now ({failed!r}); it stays pending")
                continue
            try:
                with handle as episode:
                    publish_episode_findings(episode, store=store, tenant_id=str(tenant.id))
            except FindingsRefused as bad:
                _logger.warning(f"job {job_id}: its findings are refused for good ({bad})")
                refused.append(job_id)
                continue
            except TenantInactive:
                # Offboarding moved the tenant off active: no new findings (O6). Nothing is lost by
                # leaving the job pending; offboarding ends the tenant's learning rows.
                _logger.warning(f"job {job_id}: the tenant is not active, so the store takes no findings; "
                                "it stays pending")
                continue
            except Exception as failed:  # noqa: BLE001 — anything else leaves the job pending, retried later
                _logger.warning(f"job {job_id}: its findings could not be published now ({failed!r}); "
                                "it stays pending")
                continue
            published.append(job_id)
    return published, refused


if __name__ == "__main__":
    from defender import _log

    _log.configure_from_env()
    sys.exit(main(sys.argv[1:]))
