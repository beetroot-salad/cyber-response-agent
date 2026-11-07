"""A learning job's family step (#1344): `python -m defender.learning.branch.job_entry --job <id>
--tenant <T> --source <investigation id> --parent-pid <pid>`, the worker's child.

The entry ties itself to its worker, opens the tenant's runs container (the job lane's door),
installs its own SIGTERM handler, waits a bounded time for the tenant's host lock, then runs the
launcher's job lane (`cli.launch_job`): the fork pick (O3), the questioner, pre-flight, the
siblings one at a time with the control first (O4), verification and the judge's job-lane pass.
It writes two host-held records the worker copies (`records.job_lane`): the progress record
(fork, stage, sibling cost), replaced whole as each changes, and the create-only end record,
written at every exit with the outcome table's status and reason.

**The ending.** A reason is never read from message text: every ending the outcome table gives
the entry is raised typed where it is decided (`endings.JobEnding`), and anything else is
`failed: entry_error`, its message naming only the exception's type. Messages are our own words
and carry no run text, path or secret.

**Stopping.** The first SIGTERM raises `JobStopped` where the entry is (every later one is
ignored), so the launcher unwinds and terminates the sibling it runs; the job records `stopped`,
a hand-back. Two endings are decided before that and stand whatever signal arrives: a job with
no fork point (`skipped: no_fork_point`), and a judge pass that returned (`completed`). The
tenant's host lock still busy after the entry's wait is also a hand-back.
"""
from __future__ import annotations

import argparse
import logging
import math
import os
import signal
import sys
import threading
from collections.abc import Callable, Sequence
from typing import Any

from defender import tenancy
from defender._parent_tie import require_parent, tie_to_parent
from defender.investigation import branch
from defender.learning.branch import cli
from defender.learning.branch.endings import (
    ENTRY_ERROR,
    HISTORY_UNREADABLE,
    NO_FORK_POINT,
    SOURCE_UNAVAILABLE,
    JobEnding,
    JobLaneHooks,
    ending,
)
from defender.learning.branch.fork_pick import fork_candidates, pick_fork
from defender.records import EpisodeRuns, Run, RunRefused, session_store
from defender.records.formats import TenantRefused
from defender.records.job_lane import (
    LEARNING_COMPLETED,
    LEARNING_FAILED,
    LEARNING_SKIPPED,
    LEARNING_STOPPED,
    CostUnreadable,
    JobLane,
    JobLaneRefused,
    LearningEnd,
    LearningProgress,
    sibling_cost,
)
from defender.tenancy import host_lock

_logger = logging.getLogger(__name__)

__all__ = ["JobStopped", "main", "role_preflight"]

#: How long the entry waits for the tenant's host lock (held exclusive by prepare or teardown)
#: before handing the job back.
HOST_LOCK_WAIT_SECONDS = 30.0


class JobStopped(BaseException):
    """The entry's first SIGTERM, raised where the entry was. A `BaseException`, so no broad
    `except Exception` on the way out swallows the stop."""


def parse_learning_job_args(argv: list[str]) -> argparse.Namespace:
    """`--job <id> --tenant <T> --source <investigation id> --parent-pid <pid>`."""
    p = argparse.ArgumentParser(prog="python -m defender.learning.branch.job_entry",
                                description="A learning job's family step, run by the worker.")
    p.add_argument("--job", required=True, help="the learning job's id; the episode's id too")
    p.add_argument("--tenant", required=True, help="the job's tenant")
    p.add_argument("--source", required=True, help="the finished investigation to fork, by its id")
    p.add_argument("--parent-pid", required=True, type=int, help="the worker that started this process")
    return p.parse_args(argv)


def role_preflight(model: str | None = None, *, branching: bool = True) -> int:
    """The family step's own paid roles (questioner, oracle and its verifier, judge): each one's
    model resolves to a provider whose key is usable, and each oracle role's effort is one its
    provider takes. Each provider's first-party key is sourced as a run sources it. 0 when every
    role can be paid for, else 2; the siblings, `run.py` processes, check their own roles."""
    from defender import providers
    from defender._agent_role import AgentRole
    from defender._first_party_key import resolve_first_party_key
    from defender.learning.core import config
    from defender.learning.roles import LEARNING_AGENTS

    del model, branching  # the family's roles keep their own models
    efforts = {AgentRole.ORACLE: config.oracle_effort, AgentRole.ORACLE_CHECK: config.oracle_check_effort}
    seen: set[str] = set()
    for role in (AgentRole.QUESTIONER, AgentRole.ORACLE, AgentRole.ORACLE_CHECK, AgentRole.JUDGE):
        defn = LEARNING_AGENTS.get(role)
        if defn is None:
            _logger.error(f"preflight: the learning role {role.name} has no agent definition")
            return 2
        try:
            name = str(defn.model())
            provider = providers.provider_for(name)
            if role in efforts:
                provider.settings_for_effort(efforts[role]())
        except Exception as bad:  # noqa: BLE001 — a broken model config is a preflight refusal
            _logger.error(f"preflight: {role.name}'s model config is unusable: {bad!r}")
            return 2
        if provider.id in seen:
            continue
        seen.add(provider.id)
        key, _found_at = resolve_first_party_key(var=provider.api_key_var)
        if key:
            os.environ[provider.api_key_var] = key
        elif not os.environ.get(provider.api_key_var):
            _logger.error(f"preflight: {role.name} runs on {provider.id}, and no "
                          f"{provider.api_key_var} is set")
            return 2
    return 0


class _Job:
    """One job's records and its ending: what the hooks learn, the SIGTERM handler, and the end
    record written once, whatever ends the entry."""

    def __init__(self, lane: JobLane, job_id: str) -> None:
        self.lane, self.job_id = lane, job_id
        self.fork: str | None = None
        self.stage: str | None = None
        self.cost = 0.0
        self.findings = 0
        #: An ending decided before the entry ends, which no later signal overrides: the job's
        #: `no_fork_point`, or `completed` once the judge's pass returned.
        self.decided: LearningEnd | None = None
        self.stopped = False

    # -- the SIGTERM handler ---------------------------------------------------------------

    def on_term(self, _signum: int, _frame: Any) -> None:
        """The first SIGTERM stops the job unless its ending is decided; every later one is
        ignored, so the unwind (and the sibling's termination) is not itself interrupted."""
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if self.decided is not None:
            return
        self.stopped = True
        raise JobStopped

    # -- the progress record ---------------------------------------------------------------

    def progress(self) -> None:
        """Replace the progress record. A write that fails raises: the pick must be durable
        before any spend (O3), so the entry ends `failed: entry_error` there."""
        self.lane.write_learning_progress(
            self.job_id, LearningProgress(self.fork, self.stage, self.cost))

    def at_stage(self, name: str) -> None:
        self.stage = str(name)
        self.progress()

    # -- the hooks ---------------------------------------------------------------------------

    def pick(self, source: Run, candidates: Callable[..., Any]) -> int:
        """The fork pick (O3): the source's admitted gather responses, one chosen uniformly and
        recorded before any spend; none is the decided `skipped: no_fork_point`."""
        found = _candidates_of(source, candidates)
        ids = list(found.ids)
        if not ids:
            kinds = _refusal_kinds(found)
            brief = ("the source investigation has no fork point: no response of its main agent "
                     "that called gather is admitted"
                     + (f" (refused: {'; '.join(kinds)})" if kinds else ""))
            self.decided = self._end(LEARNING_SKIPPED, NO_FORK_POINT, brief)
            raise ending(f"[learning job] {brief}", reason=NO_FORK_POINT, brief=brief)
        picked = pick_fork(ids)
        self.fork = str(picked)
        self.progress()
        return picked

    def sibling_ended(self, view: EpisodeRuns, world_ids: Sequence[str]) -> None:
        """What the siblings that have run cost so far, carried to the progress record."""
        try:
            cost = _family_cost(view, world_ids)
        except Exception as unreadable:  # noqa: BLE001 — a cost the entry cannot read keeps the last one
            _logger.warning(f"job {self.job_id}: the siblings' cost could not be read ({unreadable!r})")
        else:
            if math.isfinite(cost) and cost >= 0:
                self.cost = cost
            else:
                _logger.warning(f"job {self.job_id}: the siblings' cost read as {cost!r}, which is no cost")
        self.progress()

    def judged(self, graded: Any, count: Callable[[], int]) -> None:
        """The judge's pass returned: the ending is `completed`, decided here, before anything
        else (from now on a SIGTERM is ignored). `count()` then reads how many findings the pass
        left in the episode, for the record; a count that fails leaves 0, and the ending stands."""
        not_graded = getattr(graded, "not_graded", None)
        word = None if not_graded is None else getattr(not_graded, "outcome", None)
        self.decided = self._end(LEARNING_COMPLETED, None, _judged_message(word, None))
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            self.findings = count()
        except Exception as unreadable:  # noqa: BLE001 — the count is the record's, the ending stands
            _logger.warning(f"job {self.job_id}: the findings could not be counted ({unreadable!r})")
            return
        self.decided = self._end(LEARNING_COMPLETED, None, _judged_message(word, self.findings))

    # -- the end record ----------------------------------------------------------------------

    def _end(self, status: str, reason: str | None, message: str | None) -> LearningEnd:
        cost = self.cost if math.isfinite(self.cost) and self.cost >= 0 else 0.0
        return LearningEnd(status=status, reason=reason, message=message, fork_message_id=self.fork,
                           stage=self.stage, findings_count=self.findings, sibling_cost_usd=cost)

    def ending_for(self, raised: BaseException | None) -> LearningEnd:
        """The end record for an entry that raised `raised` (`None`: it returned)."""
        if self.decided is not None:
            return self.decided
        if self.stopped or isinstance(raised, JobStopped):
            return self._end(LEARNING_STOPPED, None, "the job was stopped before its judge's pass "
                                                     "returned; it is handed back")
        if isinstance(raised, JobEnding):
            return self._end(raised.status, raised.reason, raised.brief)
        if raised is None:
            return self._end(LEARNING_FAILED, ENTRY_ERROR, "the launch returned without a judge's pass")
        return self._end(LEARNING_FAILED, ENTRY_ERROR,
                         f"the family step failed with {type(raised).__name__}")

    def write_end(self, end: LearningEnd) -> bool:
        try:
            self.lane.write_learning_end(self.job_id, end)
        except (OSError, JobLaneRefused) as unwritten:
            _logger.error(f"job {self.job_id}: the end record could not be written ({unwritten!r})")
            return False
        return True


def _refusal_kinds(found: Any) -> list[str]:
    """The kinds of refusal among the dropped candidates (`ForkCandidates.refusal_kinds`), each
    once: fixed names in our own words, never a refusal's text."""
    kinds = getattr(found, "refusal_kinds", None) or ()
    return list(dict.fromkeys(str(kind) for kind in kinds))


def _judged_message(word: str | None, findings: int | None) -> str:
    """The completed job's message: the judge's verdict word when it graded nothing."""
    if word is not None:
        return f"the judge graded nothing: the family is {word}"
    if findings is None:
        return "the judge graded the family"
    return f"the judge graded the family: {findings} finding(s) wait in the episode"


def _candidates_of(source: Run, candidates: Callable[..., Any]) -> Any:
    """`candidates(store, source)` over the source's own session store, opened here.

    A source whose session pointer is absent is a run recorded before #1235 (its link still
    inside the folder: `LegacyRunLink`, `skipped: history_unreadable`) or one whose store is gone
    (`failed: source_unavailable`), as is a pointer naming a database that is not there. Only a
    typed format refusal (`session_store.StoreError`) is `history_unreadable`, its message naming
    the refusal's type; anything else propagates, and the entry records `failed: entry_error`."""
    if source.observability.session_pointer.read_result().absent:
        try:
            session_store.refuse_legacy_link(source.run_dir)
        except session_store.StoreError as unreadable:
            raise _history_unreadable(unreadable) from unreadable
        brief = "the source run carries no session store, so it has no fork point to read"
        raise ending(f"[learning job] {brief}", reason=SOURCE_UNAVAILABLE, brief=brief)
    try:
        database = session_store.resolve_store_path(source)
    except session_store.StoreError as unreadable:
        raise _history_unreadable(unreadable) from unreadable
    if not database.is_file():
        brief = "the source run's session database is gone"
        raise ending(f"[learning job] {brief}", reason=SOURCE_UNAVAILABLE, brief=brief)
    try:
        opened = branch.source_store_if_any(source.run_dir, source_run=source)
        if opened is None:
            brief = "the source run's session pointer is gone"
            raise ending(f"[learning job] {brief}", reason=SOURCE_UNAVAILABLE, brief=brief)
        with opened as store:
            return candidates(store, source)
    except session_store.StoreError as unreadable:
        raise _history_unreadable(unreadable) from unreadable


def _history_unreadable(refusal: BaseException) -> JobEnding:
    """`skipped: history_unreadable` for a typed format refusal, its message naming the type."""
    brief = (f"the source run's session history cannot be read by current code "
             f"({type(refusal).__name__})")
    return ending(f"[learning job] {brief}", reason=HISTORY_UNREADABLE, brief=brief, cause=refusal)


def _family_cost(view: EpisodeRuns, world_ids: Sequence[str]) -> float:
    """What the siblings of `world_ids` have cost: each one's own session in the shared
    database and every session forked from it (`records.job_lane.sibling_cost`). A sibling with
    no session pointer, or none naming its own session, spent nothing that can be read yet."""
    ids = view.arm_ids()
    if ids is None:
        raise CostUnreadable("the episode's arm roster is gone")
    arms = [ids[world_id] for world_id in world_ids if world_id in ids]
    total = 0.0
    with view.arms(arms) as handout:
        for arm_id in arms:
            arm = handout[arm_id]
            if isinstance(arm, RunRefused):
                continue
            try:
                session_id = session_store.resolve_session_id(arm)
                database = session_store.resolve_store_path(arm)
            except (FileNotFoundError, session_store.LegacyRunLink):
                continue  # a world that never recorded a session spent nothing
            if session_id is None or not database.is_file():
                continue
            with session_store.open_store_for_read(database) as store:
                total += sibling_cost(store, session_id)
    return total


def main(  # noqa: PLR0913 — the entry's inputs plus the launcher's seams
    argv: list[str], *,
    candidates: Callable[..., Any] = fork_candidates,
    grade: Callable[..., Any] | None = None,
    preflight: Callable[..., int] = role_preflight,
    **seams: Any,
) -> int:
    """The learning job's family step; returns 0 unless the job ended `failed` (1). The worker
    reads the end record, never this exit."""
    ns = parse_learning_job_args(argv)
    tie_to_parent()
    require_parent(ns.parent_pid, who="learning job")
    try:
        data_root = tenancy.resolve_data_root()
        lane = JobLane.open(data_root, ns.tenant)
    except (TenantRefused, JobLaneRefused) as refused:
        sys.exit(f"[learning job] job {ns.job}: the job lane cannot be opened: {refused}")
    with lane:
        job = _Job(lane, ns.job)
        previous = signal.signal(signal.SIGTERM, job.on_term)
        raised: BaseException | None = None
        try:
            _run(job, ns, data_root, candidates=candidates, grade=grade, preflight=preflight, **seams)
        except BaseException as caught:  # noqa: BLE001 — every exit is recorded, then decided below
            raised = caught
        finally:
            # No signal interrupts the record: from here a SIGTERM is ignored.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        end = job.ending_for(raised)
        if raised is not None and not isinstance(raised, (JobEnding, JobStopped)):
            _logger.error(f"job {ns.job}: the family step raised", exc_info=raised)
        written = job.write_end(end)
        signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)
    if not written:
        return 1
    return 1 if end.status == LEARNING_FAILED else 0


def _run(job: _Job, ns: argparse.Namespace, data_root: Any, *, candidates: Callable[..., Any],
         grade: Callable[..., Any] | None, preflight: Callable[..., int], **seams: Any) -> None:
    """The tenant's host lock within a bounded wait (a hand-back when still busy), then the
    launcher's job lane, its hooks reporting to `job`."""
    job.at_stage("waiting for the tenant")
    held = host_lock.acquire(tenancy.data_root_for_child(data_root), ns.tenant, exclusive=False,
                             timeout=HOST_LOCK_WAIT_SECONDS)
    if held is None:
        job.decided = job._end(
            LEARNING_STOPPED, None, f"the tenant's host lock was still held after "
                                    f"{HOST_LOCK_WAIT_SECONDS:.0f} s; the job is handed back")
        return
    try:
        hooks = JobLaneHooks(
            job_id=ns.job, pick=lambda source: job.pick(source, candidates), stage=job.at_stage,
            sibling_ended=job.sibling_ended, judged=job.judged, grade=grade)
        cli.launch_job(tenant=ns.tenant, source_run_id=ns.source, lane=hooks, preflight=preflight,
                       **seams)
    finally:
        host_lock.release_lock(held)


if __name__ == "__main__":
    from defender import _log

    _log.configure_from_env()
    sys.exit(main(sys.argv[1:]))
