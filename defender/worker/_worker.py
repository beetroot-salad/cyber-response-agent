"""The worker (#1342, #1343): claims queued investigations up to its slots, runs each as a child
process through the job lane, keeps each row's lease alive while it holds it, and records how it
ended.

Per claimed row, as a task: a box token is minted for the claim, the tenant's state, read by the
claim itself, must be `active` (#1342 r7 R7-1: no host lock is taken and the worker is recorded as
no holder, so a teardown never waits for it or signals it), the launch record (carrying the token)
and alert file are written beside the run folder (the tenant's runs container must exist; the
worker never makes it), the child is spawned from the event loop's thread in a session of its own
with its output inherited, its exit awaited, a leftover box carrying the claim's token removed
(the backstop), and the job-end record read for the stage. The task owns its child: however the
row ends once the child exists (its exit, a stop, a fence, even mid-spawn), the child's process
group is killed and the backstop runs (r7 D-ac).

A row belongs to the worker that keeps renewing its lease (B-P1) and stays its worker's until the
last write for it lands (B-P2): the one end write (B4) is the terminal stage, or, if someone else
already ended the row, its final cost and knowledge; a deliberate stop ends the children and hands
their rows back (B11). A write that fails as an outage is retried each second and nothing new is
claimed meanwhile (B5).

A database outage ends no child, however long it lasts (T2): a renewal that fails, or outlives
`store_call_limit`, is tried again, and a late renewal revives a row nobody took over. A worker whose
own store calls hit an outage within the last lease takes nothing over: other workers' leases lapsed
in the same outage, and their next renewal has not had its chance.

Learning jobs (#1344) share the slots: a worker with a free slot claims the oldest queued job when
fewer than `learning_slots` learning-class tasks (family steps and post-steps) run, and otherwise
the oldest investigation. A job runs as the job entry's child, with the same death tie, stop and
fence as an investigation; the worker copies the entry's progress record onto the row on its
renewal loop, and decides the row from the end record alone. After a job whose child started, a
post-step child publishes the tenant's `pending` findings and runs the drain gate, in the same
slot and the same supervision registry, with no lease of its own.

A family-less post-step (#1344 amendment 1) wakes a tenant no family has followed for a while: a
worker with learning slots, not stopping, checks each `active` tenant with learning jobs once its
last post-step (or, before any, the worker's start) is `learning_check_interval` old. That check
runs the same child without a job, and so the drain's own gate: a retained delivery, an open batch,
findings at threshold and stranded `pending` findings are each decided there, never by a second
gate here. An overdue check is claimed before a queued job, within the learning slots, so sustained
load cannot starve it."""
from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import logging
import os
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender import _log
from defender.jobs import LearningProgress, is_outage, is_refusal
from defender.jobs.audit import SYSTEM, announce
from defender.box import CLAIM_ENV, Reaped, container_name
from defender.execution import kill_group
from defender.records import job_facts, job_lane
from defender.records.formats import DataRoot, digest_of
from defender.tenancy import data_root_for_child, data_root_from_path

from ._containers import Containers, DockerContainers
from ._held import INVESTIGATION, LEARNING, POST_STEP, End, Ending, Held, LearningOutcome

if TYPE_CHECKING:
    from defender.jobs import Claim, LearningClaim

_logger = logging.getLogger(__name__)

#: How long an idle serving worker waits between claims (M10: a fixed interval, no NOTIFY).
POLL_INTERVAL = 1.0

#: The pause between tries of an end write that failed as an outage (B5).
END_RETRY_DELAY = 1.0

#: How long a tenant goes without a post-step before the worker checks it without a family
#: (#1344 amendment 1), in seconds.
LEARNING_CHECK_INTERVAL = 300.0

_RUN_PY = Path(__file__).resolve().parents[1] / "run.py"
#: The learning children's modules (#1344), started with `-m` from the code tree's root.
JOB_ENTRY_MODULE = "defender.cli.learning.job"
POST_STEP_MODULE = "defender.learning.branch.post_step"

_FAILED, _COMPLETED, _UNPARSEABLE = "failed", "completed", "unparseable"
_SETUP_REFUSED, _NO_REPORT, _WORKER_ERROR = "setup_refused", "no_report", "worker_error"
#: A job entry's end record status that ends nothing: the job is handed back (#1344 r5).
_STOPPED = "stopped"


@dataclass(frozen=True)
class Launch:
    """What a child is started for: the investigation (its id is the run id), its tenant, and
    the worker's pid, which the child checks is its parent."""

    investigation_id: str
    tenant_id: str
    parent_pid: int


@dataclass(frozen=True)
class LearningLaunch:
    """What a learning job's child is started for: the job (its id is the episode id), its
    tenant, the worker's pid, and the investigation whose run it learns from."""

    job_id: str
    tenant_id: str
    parent_pid: int
    source_investigation_id: str


@dataclass(frozen=True)
class PostStepLaunch:
    """What a post-step child is started for: the job it follows (None: a family-less post-step,
    #1344 amendment 1), its tenant, the worker's pid, and the tenant's `completed` jobs whose
    findings wait to be published, its own included."""

    job_id: str | None
    tenant_id: str
    parent_pid: int
    pending_job_ids: tuple[str, ...]


@dataclass(frozen=True)
class _PostStepOf:
    """What a post-step's entry in the supervision registry names: its tenant and the job it
    follows (None: family-less). It holds no row."""

    tenant_id: str
    learning_job_id: str | None


def run_argv(launch: Launch) -> list[str]:
    """The default child: `run.py --job <id> --tenant <T> --parent-pid <pid>`."""
    return run_argv_in(_RUN_PY.parents[1])(launch)


def run_argv_in(root: Path) -> Callable[[Launch], list[str]]:
    """The investigation child of the code tree at `root` (the parent of its `defender/`)."""
    entry = Path(root) / "defender" / "run.py"

    def argv(launch: Launch) -> list[str]:
        return [sys.executable, str(entry), "--job", launch.investigation_id,
                "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]
    return argv


def job_entry_argv(launch: LearningLaunch) -> list[str]:
    """The learning job's child: the job entry as a module, found from the working directory."""
    return [sys.executable, "-m", JOB_ENTRY_MODULE, "--job", launch.job_id, "--tenant", launch.tenant_id,
            "--source", launch.source_investigation_id, "--parent-pid", str(launch.parent_pid)]


def post_step_argv(launch: PostStepLaunch) -> list[str]:
    """The post-step's child, as a module; `--pending` may name no job, and a family-less one has
    no `--job`."""
    job = [] if launch.job_id is None else ["--job", launch.job_id]
    return [sys.executable, "-m", POST_STEP_MODULE, *job, "--tenant", launch.tenant_id,
            "--pending", *launch.pending_job_ids, "--parent-pid", str(launch.parent_pid)]


def _exit_words(returncode: int) -> str:
    return (f"was killed by signal {-returncode}" if returncode < 0
            else f"exited with code {returncode}")


def _ending_from(end: job_lane.JobEnd | None, returncode: int,
                 disposition: Callable[[], str | None]) -> Ending:
    """Rules 1-5 (O8, M9): the stage from the job-end record alone, and, once the host committed
    a report and the scrub walked the tree, the report's disposition (read only then)."""
    if end is None:
        return Ending(_FAILED, failure_reason=_NO_REPORT,
                       failure_message=f"the run left no job-end record; the child {_exit_words(returncode)}")
    if end.setup == job_facts.SETUP_REFUSED:
        return Ending(_FAILED, failure_reason=_SETUP_REFUSED,
                       failure_message="run setup refused the job", decided_by_run=True)
    if end.box == job_facts.BOX_START_FAILED:
        return Ending(_FAILED, failure_reason=_WORKER_ERROR,
                       failure_message="the run's box did not start")
    if end.report_committed and end.scrub_verified:
        found = disposition()
        return (Ending(_COMPLETED, disposition=found, decided_by_run=True) if found is not None
                else Ending(_UNPARSEABLE, decided_by_run=True))
    if end.setup != job_facts.SETUP_DONE:
        why = "run setup crashed"
    elif not end.report_committed:
        why = "the host committed no report"
    else:
        why = "the scrub did not verify the run folder after the box stopped"
    if end.cut_short is not None:
        # A vocabulary word, never a child's text (`JobEnd.parse` refuses anything else): the
        # class the run ended by, beside the existing words (#1421). The run log names the rest.
        why = f"{why}; the run was cut short ({end.cut_short})"
    return Ending(_FAILED, failure_reason=_NO_REPORT, failure_message=why)


def _report_disposition_or_none(lane: job_lane.JobLane, inv: str) -> str | None:
    """The committed report's disposition; a fault nobody planned for reads as none, so the run is
    `unparseable` as with any unreadable disposition, never `worker_error` (#1396)."""
    try:
        return lane.report_disposition(inv)
    except Exception:  # noqa: BLE001 — the stage is decided by the job-end record (#1396)
        _logger.error("investigation %s: reading its report's disposition failed; it is unparseable",
                      inv, exc_info=True)
        return None


async def _spawn_outcome(spawn: asyncio.Future[asyncio.subprocess.Process]) -> asyncio.subprocess.Process | None:
    """The child a cancelled row's spawn made, waiting for the spawn to finish however many
    further cancels arrive (r7 D-ac: a child made after the cancel is still this row's to end);
    None when the spawn failed. Waiting on it never cancels the spawn itself."""
    while not spawn.done():
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait({spawn})
    if spawn.cancelled() or spawn.exception() is not None:
        return None
    return spawn.result()


class _WorkerFault(Exception):
    """A worker-side failure for one row (O6): the row ends `failed` / `worker_error` with this
    message, which is the worker's own words."""


class Worker:
    """Runs claimed investigations, up to `slots` at once. `drain()` claims until nothing is
    queued and waits for every row's last write; `serve()` polls until SIGTERM/SIGINT and also
    takes over rows whose holders were lost. A tenant's state comes with its claim (#1342 r7
    R7-1); the children read their tenant records from `DEFENDER_DATABASE_DSN`, which they
    inherit. Cadences (#1343): the lease is renewed every `renewal_interval`, the cost so far is
    read per row every `cost_interval` and copied by the renewal that follows, and take-over
    runs every `takeover_interval`.

    `learning_slots` (#1344 O5) is both the guarantee and the limit of learning-class tasks; a bare
    worker has none. Above 0 it needs both `learning_argv` and `post_step_argv`. `child_cwd` is the
    working directory of every child (the code copy, for `-m` starts). `learning_check_interval`
    (seconds, above 0) is how long a tenant goes without a post-step before a family-less one
    checks it (amendment 1); each tenant's clock starts at the start of `serve` or `drain`."""

    def __init__(  # noqa: PLR0913 — the ratified signature
        self, store: Any, *, data_root: Path | DataRoot,
        child_argv: Callable[[Launch], list[str]] = run_argv,
        containers: Containers | None = None, slots: int = 3,
        clock: Callable[[], _dt.datetime], stop_grace: float = 30,
        renewal_interval: float = 1.0, cost_interval: float = 15.0, takeover_interval: float = 5.0,
        open_lane: Callable[[DataRoot, object], job_lane.JobLane] = job_lane.JobLane.open,
        store_call_limit: float = 10.0,
        spawn: Callable[..., Awaitable[asyncio.subprocess.Process]] = asyncio.create_subprocess_exec,
        learning_slots: int = 0,
        learning_argv: Callable[[LearningLaunch], list[str]] | None = None,
        post_step_argv: Callable[[PostStepLaunch], list[str]] | None = None,
        child_cwd: Path | None = None,
        learning_check_interval: float = LEARNING_CHECK_INTERVAL,
    ) -> None:
        if slots < 1:
            raise ValueError(f"a worker needs at least one slot, not {slots!r}")
        if not 0 <= learning_slots <= slots - 1:
            raise ValueError(f"learning slots must be between 0 and slots - 1 ({slots - 1}), not {learning_slots!r}")
        if learning_slots > 0 and (learning_argv is None or post_step_argv is None):
            raise ValueError("a worker with learning slots needs both the learning and the post-step child commands")
        if not learning_check_interval > 0:
            raise ValueError(f"the learning check interval must be above 0 seconds, not {learning_check_interval!r}")
        self._learning_slots = learning_slots
        self._learning_argv = learning_argv
        self._post_step_argv = post_step_argv
        self._child_cwd = child_cwd
        self._learning_tasks: set[asyncio.Task[None]] = set()
        # Family-less checks (#1344 amendment 1), in monotonic seconds: each tenant's last
        # post-step end, the tenants a post-step runs for now, when the clock of a tenant with no
        # post-step yet started, and when the next store read of the tenants can find one due.
        self._learning_check_interval = learning_check_interval
        self._last_check: dict[str, float] = {}
        self._checking: set[str] = set()
        self._checks_from = time.monotonic()
        self._next_check_at = self._checks_from + learning_check_interval
        self._store = store
        self._data_root = data_root if isinstance(data_root, DataRoot) else data_root_from_path(data_root)
        self._child_argv = child_argv
        self._containers: Containers = containers if containers is not None else DockerContainers()
        self._slots = slots
        self._clock = clock
        self._stop_grace = stop_grace
        self._renewal_interval = renewal_interval
        self._cost_interval = cost_interval
        self._takeover_interval = takeover_interval
        self._open_lane = open_lane  # the job lane's door; a test hands in one that faults
        self._store_call_limit = store_call_limit  # how long one renewal or take-over call may take
        self._create_process = spawn  # the process door; a test lands an event inside it
        self._lease = float(store.lease_seconds)
        self._store_outage_at: float | None = None  # this worker's last store call that hit an outage
        self._tasks: set[asyncio.Task[None]] = set()
        self._held: dict[str, Held] = {}
        self._stopping = False
        self._stop_signal = asyncio.Event()
        # Store writes that are failing now: claims wait for them all to recover (B5, r5 item 14).
        self._renewal_failing = False
        self._end_failing: set[str] = set()
        self._last_cost_copy = 0.0

    # -- entry points -----------------------------------------------------------------------------

    async def drain(self) -> None:
        """Claim while a slot is free until nothing is queued, then wait until every held row's
        last write has landed. Renews its rows but takes nothing over (r5 item 10). A store fault
        in the claim ends it (raised) and, like a cancellation, stops as a deliberate stop does
        (`_leave`)."""
        await self._claim_loop(stop=None)

    async def serve(self) -> None:
        """Poll for queued rows at a fixed interval until SIGTERM or SIGINT, then stop: each child
        gets SIGTERM, a child still alive after `stop_grace` has its group killed, the backstop
        runs, and each row it ended is handed back (B11). A store fault is logged and the claim
        retried. Installs its own handlers and removes them on return."""
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        signals = (signal.SIGTERM, signal.SIGINT)
        previous = {s: signal.getsignal(s) for s in signals}
        for s in signals:
            loop.add_signal_handler(s, stop.set)
        try:
            await self._claim_loop(stop=stop)
        finally:
            for s in signals:
                loop.remove_signal_handler(s)
                if previous[s] is not None:
                    signal.signal(s, previous[s])

    async def _claim_loop(self, *, stop: asyncio.Event | None) -> None:
        """The one claim loop of `drain` and `serve`: claim while a slot is free and no store write
        is failing, else wait for a slot to free (or, serving, for the poll interval or the stop).

        Draining (`stop` is None), the loop ends once a claim finds nothing queued, then waits
        for every task; a store fault is raised. Serving, a store fault is logged and retried,
        and the stop is the deliberate one (`_stop`). However the loop leaves by an exception
        (a store fault, a cancellation), it stops as a deliberate stop does (`_leave`). The
        renewal (and, serving, the take-over) run beside the loop until every row's last write
        has landed."""
        # The family-less checks' clocks start with the worker (amendment 1).
        self._checks_from = time.monotonic()
        self._next_check_at = self._checks_from + self._learning_check_interval
        services = self._start_services(takeover=stop is not None)
        wake = asyncio.Event()
        try:
            try:
                await self._claim_until_done(stop, wake)
            except BaseException:
                await self._leave()
                raise
        finally:
            await _end_tasks(services)

    async def _claim_until_done(self, stop: asyncio.Event | None, wake: asyncio.Event) -> None:
        while stop is None or not stop.is_set():
            wake.clear()  # before the claim: a slot freed while it runs wakes the wait below
            if len(self._tasks) < self._slots and not self._writes_failing():
                if await self._claim_or_retry(on_done=wake.set, retry=stop is not None):
                    continue
                # Drained: nothing is queued. With learning slots, not while tasks run: a finish
                # still to come queues a job this drain claims (#1344 O5); nor when a task ended
                # during the claim, which may have looked while its learning slot was still taken.
                if stop is None and (self._learning_slots == 0 or not (self._tasks or wake.is_set())):
                    break
            await self._wait(wake, stop)
        if stop is None:
            if self._tasks:
                await asyncio.wait(set(self._tasks))
        else:
            _logger.info("the worker was asked to stop; ending %d run(s)", len(self._children()))
            await self._stop()

    def _start_services(self, *, takeover: bool) -> list[asyncio.Task[None]]:
        services = [asyncio.create_task(self._renewal_loop())]
        if takeover:
            services.append(asyncio.create_task(self._takeover_loop()))
        return services

    def _writes_failing(self) -> bool:
        return self._renewal_failing or bool(self._end_failing)

    async def _claim_or_retry(self, *, on_done: Callable[[], None], retry: bool) -> bool:
        """`_claim_one`; with `retry`, a store fault is logged and read as nothing claimed."""
        if not retry:
            return await self._claim_one(on_done=on_done)
        try:
            return await self._claim_one(on_done=on_done)
        except Exception as fault:  # noqa: BLE001 — a store fault is waited out, never ends serving
            self._note_store_fault(fault)
            _logger.exception("the worker could not claim an investigation; retrying")
            return False

    @staticmethod
    async def _wait(wake: asyncio.Event, stop: asyncio.Event | None) -> None:
        """Until a task ends (`wake`), the stop, or the poll interval, whichever is first."""
        waits = [asyncio.ensure_future(wake.wait())]
        if stop is not None:
            waits.append(asyncio.ensure_future(stop.wait()))
        try:
            await asyncio.wait(waits, timeout=POLL_INTERVAL, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for w in waits:
                w.cancel()

    # -- slots ------------------------------------------------------------------------------------

    async def _claim_one(self, *, on_done: Callable[[], None] | None = None) -> bool:
        """Claim one queued row into a task; False when nothing is queued. While fewer
        learning-class tasks than `learning_slots` run: a tenant's overdue family-less check
        (#1344 amendment 1), else the oldest learning job; otherwise the oldest investigation
        (#1344 O5)."""
        if self._stopping:
            return False
        if len(self._learning_tasks) < self._learning_slots:
            tenant = await self._overdue_tenant()
            if tenant is not None:
                self._checking.add(tenant)  # before the task runs: the next claim cannot pick it again
                self._start_task(self._check_tenant(tenant), on_done=on_done, learning=True)
                return True
            learning = await self._store.claim_learning_job()
            if learning is not None:
                held = Held(learning.record, kind=LEARNING)
                self._held[learning.record.learning_job_id] = held
                self._start_task(self._run_learning(learning, held), on_done=on_done, learning=True)
                return True
        claim = await self._store.claim()
        if claim is None:
            return False
        held = Held(claim.record)
        self._held[claim.record.investigation_id] = held
        self._start_task(self._run_row(claim, held), on_done=on_done, learning=False)
        return True

    def _start_task(self, work: Awaitable[None], *, on_done: Callable[[], None] | None, learning: bool) -> None:
        task: asyncio.Task[None] = asyncio.ensure_future(work)
        self._tasks.add(task)
        if learning:
            self._learning_tasks.add(task)

        def _done(t: asyncio.Task[None]) -> None:
            self._tasks.discard(t)
            self._learning_tasks.discard(t)
            if on_done is not None:
                on_done()
        task.add_done_callback(_done)

    def _children(self) -> list[Held]:
        return [h for h in self._held.values() if h.proc is not None and h.proc.returncode is None]

    async def _stop(self) -> None:
        """The deliberate stop: no more claims, each child ended (`_end_child`), then wait for the
        tasks: each runs its backstop and its last write, which for a row the stop ended is the
        hand-back (B11). Renewal keeps running meanwhile (the caller ends it)."""
        self._stopping = True
        self._stop_signal.set()
        await asyncio.gather(*(self._end_child(h, by_stop=True) for h in self._children()))
        if self._tasks:
            await asyncio.wait(set(self._tasks))

    async def _leave(self) -> None:
        """The loop is leaving by an exception: it stops as a deliberate stop does (r5 item 3). A
        cancel that lands during that stop's wait means leave now: every child's group is killed
        at once, so no child outlives its row's lease, and each row task is cancelled and waited
        for, so its cleanup has run when the worker leaves (a cancelled row writes nothing; its
        lease lapses into a take-over)."""
        try:
            await self._stop()
        except asyncio.CancelledError:
            _logger.warning("the worker was cancelled again while stopping; killing %d child(ren)",
                            len(self._children()))
            for held in self._children():
                if held.proc is not None:
                    kill_group(held.proc.pid)
            await _end_tasks(list(self._tasks))
            raise

    async def _end_child(self, held: Held, *, by_stop: bool = False) -> None:
        """SIGTERM, then after `stop_grace` SIGKILL to the child's whole group (its own session,
        so its group id is its pid and the worker is not in it). `by_stop` marks a child a
        deliberate stop signalled while it was alive: its row is handed back (B11)."""
        proc = held.proc
        if proc is None or proc.returncode is not None:
            return
        if by_stop:
            held.signalled = True
        with contextlib.suppress(ProcessLookupError):
            proc.send_signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(asyncio.shield(proc.wait()), timeout=self._stop_grace)
        except TimeoutError:
            _logger.warning("child %d did not end within %gs of SIGTERM; killing its group",
                            proc.pid, self._stop_grace)
            kill_group(proc.pid)
            await proc.wait()

    # -- the lease: renewal, cost so far, take-over -------------------------------------------------

    async def _renewal_loop(self) -> None:
        """Every `renewal_interval`, renew every held row in one store call. A call that errors
        covers nothing and fences nothing (r5 item 14): claims wait and the next tick retries."""
        while True:
            await self._renew_once()
            await asyncio.sleep(self._renewal_interval)

    async def _renew_once(self) -> None:
        held = self._leased()
        if not held:
            self._renewal_failing = False
            return
        costs = self._costs_due(held)
        progress = self._progress_due(held) if costs is not None else None
        try:
            async with asyncio.timeout(self._store_call_limit):  # not `wait_for`: on 3.11 it can lose a cancel
                covered = set(await self._store.renew(set(held), costs=costs, **(
                    {"progress": progress} if progress else {})))
        except Exception as fault:  # noqa: BLE001 — a failed renewal is waited out, never ends the worker
            self._renewal_failing = True
            self._note_store_fault(fault)
            _logger.warning("the worker could not renew its leases; retrying", exc_info=True)
            return
        self._renewal_failing = False
        if costs is not None:
            self._last_cost_copy = time.monotonic()
        for inv, row in held.items():
            if inv not in covered:
                self._fence(inv, row)

    def _note_store_fault(self, fault: BaseException) -> None:
        if is_outage(fault):
            self._store_outage_at = time.monotonic()

    def _leased(self) -> dict[str, Held]:
        """The held entries whose rows' leases this worker renews: not the post-steps."""
        return {key: h for key, h in self._held.items() if h.leased}

    def _costs_due(self, held: dict[str, Held]) -> dict[str, float] | None:
        """The figures this renewal copies (B2), or None between cost ticks."""
        if time.monotonic() - self._last_cost_copy < self._cost_interval:
            return None
        return {inv: h.cost_so_far for inv, h in held.items() if h.kind == INVESTIGATION and h.cost_so_far is not None}

    @staticmethod
    def _progress_due(held: dict[str, Held]) -> dict[str, LearningProgress]:
        """The learning jobs' progress this renewal copies (#1344 O13), on the cost ticks."""
        return {job: h.progress for job, h in held.items() if h.kind == LEARNING and h.progress is not None}

    def _fence(self, inv: str, held: Held) -> None:
        """A renewal that succeeded no longer covers the row (cancelled, taken over or deleted,
        B3): its child is ended at once; the row's one end path runs as for any child exit. A row
        fenced before its child exists is never launched (`_run_claimed`)."""
        if held.fenced or (held.proc is not None and held.proc.returncode is not None):
            return  # already fenced, or its child already exited: the row is writing its own end
        held.fenced = True
        _logger.warning("%s %s: it was cancelled, taken over, moved or deleted; ending its child", held.kind, inv)
        held.enders.append(asyncio.create_task(self._end_child(held)))

    async def _takeover_loop(self) -> None:
        """Every `takeover_interval`, take over every lapsed row this worker does not hold (B7),
        unless this worker's own store calls hit an outage within the last lease. A pass that
        raises is logged; the next tick tries again."""
        while True:
            if self._store_settled():
                try:
                    async with asyncio.timeout(self._store_call_limit):  # not `wait_for`: on 3.11 it can lose a cancel
                        await self._store.take_over(held=frozenset(self._leased()))
                except Exception as fault:  # noqa: BLE001 — one failed pass never ends the task
                    self._note_store_fault(fault)
                    _logger.exception("the worker's take-over pass failed; retrying")
            await asyncio.sleep(self._takeover_interval)

    def _store_settled(self) -> bool:
        return self._store_outage_at is None or time.monotonic() - self._store_outage_at >= self._lease

    async def _cost_loop(self, held: Held) -> None:
        """Every `cost_interval`, read the row's cost so far into `held.cost_so_far`, in a thread
        of its own, so a read that hangs delays nothing else (r5 item 4). A read that fails keeps
        the last good figure (B2)."""
        inv = held.record.investigation_id
        while True:
            await asyncio.sleep(self._cost_interval)
            try:
                held.cost_so_far = await asyncio.to_thread(self._cost_so_far, held.record)
            except Exception:  # noqa: BLE001 — keep the last good figure
                _logger.debug("investigation %s: its cost so far could not be read", inv, exc_info=True)

    def _cost_so_far(self, record: Any) -> float:
        with self._open_lane(self._data_root, record.tenant_id) as lane:
            return lane.cost(record.investigation_id)

    # -- one row ----------------------------------------------------------------------------------

    async def _run_row(self, claim: Claim, held: Held) -> None:
        record = claim.record
        inv, tenant = record.investigation_id, record.tenant_id
        with _log.log_context(run_id=inv, tenant_id=tenant):
            try:
                end = await self._decide(held, claim.tenant_state)
                await self._write_end(held, end)
            except Exception:  # noqa: BLE001 — one row's fault never ends the worker
                _logger.exception("investigation %s: the worker failed while ending it", inv)
            finally:
                self._held.pop(inv, None)
                self._end_failing.discard(inv)

    async def _decide(self, held: Held, tenant_state: str) -> End:
        """Run one claimed row and decide its last write; the caller makes it (`_write_end`)."""
        inv = held.record.investigation_id
        try:
            return await self._run_claimed(held, tenant_state)
        except Exception as fault:  # noqa: BLE001 — one row's fault never ends the worker
            _logger.exception("investigation %s: the worker failed while running it", inv)
            if is_outage(fault) or held.signalled:
                # Nothing about the job failed: it is handed back, with what it had spent.
                return End(None, 0.0 if held.proc is None else held.cost_so_far, None)
            return End(Ending(_FAILED, failure_reason=_WORKER_ERROR,
                              failure_message="the worker failed while running the job"), None, None)

    async def _run_claimed(self, held: Held, tenant_state: str) -> End:
        record = held.record
        inv, tenant = record.investigation_id, record.tenant_id
        if self._stopping:  # claimed as the stop landed: handed back with nothing launched or spent
            return End(None, 0.0, None)
        started = self._clock()
        # This claim's box token (#1342 r5 C1): the child's box is stamped with it, and the
        # backstop removes only a container that carries it.
        token = uuid.uuid4().hex
        try:
            await self._write_launch(record, token, tenant_state)
        except _WorkerFault as fault:
            _logger.error("investigation %s: %s", inv, fault)
            return End(Ending(_FAILED, failure_reason=_WORKER_ERROR, failure_message=str(fault)), 0.0, None)
        if self._stopping:  # claimed but not started when the stop landed: handed back, nothing spent
            return End(None, 0.0, None)
        if held.fenced:  # B3: ended before its child exists; the write that follows is final accounting
            _logger.info("investigation %s: it was fenced before its child started; not launched", inv)
            return End(Ending(_FAILED, failure_reason=_WORKER_ERROR, failure_message="the job was ended before it started"),
                       0.0, None)
        launch = Launch(inv, tenant, os.getpid())

        async def backstop() -> None:
            await self._backstop(inv, token)

        proc = await self._run_child(held, lambda: self._child_argv(launch), watch=self._cost_loop, cleanup=backstop)
        if proc is None:
            return End(Ending(_FAILED, failure_reason=_WORKER_ERROR,
                              failure_message="the worker could not start the job's child process"), 0.0, None)
        returncode = await proc.wait()
        _logger.info("investigation %s: child %d %s after %s", inv, proc.pid,
                     _exit_words(returncode), self._clock() - started)
        ending, cost, knowledge = await asyncio.to_thread(self._read_ending, record, returncode)
        if held.signalled and not ending.decided_by_run:  # R1: an ending the run itself decided wins over the stop
            return End(None, cost, knowledge)
        return End(ending, cost, knowledge)

    async def _run_child(
        self, held: Held, argv: Callable[[], list[str]], *,
        watch: Callable[[Held], Coroutine[Any, Any, None]] | None = None,
        cleanup: Callable[[], Awaitable[None]] | None = None,
    ) -> asyncio.subprocess.Process | None:
        """Start the entry's child and wait for it to end, then run its cleanup; None when the
        child could not be started. `watch` runs beside the child (the cost or progress reads).
        The task owns its child: cancelled, it ends the child and writes nothing.

        Every child, of every kind, is handed a fresh claim (`box.CLAIM_ENV`): each box started
        anywhere in its process tree carries it, and once the child is gone every container
        carrying it is removed (`_sweep`), so nothing a killed or crashed child started is left
        behind. `cleanup` is a kind's own step before that sweep (an investigation's backstop)."""
        what = _what(held)
        proc: asyncio.subprocess.Process | None = None
        watch_task: asyncio.Task[None] | None = None
        claim = uuid.uuid4().hex
        # The start runs as its own task, so a cancel cannot land inside it and lose the child
        # it makes (r7 D-ac): a cancelled row waits for it, and the child is ended below.
        spawn = asyncio.ensure_future(self._spawn(argv, claim))
        try:
            try:
                proc = await asyncio.shield(spawn)
            except asyncio.CancelledError:
                proc = await _spawn_outcome(spawn)
                held.proc = proc
                _logger.warning("%s: the worker is leaving; ending its child", what)
                await self._end_child(held)
                raise
            except (OSError, ValueError) as unstarted:
                _logger.error("%s: the child could not be started: %s", what, unstarted)
                return None
            held.proc = proc
            if watch is not None:
                watch_task = asyncio.create_task(watch(held))
            await self._wait_for_child(held, proc)
        finally:
            if watch_task is not None:
                await _end_tasks([watch_task])
            if proc is not None:
                # One cleanup however the row ended (r7 D-ac): whatever the child left running in
                # its session dies with it, then its box, if it outlived it, is removed.
                kill_group(proc.pid)
                if cleanup is not None:
                    await cleanup()
                await self._sweep(what, claim)
        return proc

    async def _sweep(self, what: str, claim: str) -> None:
        """Remove every container the child's process tree started (its claim's label). Never an
        error, never the row's business: what it cannot remove is logged, and the tenant's
        teardown removes it by the tenant's label."""
        try:
            await asyncio.to_thread(self._containers.remove_claimed, claim)
        except Exception:  # noqa: BLE001 — the sweep is best effort
            _logger.exception("%s: the containers its child started could not all be removed", what)

    async def _wait_for_child(self, held: Held, proc: asyncio.subprocess.Process) -> None:
        try:
            if self._stopping or held.fenced:  # spawned as the stop or a fence landed
                await self._end_child(held, by_stop=self._stopping)
            await proc.wait()
        except asyncio.CancelledError:
            # The task owns its child: cancelled (the loop itself was cancelled), it ends the
            # child, and writes nothing.
            _logger.warning("%s: the worker is leaving; ending child %d", _what(held), proc.pid)
            await self._end_child(held)
            raise

    async def _spawn(self, argv: Callable[[], list[str]], claim: str) -> asyncio.subprocess.Process:
        """The entry's child, in a session of its own (its group id is its pid), output inherited,
        in `child_cwd` when one is set, its boxes stamped with `claim` (`box.CLAIM_ENV`)."""
        where = {} if self._child_cwd is None else {"cwd": str(self._child_cwd)}
        return await self._create_process(
            *argv(),
            stdin=subprocess.DEVNULL, stdout=None, stderr=None, start_new_session=True,
            env={**os.environ, "DEFENDER_DATA_ROOT": str(data_root_for_child(self._data_root)), CLAIM_ENV: claim},
            **where)

    async def _write_launch(self, record: Any, token: str, tenant_state: str) -> None:
        """The launch record (carrying this claim's box token) and the alert file, create-only,
        in the tenant's runs container, for a tenant whose state at the claim was `active`
        (r7 R7-1; a teardown always wins, and a job racing it fails)."""
        if tenant_state != "active":
            raise _WorkerFault(f"the tenant is {tenant_state}, not active; the job was not started")
        alert = await self._store.get_alert(record.tenant_id, record.alert_id)
        if alert is None:
            raise _WorkerFault("the job's alert is not in the store")
        launch = job_lane.LaunchRecord(
            investigation_id=record.investigation_id, tenant_id=record.tenant_id,
            alert_id=record.alert_id, digest=digest_of(alert.raw), label=alert.title or alert.vendor_ticket_id,
            box_token=token)
        await asyncio.to_thread(self._write_launch_files, launch, alert.raw)

    def _write_launch_files(self, launch: job_lane.LaunchRecord, raw: bytes) -> None:
        try:
            lane = self._open_lane(self._data_root, launch.tenant_id)
        except job_lane.JobLaneRefused as refused:
            _logger.error("investigation %s: %s", launch.investigation_id, refused)
            raise _WorkerFault("the tenant's runs container cannot be used on this host") from None
        with lane:
            try:
                lane.write_launch(launch, raw)
            except FileExistsError:
                raise _WorkerFault("a launch record for this job already exists") from None
            except job_lane.JobLaneRefused as refused:
                _logger.error("investigation %s: %s", launch.investigation_id, refused)
                raise _WorkerFault(f"the job's launch files cannot be written: {refused}") from None
            except OSError as fault:
                _logger.error("investigation %s: writing the launch files: %s", launch.investigation_id, fault)
                raise _WorkerFault("the worker could not write the job's launch files") from None

    async def _backstop(self, inv: str, token: str) -> None:
        """Remove the run's box if it is still there and carries this claim's token; a container
        under the name that is not this job's is left in place and logged. Never an error, never
        the row's business."""
        name = container_name(inv)
        try:
            reaped = await asyncio.to_thread(self._containers.reap, name, token)
        except Exception:  # noqa: BLE001 — the backstop is best effort
            _logger.exception("investigation %s: the backstop could not remove %s", inv, name)
            return
        if reaped == Reaped.REMOVED:
            _logger.info("investigation %s: its box %s outlived the child and was removed", inv, name)
        elif reaped == Reaped.NOT_OURS:
            _logger.warning("investigation %s: a container named %s is not this job's; left in place",
                            inv, name)
        elif reaped != Reaped.ABSENT:
            _logger.error("investigation %s: the backstop's answer for %s was %r", inv, name, reaped)

    def _read_ending(self, record: Any, returncode: int) -> tuple[Ending, float | None, dict | None]:
        """The stage, cost and knowledge from the host records, through the job lane (in a thread).
        A cost that cannot be read is None, the final figure's own meaning (R2)."""
        inv = record.investigation_id
        try:
            lane = self._open_lane(self._data_root, record.tenant_id)
        except job_lane.JobLaneRefused as refused:
            _logger.error("investigation %s: reading its records: %s", inv, refused)
            return (Ending(_FAILED, failure_reason=_WORKER_ERROR,
                           failure_message="the tenant's runs container could not be read after the run"),
                    None, None)
        try:
            ending = _ending_from(lane.read_job_end(inv), returncode, lambda: _report_disposition_or_none(lane, inv))
            # #1396: the ending is decided; from here no fault turns it into `worker_error`
            cost: float | None
            try:
                cost = lane.cost(inv)
            except job_lane.CostUnreadable as unreadable:
                _logger.warning("investigation %s: its cost is unknown: %s", inv, unreadable)
                cost = None
            except Exception:  # noqa: BLE001 — the decided ending stands (#1396)
                _logger.error("investigation %s: reading its cost failed; its %s ending stands and its "
                              "cost is unknown", inv, ending.stage, exc_info=True)
                cost = None
            knowledge: dict | None
            try:
                knowledge = lane.knowledge(inv)
            except Exception:  # noqa: BLE001 — the decided ending stands (#1396)
                _logger.error("investigation %s: reading its knowledge failed; its %s ending stands and "
                              "its knowledge is unreadable", inv, ending.stage, exc_info=True)
                knowledge = job_lane.JobLane.unreadable_knowledge()
        finally:
            try:
                lane.close()
            except Exception:  # noqa: BLE001 — a fault before the ending still raises; one after keeps it (#1396)
                _logger.error("investigation %s: closing its records failed", inv, exc_info=True)
        return ending, cost, knowledge

    # -- one learning job (#1344) -----------------------------------------------------------------

    async def _run_learning(self, claim: LearningClaim, held: Held) -> None:
        """One claimed job: its family step as the job entry's child, the row's one end write, then,
        after a job whose child started and that ended (not handed back), the post-step, in this
        same task and so the same slot (O8). A stopping worker starts no post-step."""
        record = claim.record
        job, tenant = record.learning_job_id, record.tenant_id
        with _log.log_context(tenant_id=tenant):
            outcome: LearningOutcome | None = None
            started = False
            try:
                outcome, started = await self._decide_learning(held, claim.tenant_state)
                await self._write_end(held, outcome)
            except Exception:  # noqa: BLE001 — one row's fault never ends the worker
                _logger.exception("learning job %s: the worker failed while ending it", job)
            finally:
                self._held.pop(job, None)
                self._end_failing.discard(job)
            if started and not self._stopping and outcome is not None and outcome.status is not None:
                try:
                    await self._post_step(tenant, job)
                except Exception:  # noqa: BLE001 — a post-step's fault leaves the job's row as it is
                    _logger.exception("learning job %s: its post-step failed", job)

    async def _decide_learning(self, held: Held, tenant_state: str) -> tuple[LearningOutcome, bool]:
        """Run one claimed job's family step and decide its last write; also whether its child
        started."""
        try:
            return await self._run_family(held, tenant_state)
        except Exception as fault:  # noqa: BLE001 — one row's fault never ends the worker
            _logger.exception("learning job %s: the worker failed while running it", _key(held))
            started = held.proc is not None
            if is_outage(fault) or held.signalled:
                return LearningOutcome(None, progress=held.progress), started
            return LearningOutcome(_FAILED, _WORKER_ERROR, "the worker failed while running the job"), started

    async def _run_family(self, held: Held, tenant_state: str) -> tuple[LearningOutcome, bool]:
        record = held.record
        job, tenant = record.learning_job_id, record.tenant_id
        if self._stopping:  # claimed as the stop landed: handed back with nothing started
            return LearningOutcome(None), False
        if tenant_state != "active":
            return LearningOutcome(_FAILED, _WORKER_ERROR,
                                   f"the tenant is {tenant_state}, not active; the job was not started"), False
        if held.fenced:
            return LearningOutcome(_FAILED, _WORKER_ERROR, "the job was ended before it started"), False
        learning_argv = self._learning_argv
        assert learning_argv is not None  # a worker with learning slots has it (constructor)
        launch = LearningLaunch(job, tenant, os.getpid(), record.investigation_id)
        started = self._clock()
        proc = await self._run_child(held, lambda: learning_argv(launch), watch=self._progress_loop)
        if proc is None:
            return LearningOutcome(_FAILED, _WORKER_ERROR, "the worker could not start the job's child process"), False
        returncode = await proc.wait()
        _logger.info("learning job %s: child %d %s after %s", job, proc.pid, _exit_words(returncode),
                     self._clock() - started)
        try:
            end = await asyncio.to_thread(self._read_learning_strict, tenant, lambda lane: lane.read_learning_end(job))
        except (job_lane.JobLaneRefused, OSError) as fault:
            # The worker's own failure, as an investigation's records that cannot be read are
            # (`_read_ending`): the child may have left a good record, so not `exited_without_result`.
            _logger.error("learning job %s: reading its end record: %s", job, fault)
            if held.signalled:  # a stop can never permanently fail or skip a job: handed back
                return LearningOutcome(None, progress=held.progress), True
            return LearningOutcome(_FAILED, _WORKER_ERROR, "the tenant's runs container could not be read after the job",
                                   held.progress), True
        if end is None:
            progress = await asyncio.to_thread(
                self._read_learning, tenant, lambda lane: lane.read_learning_progress(job)) or held.progress
            if held.signalled:  # a stop can never permanently fail or skip a job: handed back
                return LearningOutcome(None, progress=progress), True
            return LearningOutcome(
                _FAILED, "exited_without_result",
                f"the job's child left no readable end record; it {_exit_words(returncode)}", progress), True
        if end.status == _STOPPED:
            return LearningOutcome(None, progress=end), True
        # The record decided the ending, so a stop that landed after it does not override it.
        return LearningOutcome(end.status, end.reason, end.message, end, end.findings_count), True

    async def _progress_loop(self, held: Held) -> None:
        """Every `cost_interval`, read the job entry's progress record into `held.progress`, in a
        thread; the renewal copies it to the row (O13). A record that cannot be read keeps the
        last good one."""
        record = held.record
        job = record.learning_job_id
        while True:
            await asyncio.sleep(self._cost_interval)
            found = await asyncio.to_thread(
                self._read_learning, record.tenant_id, lambda lane: lane.read_learning_progress(job))
            if found is not None:
                held.progress = found

    def _read_learning_strict(self, tenant: str, read: Callable[[job_lane.JobLane], Any]) -> Any:
        """One of a learning job's records, through the job lane; a runs container that cannot be
        used, or an OS error reading it, raises (`JobLaneRefused`, `OSError`). A record absent,
        unreadable or not of its shape is the lane's `None`."""
        with self._open_lane(self._data_root, tenant) as lane:
            return read(lane)

    def _read_learning(self, tenant: str, read: Callable[[job_lane.JobLane], Any]) -> Any:
        """`_read_learning_strict`, where a runs container that cannot be used counts as the
        record absent (progress and post-step records: nothing is decided on their absence)."""
        try:
            return self._read_learning_strict(tenant, read)
        except (job_lane.JobLaneRefused, OSError) as fault:
            _logger.warning("tenant %s: a learning record could not be read: %s", tenant, fault)
            return None

    async def _learning_end_once(self, held: Held, end: LearningOutcome) -> None:
        """One try: the terminal status, or the hand-back, if the row is still this worker's
        (running, not handed back); a row that moved is not written (O2, P1)."""
        record = held.record
        job, tenant = record.learning_job_id, record.tenant_id
        if end.status is None:
            written = await self._store.hand_back_learning_job(tenant, job, progress=end.progress)
            what = "handed back"
        else:
            written = await self._store.finish_learning_job(
                tenant, job, status=end.status, reason=end.reason, message=end.message, progress=end.progress,
                findings_count=end.findings_count)
            what = end.status + (f" ({end.reason})" if end.reason else "")
        if written is None:
            _logger.info("learning job %s: the row is no longer this worker's; nothing written", job)
        else:
            _logger.info("learning job %s: %s", job, what)

    async def _overdue_tenant(self) -> str | None:
        """The tenant whose family-less check is most overdue (#1344 amendment 1), or None: an
        `active` tenant with learning jobs, no post-step of its own running, whose last post-step
        ended (or, before any, whose clock started with the worker) `learning_check_interval` ago.
        The store is read only once a check can be due, and a read that fails is logged and
        waits an interval: it never stops a claim."""
        now = time.monotonic()
        if now < self._next_check_at:
            return None
        interval = self._learning_check_interval
        try:
            tenants = await self._store.learning_tenants()
        except Exception as fault:  # noqa: BLE001 — a failed read delays the checks, never the claims
            self._note_store_fault(fault)
            _logger.warning("the worker could not list the tenants to check for learning; retrying in %gs",
                            interval, exc_info=True)
            self._next_check_at = now + interval
            return None
        due_at = {t: self._last_check.get(t, self._checks_from) + interval
                  for t in tenants if t not in self._checking}
        overdue = sorted((at, t) for t, at in due_at.items() if at <= now)
        if overdue:
            self._next_check_at = now  # another may be due too: read again at the next claim
            return overdue[0][1]
        # Nothing due: read again when the soonest known tenant is, and within one interval
        # for a tenant not yet known.
        self._next_check_at = min([now + interval, *due_at.values()])
        return None

    async def _check_tenant(self, tenant: str) -> None:
        """One family-less post-step for `tenant` (#1344 amendment 1), as a learning-class task:
        none once the worker is stopping, and a fault never ends the worker."""
        with _log.log_context(tenant_id=tenant):
            try:
                if self._stopping:
                    return
                _logger.info("tenant %s: no post-step for %gs; checking its learning without a family",
                             tenant, self._learning_check_interval)
                await self._post_step(tenant, None)
            except Exception:  # noqa: BLE001 — a failed check changes no row; the next one retries
                _logger.exception("tenant %s: its family-less post-step failed", tenant)
            finally:
                self._checking.discard(tenant)
                self._last_check[tenant] = time.monotonic()

    async def _post_step(self, tenant: str, job: str | None) -> None:
        """The post-step after `job` (O8, O14), or, with `job` None, a family-less one
        (amendment 1): a child handed the tenant's `pending` jobs, in the one supervision registry
        with no lease, then the publish state of each job its record names. A post-step that
        cannot start, or leaves no readable record, changes no row: its jobs stay `pending` for
        the next one. Either kind restarts the tenant's check clock when it ends."""
        post_step = self._post_step_argv
        assert post_step is not None  # a worker with learning slots has it (constructor)
        pending = tuple(await self._store.pending_publish(tenant))
        held = Held(_PostStepOf(tenant, job), kind=POST_STEP)
        key = f"{POST_STEP}:{job if job is not None else 'tenant:' + tenant}"
        self._held[key] = held
        self._checking.add(tenant)
        try:
            launch = PostStepLaunch(job, tenant, os.getpid(), pending)
            proc = await self._run_child(held, lambda: post_step(launch))
            if proc is None:
                return
            answer = await asyncio.to_thread(self._read_learning, tenant, lambda lane: lane.read_post_step(job))
        finally:
            self._held.pop(key, None)
            self._checking.discard(tenant)
            self._last_check[tenant] = time.monotonic()
        if answer is None:
            _logger.warning("%s: it left no readable record; the jobs it was handed stay pending", _what(held))
            return
        # A record left by an earlier check of the tenant is truthful too: a job it names is moved
        # only while still `pending`, so it can only confirm a publish that happened.
        published = [j for j in answer.published if j in pending]
        refused = [j for j in answer.refused if j in pending and j not in published]
        await self._store.record_publish(tenant, published=published, refused=refused)
        announce("learning_post_step", actor=SYSTEM, tenant_id=tenant, target=job if job is not None else tenant,
                 detail=f"published {len(published)} job(s); refused {len(refused)} job(s)")

    # -- the last write ---------------------------------------------------------------------------

    async def _write_end(self, held: Held, end: End | LearningOutcome) -> None:
        """The row's one end write (B4), made until it lands or there is nothing left to write.
        A failure that is an outage is retried each second while claims wait (B5). A value the
        store refuses never drops the decided ending, since a dropped one would lapse into a
        take-over that re-runs the job: it is written again with less (`_lesser_ends`). Any other
        failure decides nothing about the job: it is logged and the row left to lapse, as it is
        when even the barest end is refused. During a deliberate stop an outage gets one try: the
        stop gives up on it (B11)."""
        what = _what(held)
        key = _key(held)
        attempts: list[Any] = (_lesser_learning_ends(end) if isinstance(end, LearningOutcome)
                               else _lesser_ends(end))
        once = self._learning_end_once if isinstance(end, LearningOutcome) else self._end_once
        for attempt in attempts:
            if attempt is not end:
                _logger.error("%s: the store refused its end; writing it with less: %s", what, _what_end(attempt))
            while True:
                tried_stopping = self._stopping
                try:
                    await once(held, attempt)
                    return
                except Exception as fault:  # noqa: BLE001 — classified below
                    if is_refusal(fault):
                        _logger.error("%s: the store refused its end (%s)", what, _what_end(attempt), exc_info=True)
                        break
                    if not is_outage(fault):
                        _logger.exception("%s: its end could not be recorded and is dropped; its "
                                          "lease will lapse and it will be taken over", what)
                        return
                    self._note_store_fault(fault)
                    if tried_stopping:
                        _logger.warning("%s: its end could not be recorded while stopping; "
                                        "its lease will lapse on its own", what, exc_info=True)
                        return
                    self._end_failing.add(key)
                    _logger.warning("%s: its end could not be recorded (%s); retrying", what, fault)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stop_signal.wait(), timeout=END_RETRY_DELAY)
        _logger.error("%s: the store refused even its barest end; it is dropped, and its "
                      "lease will lapse and it will be taken over", what)

    async def _end_once(self, held: Held, end: End) -> None:
        """One try: the terminal stage (or hand-back) if the row is still `running`, else the
        holder's final cost and knowledge on the row someone else ended; a row that is gone or
        already accounted for needs nothing."""
        record = held.record
        inv, tenant = record.investigation_id, record.tenant_id
        if end.ending is not None:
            ending = end.ending
            written = await self._store.finish(
                tenant, inv, stage=ending.stage, disposition=ending.disposition, cost_usd=end.cost,
                knowledge=end.knowledge, failure_reason=ending.failure_reason,
                failure_message=ending.failure_message)
            what = ending.stage + (f" ({ending.failure_reason})" if ending.failure_reason else "")
        else:
            written = await self._store.hand_back(tenant, inv, cost_usd=end.cost, knowledge=end.knowledge)
            what = "handed back"
        if written is not None:
            _logger.info("investigation %s: %s", inv, what)
            return
        accounted = await self._store.write_accounting(tenant, inv, cost_usd=end.cost, knowledge=end.knowledge)
        if accounted is not None:
            _logger.info("investigation %s: the row had already ended; its final cost and knowledge are recorded", inv)
        else:
            _logger.info("investigation %s: the row is gone or already accounted for; nothing to write", inv)


def _lesser_ends(end: End) -> list[End]:
    """The end writes to try in turn when the store refuses one outright (#1343 review): the end
    as decided; then with its knowledge replaced by the unreadable-knowledge marker, a value the
    store is known to take; then the barest end, with no cost or knowledge, and for a decided
    ending `worker_error`, naming the refusal (a hand-back stays a hand-back)."""
    marker = job_lane.JobLane.unreadable_knowledge()
    ends = [end]
    if end.knowledge is not None and end.knowledge != marker:
        ends.append(End(end.ending, end.cost, marker))
    barest = End(None if end.ending is None else Ending(
        _FAILED, failure_reason=_WORKER_ERROR, failure_message="the store refused the job's ending as decided"),
        None, None)
    if barest != ends[-1]:
        ends.append(barest)
    return ends


def _lesser_learning_ends(end: LearningOutcome) -> list[LearningOutcome]:
    """`_lesser_ends` for a learning job: the end as decided; then the barest, which keeps the
    row's copied progress and, for a decided ending, is `worker_error` naming the refusal."""
    barest = (LearningOutcome(None) if end.status is None else LearningOutcome(
        _FAILED, _WORKER_ERROR, "the store refused the job's ending as decided"))
    return [end] if barest == end else [end, barest]


def _what_end(end: End | LearningOutcome) -> str:
    if isinstance(end, LearningOutcome):
        return "a hand-back" if end.status is None else end.status + (f" ({end.reason})" if end.reason else "")
    what = "a hand-back" if end.ending is None else end.ending.stage + (
        f" ({end.ending.failure_reason})" if end.ending.failure_reason else "")
    return f"{what}, cost {end.cost}, knowledge {'kept' if end.knowledge is not None else 'none'}"


def _key(held: Held) -> str:
    """The registry key of a held row."""
    record = held.record
    return str(record.learning_job_id if held.kind != INVESTIGATION else record.investigation_id)


def _what(held: Held) -> str:
    """How the log names a held entry."""
    if held.kind == POST_STEP and held.record.learning_job_id is None:
        return f"the family-less post-step of tenant {held.record.tenant_id}"
    names = {INVESTIGATION: "investigation", LEARNING: "learning job", POST_STEP: "the post-step after learning job"}
    return f"{names[held.kind]} {_key(held)}"


async def _end_tasks(tasks: list[asyncio.Task[None]]) -> None:
    """Cancel service tasks and wait for them to finish."""
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
