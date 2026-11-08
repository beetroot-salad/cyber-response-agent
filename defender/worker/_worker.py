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
in the same outage, and their next renewal has not had its chance."""
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
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender import _log
from defender.jobs import is_outage, is_refusal
from defender.box import Reaped, container_name
from defender.execution import kill_group, wait_group_gone
from defender.records import job_facts, job_lane
from defender.records.formats import DataRoot, digest_of
from defender.tenancy import data_root_for_child, data_root_from_path

from ._containers import Containers, DockerContainers
from ._held import End, Ending, Held

if TYPE_CHECKING:
    from defender.jobs import Claim

_logger = logging.getLogger(__name__)

#: How long an idle serving worker waits between claims (M10: a fixed interval, no NOTIFY).
POLL_INTERVAL = 1.0

#: The pause between tries of an end write that failed as an outage (B5).
END_RETRY_DELAY = 1.0

_RUN_PY = Path(__file__).resolve().parents[1] / "run.py"

_FAILED, _COMPLETED, _UNPARSEABLE = "failed", "completed", "unparseable"
_SETUP_REFUSED, _NO_REPORT, _WORKER_ERROR = "setup_refused", "no_report", "worker_error"


@dataclass(frozen=True)
class Launch:
    """What a child is started for: the investigation (its id is the run id), its tenant, and
    the worker's pid, which the child checks is its parent."""

    investigation_id: str
    tenant_id: str
    parent_pid: int


def run_argv(launch: Launch) -> list[str]:
    """The default child: `run.py --job <id> --tenant <T> --parent-pid <pid>`."""
    return [sys.executable, str(_RUN_PY), "--job", launch.investigation_id,
            "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]


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
    runs every `takeover_interval`."""

    def __init__(  # noqa: PLR0913 — the ratified signature
        self, store: Any, *, data_root: Path | DataRoot,
        child_argv: Callable[[Launch], list[str]] = run_argv,
        containers: Containers | None = None, slots: int = 3,
        clock: Callable[[], _dt.datetime], stop_grace: float = 30,
        renewal_interval: float = 1.0, cost_interval: float = 15.0, takeover_interval: float = 5.0,
        open_lane: Callable[[DataRoot, object], job_lane.JobLane] = job_lane.JobLane.open,
        store_call_limit: float = 10.0,
        spawn: Callable[..., Awaitable[asyncio.subprocess.Process]] = asyncio.create_subprocess_exec,
    ) -> None:
        if slots < 1:
            raise ValueError(f"a worker needs at least one slot, not {slots!r}")
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
        self._takeover: asyncio.Task[None] | None = None  # serving only; a stop ends it first
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
        renewal runs beside the loop until every row's last write has landed; serving, the
        take-over runs beside it until a stop begins (`_stop`)."""
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
                if stop is None:
                    break  # drained: nothing is queued
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
            self._takeover = asyncio.create_task(self._takeover_loop())
            services.append(self._takeover)
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
        """Claim one queued row into a task; False when nothing is queued."""
        if self._stopping:
            return False
        claim = await self._store.claim()
        if claim is None:
            return False
        held = Held(claim.record)
        self._held[claim.record.investigation_id] = held
        task = asyncio.create_task(self._run_row(claim, held))
        self._tasks.add(task)

        def _done(t: asyncio.Task[None]) -> None:
            self._tasks.discard(t)
            if on_done is not None:
                on_done()
        task.add_done_callback(_done)
        return True

    def _children(self) -> list[Held]:
        return [h for h in self._held.values() if h.proc is not None and h.proc.returncode is None]

    async def _stop(self) -> None:
        """The deliberate stop, in order: no more claims and no more take-over (a pass under way
        is cancelled and waited for), each child ended (`_end_child`), then wait for the tasks:
        each runs its backstop and its last write, which for a row the stop ended is the hand-back
        (B11). A hand-back lapses the row's lease and the row leaves `_held`, so a take-over still
        running here would take this worker's own rows over; other workers' passes retry them.
        Renewal keeps running meanwhile (the caller ends it)."""
        self._stopping = True
        self._stop_signal.set()
        if self._takeover is not None:
            await _end_tasks([self._takeover])
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
            if not await _end_group(proc.pid):
                held.group_left = True
            await proc.wait()

    # -- the lease: renewal, cost so far, take-over -------------------------------------------------

    async def _renewal_loop(self) -> None:
        """Every `renewal_interval`, renew every held row in one store call. A call that errors
        covers nothing and fences nothing (r5 item 14): claims wait and the next tick retries."""
        while True:
            await self._renew_once()
            await asyncio.sleep(self._renewal_interval)

    async def _renew_once(self) -> None:
        held = dict(self._held)
        if not held:
            self._renewal_failing = False
            return
        costs = self._costs_due(held)
        try:
            async with asyncio.timeout(self._store_call_limit):  # not `wait_for`: on 3.11 it can lose a cancel
                covered = set(await self._store.renew(set(held), costs=costs))
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

    def _costs_due(self, held: dict[str, Held]) -> dict[str, float] | None:
        """The figures this renewal copies (B2), or None between cost ticks."""
        if time.monotonic() - self._last_cost_copy < self._cost_interval:
            return None
        return {inv: h.cost_so_far for inv, h in held.items() if h.cost_so_far is not None}

    def _fence(self, inv: str, held: Held) -> None:
        """A renewal that succeeded no longer covers the row (cancelled, taken over or deleted,
        B3): its child is ended at once; the row's one end path runs as for any child exit. A row
        fenced before its child exists is never launched (`_run_claimed`)."""
        if held.fenced or (held.proc is not None and held.proc.returncode is not None):
            return  # already fenced, or its child already exited: the row is writing its own end
        held.fenced = True
        _logger.warning("investigation %s: it was cancelled, taken over or deleted; ending its child", inv)
        held.enders.append(asyncio.create_task(self._end_child(held)))

    async def _takeover_loop(self) -> None:
        """Every `takeover_interval`, take over every lapsed row this worker does not hold (B7),
        unless this worker's own store calls hit an outage within the last lease. A pass that
        raises is logged; the next tick tries again. Serving only, until a stop begins."""
        while True:
            if self._store_settled():
                try:
                    async with asyncio.timeout(self._store_call_limit):  # not `wait_for`: on 3.11 it can lose a cancel
                        await self._store.take_over(held=frozenset(self._held))
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
        proc = await self._run_child(held, token, Launch(inv, tenant, os.getpid()))
        if isinstance(proc, End):
            return proc
        returncode = await proc.wait()
        _logger.info("investigation %s: child %d %s after %s", inv, proc.pid,
                     _exit_words(returncode), self._clock() - started)
        ending, cost, knowledge = await asyncio.to_thread(self._read_ending, record, returncode)
        if held.signalled and not ending.decided_by_run:  # R1: an ending the run itself decided wins over the stop
            return End(None, cost, knowledge)
        return End(ending, cost, knowledge)

    async def _run_child(self, held: Held, token: str, launch: Launch) -> asyncio.subprocess.Process | End:
        """Start the row's child and wait for it to end, then run its cleanup. The task owns its
        child: cancelled, it ends the child and writes nothing."""
        inv = launch.investigation_id
        proc: asyncio.subprocess.Process | None = None
        cost_task: asyncio.Task[None] | None = None
        # The start runs as its own task, so a cancel cannot land inside it and lose the child
        # it makes (r7 D-ac): a cancelled row waits for it, and the child is ended below.
        spawn = asyncio.ensure_future(self._spawn(launch))
        try:
            try:
                proc = await asyncio.shield(spawn)
            except asyncio.CancelledError:
                proc = await _spawn_outcome(spawn)
                held.proc = proc
                _logger.warning("investigation %s: the worker is leaving; ending its child", inv)
                await self._end_child(held)
                raise
            except (OSError, ValueError) as unstarted:
                _logger.error("investigation %s: the child could not be started: %s", inv, unstarted)
                return End(Ending(_FAILED, failure_reason=_WORKER_ERROR,
                                  failure_message="the worker could not start the job's child process"),
                           0.0, None)
            held.proc = proc
            cost_task = asyncio.create_task(self._cost_loop(held))
            await self._wait_for_child(held, proc)
        finally:
            if cost_task is not None:
                await _end_tasks([cost_task])
            if proc is not None:
                # One cleanup however the row ended (r7 D-ac): whatever the child left running in
                # its session is killed and waited for, then its box, if it outlived it, is
                # removed. The removal runs however the wait ends, a cancel included; a group
                # an earlier wait already gave up on is killed again but not waited for twice.
                try:
                    if held.group_left:
                        kill_group(proc.pid)
                    elif not await _end_group(proc.pid):
                        held.group_left = True
                finally:
                    await self._backstop(inv, token)
        return proc

    async def _wait_for_child(self, held: Held, proc: asyncio.subprocess.Process) -> None:
        try:
            if self._stopping or held.fenced:  # spawned as the stop or a fence landed
                await self._end_child(held, by_stop=self._stopping)
            await proc.wait()
        except asyncio.CancelledError:
            # The task owns its child: cancelled (the loop itself was cancelled), it ends the
            # child, and writes nothing.
            _logger.warning("investigation %s: the worker is leaving; ending child %d",
                            held.record.investigation_id, proc.pid)
            await self._end_child(held)
            raise

    async def _spawn(self, launch: Launch) -> asyncio.subprocess.Process:
        """The job's child, in a session of its own (its group id is its pid), output inherited."""
        return await self._create_process(
            *self._child_argv(launch),
            stdin=subprocess.DEVNULL, stdout=None, stderr=None, start_new_session=True,
            env={**os.environ, "DEFENDER_DATA_ROOT": str(data_root_for_child(self._data_root))})

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

    # -- the last write ---------------------------------------------------------------------------

    async def _write_end(self, held: Held, end: End) -> None:
        """The row's one end write (B4), made until it lands or there is nothing left to write.
        A failure that is an outage is retried each second while claims wait (B5). A value the
        store refuses never drops the decided ending, since a dropped one would lapse into a
        take-over that re-runs the job: it is written again with less (`_lesser_ends`). Any other
        failure decides nothing about the job: it is logged and the row left to lapse, as it is
        when even the barest end is refused. During a deliberate stop an outage gets one try: the
        stop gives up on it (B11)."""
        inv = held.record.investigation_id
        for attempt in _lesser_ends(end):
            if attempt is not end:
                _logger.error("investigation %s: the store refused its end; writing it with less: %s",
                              inv, _what_end(attempt))
            while True:
                tried_stopping = self._stopping
                try:
                    await self._end_once(held, attempt)
                    return
                except Exception as fault:  # noqa: BLE001 — classified below
                    if is_refusal(fault):
                        _logger.error("investigation %s: the store refused its end (%s)", inv, _what_end(attempt),
                                      exc_info=True)
                        break
                    if not is_outage(fault):
                        _logger.exception("investigation %s: its end could not be recorded and is dropped; its "
                                          "lease will lapse and it will be taken over", inv)
                        return
                    self._note_store_fault(fault)
                    if tried_stopping:
                        _logger.warning("investigation %s: its end could not be recorded while stopping; "
                                        "its lease will lapse on its own", inv, exc_info=True)
                        return
                    self._end_failing.add(inv)
                    _logger.warning("investigation %s: its end could not be recorded (%s); retrying", inv, fault)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stop_signal.wait(), timeout=END_RETRY_DELAY)
        _logger.error("investigation %s: the store refused even its barest end; it is dropped, and its "
                      "lease will lapse and it will be taken over", inv)

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


def _what_end(end: End) -> str:
    what = "a hand-back" if end.ending is None else end.ending.stage + (
        f" ({end.ending.failure_reason})" if end.ending.failure_reason else "")
    return f"{what}, cost {end.cost}, knowledge {'kept' if end.knowledge is not None else 'none'}"


async def _end_group(pgid: int) -> bool:
    """The child's whole group killed and waited for: the SIGKILL goes out here, at once, so a
    cancel landing in the wait cannot keep it from being sent; the wait for every member to be
    gone (`wait_group_gone`, bounded, logged if one never goes) runs in a thread. False when a
    member still ran at the limit."""
    kill_group(pgid)
    return await asyncio.to_thread(wait_group_gone, pgid)


async def _end_tasks(tasks: list[asyncio.Task[None]]) -> None:
    """Cancel service tasks and wait for them to finish."""
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
