"""The worker (#1342): claims queued investigations up to its slots, runs each as a child
process through the job lane, and records the one terminal stage the child's host records say.

Per claimed row, as a task: a box token is minted for the claim, the tenant's state, read by the
claim itself, must be `active` (#1342 r7 R7-1: no host lock is taken and the worker is recorded as
no holder, so a teardown never waits for it or signals it), the launch record (carrying the token)
and alert file are written beside the run folder (the tenant's runs container must exist; the
worker never makes it), the child is spawned from the event loop's thread in a session of its own
with its output inherited, its exit awaited, a leftover box carrying the claim's token removed
(the backstop), and the job-end record read for the stage. The task owns its child: however the
row ends once the child exists (its exit, a stop, a cancel, even mid-spawn), the child's process
group is killed and the backstop runs (r7 D-ac). A deliberate stop ends the children and writes no row (D3):
such rows stay `running` until #1343."""
from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import logging
import os
import signal
import subprocess
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender import _log
from defender.box import Reaped, container_name
from defender.execution import kill_group
from defender.records import job_facts, job_lane
from defender.records.formats import DataRoot, digest_of
from defender.tenancy import data_root_for_child, data_root_from_path

from ._containers import Containers, DockerContainers

if TYPE_CHECKING:
    from defender.jobs import Claim

_logger = logging.getLogger(__name__)

#: How long an idle serving worker waits between claims (M10: a fixed interval, no NOTIFY).
POLL_INTERVAL = 1.0

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


@dataclass(frozen=True)
class _Ending:
    """The terminal write for one row."""

    stage: str
    disposition: str | None = None
    failure_reason: str | None = None
    failure_message: str | None = None


def _exit_words(returncode: int) -> str:
    return (f"was killed by signal {-returncode}" if returncode < 0
            else f"exited with code {returncode}")


def _ending_from(end: job_lane.JobEnd | None, returncode: int,
                 disposition: Callable[[], str | None]) -> _Ending:
    """Rules 1-5 (O8, M9): the stage from the job-end record alone, and, once the host committed
    a report and the scrub walked the tree, the report's disposition (read only then)."""
    if end is None:
        return _Ending(_FAILED, failure_reason=_NO_REPORT,
                       failure_message=f"the run left no job-end record; the child {_exit_words(returncode)}")
    if end.setup == job_facts.SETUP_REFUSED:
        return _Ending(_FAILED, failure_reason=_SETUP_REFUSED,
                       failure_message="run setup refused the job")
    if end.box == job_facts.BOX_START_FAILED:
        return _Ending(_FAILED, failure_reason=_WORKER_ERROR,
                       failure_message="the run's box did not start")
    if end.report_committed and end.scrub_verified:
        found = disposition()
        return _Ending(_COMPLETED, disposition=found) if found is not None else _Ending(_UNPARSEABLE)
    if end.setup != job_facts.SETUP_DONE:
        why = "run setup crashed"
    elif not end.report_committed:
        why = "the host committed no report"
    else:
        why = "the scrub did not verify the run folder after the box stopped"
    return _Ending(_FAILED, failure_reason=_NO_REPORT, failure_message=why)


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
    queued and waits for every slot's task; `serve()` polls until SIGTERM/SIGINT. A tenant's state
    comes with its claim (#1342 r7 R7-1); the children read their tenant records from
    `DEFENDER_DATABASE_DSN`, which they inherit."""

    def __init__(  # noqa: PLR0913 — the ratified signature
        self, store: Any, *, data_root: Path | DataRoot,
        child_argv: Callable[[Launch], list[str]] = run_argv,
        containers: Containers | None = None, slots: int = 3,
        clock: Callable[[], _dt.datetime], stop_grace: float = 30,
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
        self._tasks: set[asyncio.Task[None]] = set()
        self._children: dict[str, asyncio.subprocess.Process] = {}
        self._stopping = False

    # -- entry points -----------------------------------------------------------------------------

    async def drain(self) -> None:
        """Claim while a slot is free until nothing is queued, then wait for every task. A store
        fault ends it (raised) and, like a cancellation, leaves no child behind (`_claim_loop`)."""
        await self._claim_loop(stop=None)

    async def serve(self) -> None:
        """Poll for queued rows at a fixed interval until SIGTERM or SIGINT, then stop: each child
        gets SIGTERM, a child still alive after `stop_grace` has its group killed, the backstop
        runs, and no row is written (D3). A store fault is logged and the claim retried. Installs
        its own handlers and removes them on return."""
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
        """The one claim loop of `drain` and `serve`: claim while a slot is free, else wait for a
        slot to free (or, serving, for the poll interval or the stop).

        Draining (`stop` is None), the loop ends once a claim finds nothing queued, then waits
        for every task; a store fault is raised. Serving, a store fault is logged and retried,
        and the stop is the deliberate one (`_stop`). However the loop leaves by an exception
        (a store fault, a cancellation), no row's task is abandoned: each is cancelled, which
        ends its child and runs its backstop, and none writes its row."""
        wake = asyncio.Event()
        try:
            while stop is None or not stop.is_set():
                wake.clear()  # before the claim: a slot freed while it runs wakes the wait below
                if len(self._tasks) < self._slots:
                    if await self._claim_or_retry(on_done=wake.set, retry=stop is not None):
                        continue
                    if stop is None:
                        break  # drained: nothing is queued
                await self._wait(wake, stop)
            if stop is None:
                if self._tasks:
                    await asyncio.wait(set(self._tasks))
            else:
                _logger.info("the worker was asked to stop; ending %d run(s)", len(self._children))
                await self._stop()
        except BaseException:
            await self._abandon()
            raise

    async def _claim_or_retry(self, *, on_done: Callable[[], None], retry: bool) -> bool:
        """`_claim_one`; with `retry`, a store fault is logged and read as nothing claimed."""
        if not retry:
            return await self._claim_one(on_done=on_done)
        try:
            return await self._claim_one(on_done=on_done)
        except Exception:  # noqa: BLE001 — a store fault is waited out, never ends serving
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
        task = asyncio.create_task(self._run_row(claim))
        self._tasks.add(task)

        def _done(t: asyncio.Task[None]) -> None:
            self._tasks.discard(t)
            if on_done is not None:
                on_done()
        task.add_done_callback(_done)
        return True

    async def _stop(self) -> None:
        """The deliberate stop: no more claims, each child ended (`_end_child`), then wait for the
        tasks (each runs its backstop and writes nothing)."""
        self._stopping = True
        await asyncio.gather(*(self._end_child(p) for p in list(self._children.values())))
        if self._tasks:
            await asyncio.wait(set(self._tasks))

    async def _abandon(self) -> None:
        """The loop is leaving by an exception: no more claims and no row written (as for a
        deliberate stop), and each task cancelled, which ends its child and runs its backstop
        (`_run_claimed`); then wait for the tasks."""
        self._stopping = True
        tasks = set(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks)

    async def _end_child(self, proc: asyncio.subprocess.Process) -> None:
        """SIGTERM, then after `stop_grace` SIGKILL to the child's whole group (its own session,
        so its group id is its pid and the worker is not in it)."""
        with contextlib.suppress(ProcessLookupError):
            proc.send_signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(asyncio.shield(proc.wait()), timeout=self._stop_grace)
        except TimeoutError:
            _logger.warning("child %d did not end within %gs of SIGTERM; killing its group",
                            proc.pid, self._stop_grace)
            kill_group(proc.pid)
            await proc.wait()

    # -- one row ----------------------------------------------------------------------------------

    async def _run_row(self, claim: Claim) -> None:
        record = claim.record
        inv, tenant = record.investigation_id, record.tenant_id
        if self._stopping:  # D3: claimed as the stop landed; the row stays running, nothing launched
            return
        with _log.log_context(run_id=inv, tenant_id=tenant):
            try:
                await self._run_claimed(record, claim.tenant_state)
            except Exception:  # noqa: BLE001 — one row's fault never ends the worker
                _logger.exception("investigation %s: the worker failed while running it", inv)
                try:
                    await self._finish(record, _Ending(_FAILED, failure_reason=_WORKER_ERROR,
                                                      failure_message="the worker failed while running the job"),
                                       cost=None, knowledge=None)
                except Exception:  # noqa: BLE001 — the row stays running; #1343 reclaims it
                    _logger.exception("investigation %s: its failure could not be recorded", inv)

    async def _run_claimed(self, record: Any, tenant_state: str) -> None:
        inv, tenant = record.investigation_id, record.tenant_id
        started = self._clock()
        # This claim's box token (#1342 r5 C1): the child's box is stamped with it, and the
        # backstop removes only a container that carries it.
        token = uuid.uuid4().hex
        try:
            await self._write_launch(record, token, tenant_state)
        except _WorkerFault as fault:
            _logger.error("investigation %s: %s", inv, fault)
            await self._finish(record, _Ending(_FAILED, failure_reason=_WORKER_ERROR,
                                              failure_message=str(fault)), cost=0.0, knowledge=None)
            return
        if self._stopping:  # D3: claimed but not started; the row stays running
            return
        proc: asyncio.subprocess.Process | None = None
        # The start runs as its own task, so a cancel cannot land inside it and lose the child
        # it makes (r7 D-ac): a cancelled row waits for it, and the child is ended below.
        spawn = asyncio.ensure_future(self._spawn(Launch(inv, tenant, os.getpid())))
        try:
            try:
                proc = await asyncio.shield(spawn)
            except asyncio.CancelledError:
                proc = await _spawn_outcome(spawn)
                if proc is not None:
                    _logger.warning("investigation %s: the worker is leaving; ending child %d", inv, proc.pid)
                    await self._end_child(proc)
                raise
            except (OSError, ValueError) as unstarted:
                _logger.error("investigation %s: the child could not be started: %s", inv, unstarted)
                await self._finish(record, _Ending(_FAILED, failure_reason=_WORKER_ERROR,
                                                  failure_message="the worker could not start the job's child process"),
                                   cost=0.0, knowledge=None)
                return
            self._children[inv] = proc
            try:
                if self._stopping:  # spawned while the stop was ending the others
                    await self._end_child(proc)
                returncode = await proc.wait()
            except asyncio.CancelledError:
                # The task owns its child: cancelled (the claim loop left by a fault, or was itself
                # cancelled), it ends the child, and writes no row.
                _logger.warning("investigation %s: the worker is leaving; ending child %d", inv, proc.pid)
                await self._end_child(proc)
                raise
        finally:
            if proc is not None:
                self._children.pop(inv, None)
                # One cleanup however the row ended (r7 D-ac): whatever the child left running in
                # its session dies with it, then its box, if it outlived it, is removed.
                kill_group(proc.pid)
                await self._backstop(inv, token)
        _logger.info("investigation %s: child %d %s after %s", inv, proc.pid,
                     _exit_words(returncode), self._clock() - started)
        if self._stopping:  # D3: a deliberate stop writes no row
            return
        ending, cost, knowledge = await asyncio.to_thread(self._read_ending, record, returncode)
        await self._finish(record, ending, cost=cost, knowledge=knowledge)

    async def _spawn(self, launch: Launch) -> asyncio.subprocess.Process:
        """The job's child, in a session of its own (its group id is its pid), output inherited."""
        return await asyncio.create_subprocess_exec(
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
            alert_id=record.alert_id, digest=digest_of(alert.raw), label=alert.title,
            box_token=token)
        await asyncio.to_thread(self._write_launch_files, launch, alert.raw)

    def _write_launch_files(self, launch: job_lane.LaunchRecord, raw: bytes) -> None:
        try:
            lane = job_lane.JobLane.open(self._data_root, launch.tenant_id)
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

    def _read_ending(self, record: Any, returncode: int) -> tuple[_Ending, float | None, dict | None]:
        """The stage, cost and knowledge from the host records, through the job lane (in a thread)."""
        inv = record.investigation_id
        try:
            lane = job_lane.JobLane.open(self._data_root, record.tenant_id)
        except job_lane.JobLaneRefused as refused:
            _logger.error("investigation %s: reading its records: %s", inv, refused)
            return (_Ending(_FAILED, failure_reason=_WORKER_ERROR,
                            failure_message="the tenant's runs container could not be read after the run"),
                    None, None)
        with lane:
            ending = _ending_from(lane.read_job_end(inv), returncode, lambda: lane.report_disposition(inv))
            cost: float | None
            try:
                cost = lane.cost(inv)
            except job_lane.CostUnreadable as unreadable:
                _logger.warning("investigation %s: its cost is unknown: %s", inv, unreadable)
                cost = None
            return ending, cost, lane.knowledge(inv)

    async def _finish(self, record: Any, ending: _Ending, *, cost: float | None,
                      knowledge: dict | None) -> None:
        inv = record.investigation_id
        if self._stopping:  # D3: a deliberate stop writes no row
            _logger.info("investigation %s: the worker is stopping; the row stays running", inv)
            return
        written = await self._store.finish(
            record.tenant_id, inv, stage=ending.stage, disposition=ending.disposition,
            cost_usd=cost, knowledge=knowledge, failure_reason=ending.failure_reason,
            failure_message=ending.failure_message)
        if written is None:
            _logger.warning("investigation %s: the row is no longer running; its %s finish changed "
                            "nothing and the worker leaves it", inv, ending.stage)
            return
        _logger.info("investigation %s: %s%s", inv, ending.stage,
                     f" ({ending.failure_reason})" if ending.failure_reason else "")
