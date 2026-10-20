"""Oracle attempts settle box workers across AnyIO and direct asyncio cancellation."""
from __future__ import annotations

import asyncio
import subprocess
import threading

import anyio
import pytest

from defender import box
from defender.learning.branch.estate._oracle_attempt import _AttemptBox, _AttemptFailed, _Run
from defender.learning.branch.estate.oracle import _within_deadline
from defender.runtime.exception_groups import carried


class _Worker:
    def __init__(self, *, fault=None, stop_fails=False, lost=False, release=None):
        self.started = threading.Event()
        self.shutdown = threading.Event()
        self.finished = threading.Event()
        self.calls = []
        self.fault = fault
        self.stop_fails = stop_fails
        self.lost = lost
        self.release = release
        self.owner = _AttemptBox(self.factory)

    def docker(self, argv):
        self.calls.append(argv)
        if argv[1] == "stop":
            self.shutdown.set()
        return subprocess.CompletedProcess(argv, 0, "running" if self.stop_fails else "exited", "")

    def factory(self):
        return box.BoxExecutor(name="owned-worker", docker=self.docker,
                               transport=box._DockerTransport("owned-worker", box.BoxSpec()))

    def work(self):
        resource = self.owner.get()
        self.started.set()
        try:
            assert self.shutdown.wait(5), "deadline never stopped the box"
            if self.release is not None:
                assert self.release.wait(5), "worker settlement was never released"
            if self.fault is not None:
                raise self.fault
            if self.lost:
                self.owner.lost(resource)
            return "late result"
        finally:
            self.finished.set()

    def removed(self):
        return [call for call in self.calls if call[1:3] == ["rm", "-f"]]


@pytest.mark.parametrize(("fault", "lost"), [
    (None, False), (None, True), (box.BoxOutputLimitExceeded(), False),
    (RuntimeError("worker failed"), False),
])
def test_deadline_stops_and_settles_worker_without_accepting_late_result(fault, lost):
    worker = _Worker(fault=fault, lost=lost)
    run = _Run(door=None, deadline=0.1, box=worker.owner)

    async def work():
        return await run.box_work(worker.work)

    try:
        if fault is None:
            assert anyio.run(_within_deadline, run, work) == (False, None)
        else:
            with pytest.raises(type(fault)) as caught:
                anyio.run(_within_deadline, run, work)
            assert caught.value is fault
        assert worker.started.is_set()
        assert worker.finished.is_set()
        assert not worker.removed(), "scratch/container removal preceded settlement"
        assert not run.has_box_work
    finally:
        worker.shutdown.set()
        worker.owner.stop()
    assert worker.removed()


@pytest.mark.parametrize("main_fails", [False, True])
def test_direct_tool_task_cancellation_cannot_discard_a_fatal_worker(main_fails):
    fault = box.BoxOutputLimitExceeded()
    worker = _Worker(fault=fault)
    run = _Run(door=None, deadline=10, box=worker.owner)
    main_fault = _AttemptFailed("ordinary attempt failure")

    async def work():
        tool = asyncio.create_task(run.box_work(worker.work))
        assert await anyio.to_thread.run_sync(worker.started.wait, 5)
        tool.cancel()  # how the agent framework cancels a tool task
        with pytest.raises(asyncio.CancelledError):
            await tool
        if main_fails:
            raise main_fault
        return "submitted"

    try:
        with pytest.raises((box.BoxOutputLimitExceeded, ExceptionGroup)) as caught:
            anyio.run(_within_deadline, run, work)
        assert carried(caught.value, box.BoxOutputLimitExceeded) is fault
        if main_fails:
            assert carried(caught.value, _AttemptFailed) is main_fault
        assert worker.finished.is_set()
        assert not run.has_box_work
    finally:
        worker.shutdown.set()
        worker.owner.stop()


def test_external_cancellation_also_stops_and_drains_owned_worker():
    worker = _Worker()
    run = _Run(door=None, deadline=10, box=worker.owner)

    async def work():
        return await run.box_work(worker.work)

    async def cancel():
        attempt = asyncio.create_task(_within_deadline(run, work))
        assert await anyio.to_thread.run_sync(worker.started.wait, 5)
        attempt.cancel()
        with pytest.raises(asyncio.CancelledError):
            await attempt
        assert worker.finished.is_set()
        assert not run.has_box_work

    try:
        anyio.run(cancel)
    finally:
        worker.shutdown.set()
        worker.owner.stop()


def test_failed_stop_proof_is_fatal_after_the_worker_settles():
    worker = _Worker(stop_fails=True)
    run = _Run(door=None, deadline=0.1, box=worker.owner)

    async def work():
        return await run.box_work(worker.work)

    try:
        with pytest.raises(box.BoxFault, match="could not stop"):
            anyio.run(_within_deadline, run, work)
        assert worker.finished.is_set()
    finally:
        worker.shutdown.set()
        worker.owner.stop()


def test_external_read_can_still_be_abandoned_at_deadline():
    release = threading.Event()
    finished = threading.Event()
    run = _Run(door=None, deadline=0.1)

    def read():
        try:
            release.wait(5)
        finally:
            finished.set()

    async def work():
        return await run.blocking(read)

    try:
        assert anyio.run(_within_deadline, run, work) == (False, None)
        assert not finished.is_set()
    finally:
        release.set()
        assert finished.wait(5)


def test_startup_finishing_after_cancellation_is_discarded_before_worker_settles():
    release_startup = threading.Event()
    worker_finished = threading.Event()
    calls = []

    def docker(argv):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "exited", "")

    def factory():
        assert release_startup.wait(5)
        return box.BoxExecutor(name="late-start", docker=docker,
                               transport=box._DockerTransport("late-start", box.BoxSpec()))

    class StartupOwner(_AttemptBox):
        def cancel(self):
            super().cancel()
            release_startup.set()

    owner = StartupOwner(factory)
    run = _Run(door=None, deadline=0.1, box=owner)

    def start():
        try:
            return owner.get()
        finally:
            worker_finished.set()

    async def work():
        return await run.box_work(start)

    try:
        with pytest.raises(_AttemptFailed, match="already ended"):
            anyio.run(_within_deadline, run, work)
        assert worker_finished.is_set()
        assert ["docker", "rm", "-f", "late-start"] in calls
        assert not run.has_box_work
    finally:
        release_startup.set()
        owner.stop()


def test_external_reads_cannot_starve_owned_execution_or_its_shutdown():
    release_read = threading.Event()
    read_started = threading.Event()
    worker = _Worker()

    def external_read():
        read_started.set()
        release_read.wait(5)

    async def work(run):
        return await run.box_work(worker.work)

    async def scenario():
        # Fill the pool used by abandonable external reads. Owned execution and shutdown
        # must remain able to run, including while the box worker is waiting for shutdown.
        limiter = anyio.to_thread.current_default_thread_limiter()
        original = limiter.total_tokens
        limiter.total_tokens = 1
        try:
            async with anyio.create_task_group() as group:
                group.start_soon(anyio.to_thread.run_sync, external_read)
                while not read_started.is_set():
                    await anyio.sleep(0.001)
                run = _Run(door=None, deadline=0.1, box=worker.owner)
                try:
                    assert await _within_deadline(run, lambda: work(run)) == (False, None)
                    assert worker.started.is_set()
                    assert worker.finished.is_set()
                finally:
                    release_read.set()
        finally:
            limiter.total_tokens = original

    try:
        anyio.run(scenario)
    finally:
        release_read.set()
        worker.shutdown.set()
        worker.owner.stop()


@pytest.mark.parametrize("worker_fails", [False, True])
@pytest.mark.parametrize("stop_fails", [False, True])
def test_caller_cancellation_preserves_all_settlement_failures(worker_fails, stop_fails):
    fault = box.BoxOutputLimitExceeded() if worker_fails else None
    worker = _Worker(fault=fault, stop_fails=stop_fails)
    run = _Run(door=None, deadline=10, box=worker.owner)

    async def work():
        return await run.box_work(worker.work)

    async def cancel():
        attempt = asyncio.create_task(_within_deadline(run, work))
        assert await anyio.to_thread.run_sync(worker.started.wait, 5)
        attempt.cancel("caller ended the attempt")
        expected = BaseExceptionGroup if worker_fails or stop_fails else asyncio.CancelledError
        with pytest.raises(expected) as caught:
            await attempt
        assert carried(caught.value, asyncio.CancelledError) is not None
        if worker_fails:
            assert carried(caught.value, box.BoxOutputLimitExceeded) is fault
        if stop_fails:
            leaves = _leaves(caught.value)
            assert any(isinstance(leaf, box.BoxFault) and "could not stop" in str(leaf)
                       for leaf in leaves)
        assert worker.finished.is_set()
        assert not run.has_box_work
        assert not worker.removed()

    try:
        anyio.run(cancel)
    finally:
        worker.shutdown.set()
        worker.owner.stop()


def _leaves(exc):
    if isinstance(exc, BaseExceptionGroup):
        return [leaf for child in exc.exceptions for leaf in _leaves(child)]
    return [exc]


@pytest.mark.parametrize("worker_fails", [False, True])
@pytest.mark.parametrize("stop_fails", [False, True])
def test_repeated_caller_cancellation_cannot_interrupt_settlement(worker_fails, stop_fails):
    release = threading.Event()
    fault = box.BoxOutputLimitExceeded() if worker_fails else None
    worker = _Worker(fault=fault, stop_fails=stop_fails, release=release)
    run = _Run(door=None, deadline=10, box=worker.owner)

    async def work():
        return await run.box_work(worker.work)

    async def cancel():
        attempt = asyncio.create_task(_within_deadline(run, work))
        assert await anyio.to_thread.run_sync(worker.started.wait, 5)
        attempt.cancel("first cancellation")
        assert await anyio.to_thread.run_sync(worker.shutdown.wait, 5)
        for message in ("second cancellation", "third cancellation"):
            attempt.cancel(message)
            await asyncio.sleep(0)
            assert not attempt.done(), "caller cancellation interrupted settlement"
        assert not worker.finished.is_set()
        release.set()
        expected = BaseExceptionGroup if worker_fails or stop_fails else asyncio.CancelledError
        with pytest.raises(expected) as caught:
            await attempt
        cancellation = carried(caught.value, asyncio.CancelledError)
        assert cancellation is not None
        assert cancellation.args == ("first cancellation",)
        if worker_fails:
            assert carried(caught.value, box.BoxOutputLimitExceeded) is fault
        assert worker.finished.is_set()
        assert not run.has_box_work
        if stop_fails:
            assert any(isinstance(leaf, box.BoxFault) and "could not stop" in str(leaf)
                       for leaf in _leaves(caught.value))

    try:
        anyio.run(cancel)
    finally:
        release.set()
        worker.shutdown.set()
        worker.owner.stop()


@pytest.mark.parametrize("worker_fails", [False, True])
def test_enclosing_anyio_cancellation_settles_before_leaving_scope(worker_fails):
    fault = box.BoxOutputLimitExceeded() if worker_fails else None
    worker = _Worker(fault=fault)
    run = _Run(door=None, deadline=10, box=worker.owner)

    async def work():
        return await run.box_work(worker.work)

    async def scenario():
        async with anyio.create_task_group() as group:
            async def cancel(scope):
                assert await anyio.to_thread.run_sync(worker.started.wait, 5)
                scope.cancel()

            with anyio.CancelScope() as scope:
                group.start_soon(cancel, scope)
                if worker_fails:
                    with pytest.raises(BaseExceptionGroup) as caught:
                        await _within_deadline(run, work)
                    assert carried(caught.value, asyncio.CancelledError) is not None
                    assert carried(caught.value, box.BoxOutputLimitExceeded) is fault
                else:
                    await _within_deadline(run, work)
                    pytest.fail("cancelled attempt returned successfully")
            assert worker.finished.is_set()
            assert not run.has_box_work

    try:
        anyio.run(scenario)
    finally:
        worker.shutdown.set()
        worker.owner.stop()


def test_base_exception_leaving_work_is_preserved_after_settlement():
    fault = box.BoxOutputLimitExceeded()
    cancellation = asyncio.CancelledError("tool cancellation")
    run = _Run(door=None, deadline=10)

    async def work():
        raise BaseExceptionGroup("tool exit", [cancellation, fault])

    with pytest.raises(BaseExceptionGroup) as caught:
        anyio.run(_within_deadline, run, work)
    assert carried(caught.value, asyncio.CancelledError) is cancellation
    assert carried(caught.value, box.BoxOutputLimitExceeded) is fault
    assert not run.has_box_work


def test_work_suppressing_deadline_cancellation_cannot_return_a_late_result():
    run = _Run(door=None, deadline=0)

    async def work():
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            return "late result"

    assert anyio.run(_within_deadline, run, work) == (False, None)
