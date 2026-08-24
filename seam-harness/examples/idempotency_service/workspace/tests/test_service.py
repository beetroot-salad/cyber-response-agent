from __future__ import annotations

import asyncio

from job_service.metrics import Metrics
from job_service.queue import RecordingQueue
from job_service.service import JobService
from job_service.store import InMemoryJobStore


def test_submit_creates_and_publishes_a_job() -> None:
    async def scenario() -> None:
        store = InMemoryJobStore()
        queue = RecordingQueue()
        metrics = Metrics()
        service = JobService(store, queue, metrics, clock=lambda: 10.0)

        job = await service.submit("tenant-a", "request-1", {"kind": "export"})

        assert await store.get(job.id) == job
        assert queue.published == [job]
        assert metrics.counts == {"jobs.submitted": 1}

    asyncio.run(scenario())


def test_different_submissions_create_distinct_jobs() -> None:
    async def scenario() -> None:
        service = JobService(InMemoryJobStore(), RecordingQueue(), Metrics())

        first = await service.submit("tenant-a", "request-1", {"item": 1})
        second = await service.submit("tenant-a", "request-2", {"item": 2})

        assert first.id != second.id

    asyncio.run(scenario())
