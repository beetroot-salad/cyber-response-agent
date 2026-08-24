from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from .metrics import Metrics
from .models import Job
from .queue import RecordingQueue
from .store import InMemoryJobStore


class JobService:
    def __init__(
        self,
        store: InMemoryJobStore,
        queue: RecordingQueue,
        metrics: Metrics,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._queue = queue
        self._metrics = metrics
        self._clock = clock

    async def submit(
        self, tenant_id: str, idempotency_key: str, payload: dict[str, Any]
    ) -> Job:
        job = Job(
            id=str(uuid4()),
            tenant_id=tenant_id,
            payload=dict(payload),
            created_at=self._clock(),
        )
        await self._store.save(job)
        await self._queue.publish(job)
        self._metrics.increment("jobs.submitted")
        return job
