from __future__ import annotations

from .models import Job


class RecordingQueue:
    def __init__(self) -> None:
        self.published: list[Job] = []

    async def publish(self, job: Job) -> None:
        self.published.append(job)
