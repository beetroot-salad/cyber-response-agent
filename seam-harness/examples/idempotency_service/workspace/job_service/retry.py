from __future__ import annotations

from typing import Any

from .models import Job
from .service import JobService


async def submit_retry(
    service: JobService,
    tenant_id: str,
    idempotency_key: str,
    payload: dict[str, Any],
) -> Job:
    return await service.submit(tenant_id, idempotency_key, payload)
