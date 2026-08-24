from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Job:
    id: str
    tenant_id: str
    payload: dict[str, Any]
    created_at: float
