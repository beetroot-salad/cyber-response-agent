
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str = ""
