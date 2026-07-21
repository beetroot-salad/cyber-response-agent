
from __future__ import annotations

from dataclasses import dataclass, field


class RowError(ValueError):
    pass


@dataclass
class Block:
    tag: str
    name: str
    columns: list[str] | None
    rows: list[str] = field(default_factory=list)
