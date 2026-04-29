"""AlertSchema declaration shared by vendor-specific `schemas.py` files.

Each vendor under `knowledge/environment/systems/{vendor}/schemas.py` declares
a `SCHEMAS` tuple of one or more `AlertSchema` instances. The handler-side
loader resolves the vendor at run time and picks the first schema whose
`matches(alert)` predicate is truthy.

Kept in its own tiny module so vendor schema files can import only this
without pulling the wider `_context_loader` surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class AlertSchema:
    name: str
    matches: Callable[[dict], bool]
    fields: tuple[str, ...]
