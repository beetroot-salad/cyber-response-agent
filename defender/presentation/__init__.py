"""Rendering investigation and learning records for people."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.presentation._page_failed import (
        VisualizeFailed as VisualizeFailed,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("VisualizeFailed",), "_page_failed"),
}

__getattr__ = lazy_door(globals(), _HOMES)
