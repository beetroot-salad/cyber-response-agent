"""The adoption job container's entry (#1471 A3): `python -m defender.adoption --job <id> --tenant <T>`, started by the per-job
host helper's `adoption` kind. `main` is served lazily, so `python -m` does not import the entry twice."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.adoption.__main__ import main as main

__all__ = ["main"]

_HOMES: dict[str, str] = {"main": "__main__"}

__getattr__ = lazy_door(globals(), _HOMES)
