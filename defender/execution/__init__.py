"""Stdlib-only command transport shared by sandbox and host execution."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.execution._async import (
        run_sync as run_sync,
    )
    from defender.execution._process_group import (
        kill_group as kill_group,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("run_sync",), "_async"),
    **dict.fromkeys(("kill_group",), "_process_group"),
}

__getattr__ = lazy_door(globals(), _HOMES)
