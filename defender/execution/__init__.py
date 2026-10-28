"""Stdlib-only command transport shared by sandbox and host execution.

The door serves its names lazily like every other (`defender/lazy_door.py`), but with its own
lookup: the oracle box ships this package alone in its runner tree (`box/_oracle.py`
`RUNNER_FILES`), so it imports nothing else from `defender`.
"""
from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

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


def __getattr__(name: str) -> Any:  # lint-dup: ok — PEP 562 hook; the oracle runner tree holds only this package, not `defender.lazy_door`
    home = _HOMES.get(name)
    if home is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(f"{__name__}.{home}"), name)
