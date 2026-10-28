"""Agent hooks and the command-segment rules they share."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.hooks._cmd_segments import (
        ADAPTER_RE as ADAPTER_RE,
        NON_ADAPTER_SHIMS as NON_ADAPTER_SHIMS,
        OPERATOR_TOOLS as OPERATOR_TOOLS,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("ADAPTER_RE", "NON_ADAPTER_SHIMS", "OPERATOR_TOOLS",), "_cmd_segments"),
}

__getattr__ = lazy_door(globals(), _HOMES)
