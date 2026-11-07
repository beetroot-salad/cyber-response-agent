"""Typed system-of-record integrations and ticket publication."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.integrations._stub_transport import (
        load_config as load_config,
        record_config as record_config,
    )


#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("load_config", "record_config"), "_stub_transport"),
}

__getattr__ = lazy_door(globals(), _HOMES)
