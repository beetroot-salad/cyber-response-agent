"""Typed system-of-record integrations and ticket publication."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.integrations._stub_transport import (
        docker_exec_curl as docker_exec_curl,
        load_config as load_config,
        proxy_exchange as proxy_exchange,
        record_config as record_config,
        split_status as split_status,
        uses_proxy as uses_proxy,
    )


#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("docker_exec_curl", "load_config", "proxy_exchange", "record_config", "split_status",
                     "uses_proxy"), "_stub_transport"),
}

__getattr__ = lazy_door(globals(), _HOMES)
