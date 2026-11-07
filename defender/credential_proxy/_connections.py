"""The connections the proxy serves (#1428 O1)."""
from __future__ import annotations

import asyncio
import socket
from typing import ClassVar, cast

from uvicorn.protocols.http.h11_impl import H11Protocol


class DeliveryLimited(H11Protocol):
    """HTTP as uvicorn serves it, on a connection the kernel drops once bytes the proxy has sent
    find no room for `limit_sec`, freeing them. Long enough that a run which recovers rarely loses
    a reply; no ordering with `CALLER_GRACE_SEC` is promised (a slow system can delay the proxy's
    own give-up past any multiple of it)."""

    limit_sec: ClassVar[int] = 60

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, self.limit_sec * 1000)
        super().connection_made(cast("asyncio.Transport", transport))
