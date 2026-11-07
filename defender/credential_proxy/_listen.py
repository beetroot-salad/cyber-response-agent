"""The proxy's listening socket (#1428 O1)."""
from __future__ import annotations

import socket

import uvicorn

#: How long bytes the proxy has sent may stay unacknowledged-for-room before the kernel drops the
#: connection and frees them. Long enough that a run which recovers rarely loses a reply; no
#: ordering with `CALLER_GRACE_SEC` is promised (a slow system can delay the proxy's own give-up
#: past any multiple of it).
DELIVERY_LIMIT_SEC = 60


def listening_socket(config: uvicorn.Config, *, delivery_limit_sec: int = DELIVERY_LIMIT_SEC) -> socket.socket:
    """`config`'s address, bound, with the delivery limit set: connections accepted on it inherit
    it, and the kernel drops one whose sent bytes find no room for `delivery_limit_sec`."""
    sock = config.bind_socket()
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, delivery_limit_sec * 1000)
    return sock
