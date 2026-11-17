"""The model clients' HTTP client: no connection outlives the request that opened it.

A pooled connection belongs to the event loop that opened it. The product drives agents from synchronous
code through `execution.run_sync`, which starts a fresh loop (`asyncio.run`) for each call, and a model is
built once and reused across those calls (the branch oracle's and verifier's agents, for one). With
keep-alive, the second call's request could take a connection the first call's loop opened; that loop is
closed by then, and the request failed with "Event loop is closed" (about every other request of the
oracle, which is how two worlds of an episode lost all their retries).

Keep-alive is off, so every request opens its own connection: tens of milliseconds against model requests
that take seconds. Everything else is the library's own client, so the environment's proxy settings
(`HTTPS_PROXY`) still apply; a transport of our own would bypass them.
"""
from __future__ import annotations

import httpx2

#: The library's own defaults (`pydantic_ai._http.create_async_httpx2_client`), which match OpenAI's.
_TIMEOUT_SECONDS = 600
_CONNECT_SECONDS = 5


def async_client() -> httpx2.AsyncClient:
    """A model client's HTTP client, safe to use from one event loop after another."""
    from pydantic_ai.models import get_user_agent

    return httpx2.AsyncClient(
        timeout=httpx2.Timeout(timeout=_TIMEOUT_SECONDS, connect=_CONNECT_SECONDS),
        headers={"User-Agent": get_user_agent()},
        limits=httpx2.Limits(max_keepalive_connections=0),
    )
