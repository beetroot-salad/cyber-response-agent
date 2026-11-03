"""Clients for the deployment's own services: OpenBao, the forge, the credential proxy (#1163).

Every such client trusts and routes the same way, decided here once:

- TLS trust is the deployment's: its `ca_cert` when one is set, else where the TLS client looks
  by default (the system store, or `SSL_CERT_FILE`/`SSL_CERT_DIR`, which is how the
  infrastructure provides the dev issuer's CA; `configuration.issuer.DeploymentIssuer`).
  `tls_trust` is the one way to make the context a client is given; its caller decides when it
  is built, since building one blocks (#1375).
- Nothing else is taken from the environment: no outbound web proxy and no `.netrc`, so a token
  sent to one of these services never passes through a third party.
- No redirect is followed.

A test's `transport` replaces the network (and so TLS) entirely.
"""
from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any

import httpx


def tls_trust(ca_cert: Path | None = None) -> ssl.SSLContext:
    """The TLS context a client of the deployment's services verifies with (module doc).
    `OSError`/`ssl.SSLError` when `ca_cert` is unreadable or not a certificate."""
    if ca_cert is not None:
        return ssl.create_default_context(cafile=str(ca_cert))
    return ssl.create_default_context()


def internal_client(*, trust: ssl.SSLContext, transport: httpx.BaseTransport | None = None,
                    **kw: Any) -> httpx.Client:
    """A synchronous client of the deployment's services (module doc) verifying with `trust`, a
    `tls_trust` context; `kw` as `httpx.Client`. The caller decides when the context is built
    (building one loads a trust store and blocks, #1375). httpcore sets the context's ALPN on
    every connect, so connects on different threads through one context race on it: give a
    context to the clients of one thread. A pooled client shared across threads already does
    this to its own context; harmless while every connect sets the same ALPN (HTTP/1.1 only)."""
    return httpx.Client(verify=trust, transport=transport, trust_env=False,
                        follow_redirects=False, **kw)


def internal_async_client(*, trust: ssl.SSLContext,
                          transport: httpx.AsyncBaseTransport | None = None,
                          **kw: Any) -> httpx.AsyncClient:
    """An asynchronous client of the deployment's services (module doc); `trust` and `kw` as
    `internal_client`'s."""
    return httpx.AsyncClient(verify=trust, transport=transport, trust_env=False,
                             follow_redirects=False, **kw)


__all__ = ["internal_async_client", "internal_client", "tls_trust"]
