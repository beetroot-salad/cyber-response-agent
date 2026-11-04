"""The TLS trust the credential proxy verifies a tenant's system with (#1391 O4, P4).

Every context is built here, from an empty client context: the certificates it is handed and
nothing else. Nothing is inherited from Python's defaults (`ssl.create_default_context` reads
`SSLKEYLOGFILE`, loads the default paths, and from Python 3.13 turns on partial-chain
acceptance), so the environment and the Python version play no part.

A declaration's `ca` context is built where the declaration is parsed, which in the proxy is a
worker thread and never the event loop, and kept in a small bounded cache keyed by the PEM text,
so a request that sees the same `ca` again builds nothing (#1375 O1). Tenants can change their CA,
so the cache is bounded."""
from __future__ import annotations

import re
import ssl
import threading
from collections import OrderedDict

#: How many distinct CAs are kept; the oldest-used goes first.
CACHE_SIZE = 64

#: The verify flags every context carries, assigned and never inherited: the chain must end at a
#: certificate the context trusts, treated as a root (no partial chain, #1391 F7).
VERIFY_FLAGS = ssl.VERIFY_X509_TRUSTED_FIRST

# ASCII whitespace only: `\s` also matches U+00A0 and the like, which `cadata` rejects with a
# `TypeError` that would escape as a crash instead of the settings fault.
_BLOCK = r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/= \t\r\n]*?-----END CERTIFICATE-----"
_ONLY_CERTIFICATES = re.compile(rf"[ \t\r\n]*(?:{_BLOCK}[ \t\r\n]*)+")

_lock = threading.Lock()
_built: OrderedDict[str, ssl.SSLContext] = OrderedDict()


def client_trust(*, cadata: str | None = None, cafile: str | None = None) -> ssl.SSLContext:
    """A client context that trusts exactly the certificates of `cadata` (PEM text) or `cafile`
    (a PEM bundle's path), verifying the host name. `ssl.SSLError` when they do not load."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # host name checked, certificate required
    context.verify_flags = VERIFY_FLAGS
    context.load_verify_locations(cafile=cafile, cadata=cadata)
    return context


def trust_of_ca(pem: str) -> ssl.SSLContext:
    """A client context that trusts the certificates of `pem` only (`client_trust`).

    Raises `ValueError` saying what is wrong when `pem` is anything but certificate blocks or
    holds no CA certificate, and `ssl.SSLError` when a block is not a certificate. Neither
    message quotes `pem`: a pasted private key must never reach an export or a run record."""
    with _lock:
        found = _built.get(pem)
        if found is not None:
            _built.move_to_end(pem)
            return found
    # Built outside the lock: one tenant's new CA does not hold up every other request.
    if not _ONLY_CERTIFICATES.fullmatch(pem):
        raise ValueError("must be PEM certificate blocks and nothing else (no key, no other text)")
    context = client_trust(cadata=pem)
    if not context.cert_store_stats()["x509_ca"]:
        raise ValueError("holds no CA certificate: give the certificate of the CA that signed "
                         "the server's certificate, not the server's own")
    with _lock:
        _built[pem] = context
        _built.move_to_end(pem)
        while len(_built) > CACHE_SIZE:
            _built.popitem(last=False)
    return context


__all__ = ["CACHE_SIZE", "VERIFY_FLAGS", "client_trust", "trust_of_ca"]
