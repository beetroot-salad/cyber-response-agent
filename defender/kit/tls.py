"""The TLS trust a declaration's `ca` makes (#1391 O4, P4): those certificates and nothing else.

The context is built where the declaration is parsed, which in the proxy is a worker thread and
never the event loop, at most once per distinct PEM text per process, and kept in a small bounded
cache so a request that sees the same `ca` again builds nothing (#1375 O1). Tenants can change
their CA, so the cache is bounded and keyed by content."""
from __future__ import annotations

import re
import ssl
import threading
from collections import OrderedDict

#: How many distinct CAs are kept; the oldest-used goes first.
CACHE_SIZE = 64

#: The verify flags a `ca` context carries, assigned and never inherited: from Python 3.13 the
#: default context also turns on partial-chain acceptance (a chain ending at an intermediate in
#: `ca`) and strict checks; here the chain must end at a certificate in `ca` treated as a root.
VERIFY_FLAGS = ssl.VERIFY_X509_TRUSTED_FIRST

_BLOCK = r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]*?-----END CERTIFICATE-----"
_ONLY_CERTIFICATES = re.compile(rf"\s*(?:{_BLOCK}\s*)+")

_lock = threading.Lock()
_built: OrderedDict[str, ssl.SSLContext] = OrderedDict()


def trust_of_ca(pem: str) -> ssl.SSLContext:
    """A client context that trusts the certificates of `pem` only, verifying the host name.

    Raises `ValueError` when `pem` is anything but certificate blocks (a pasted private key must
    never reach an export or a run record, so the text is never echoed) and `ssl.SSLError` when
    a block is not a certificate. The environment and the default paths play no part."""
    with _lock:
        found = _built.get(pem)
        if found is not None:
            _built.move_to_end(pem)
            return found
        if not _ONLY_CERTIFICATES.fullmatch(pem):
            raise ValueError("not PEM certificate blocks alone")
        context = ssl.create_default_context(cadata=pem)
        if not context.cert_store_stats()["x509_ca"]:
            raise ValueError("no CA certificate in it")
        context.verify_flags = VERIFY_FLAGS
        _built[pem] = context
        while len(_built) > CACHE_SIZE:
            _built.popitem(last=False)
        return context


__all__ = ["CACHE_SIZE", "VERIFY_FLAGS", "trust_of_ca"]
