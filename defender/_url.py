"""The one rule for an absolute http(s) URL a setting names (#1083): the sign-in adapters' URLs and the API's
frontend origin are both read by it, so the two cannot refuse different inputs. Each reader adds only its own rules
on top (a realm path, an origin's lack of one) and names its setting in the refusal."""

from __future__ import annotations

import urllib.parse


def split_http_url(value: str, *, query: bool = False) -> urllib.parse.SplitResult:
    """`value` split, when it is an absolute http(s) URL with a host, a valid port if any, and no credentials,
    fragment or whitespace, and no query unless `query`; else `ValueError` saying why (the caller names the
    setting)."""
    if any(c.isspace() or not c.isprintable() for c in value):
        raise ValueError("contains whitespace or a control character")
    try:
        parts = urllib.parse.urlsplit(value)
        parts.port  # noqa: B018 — reading it is the check: a non-numeric or out-of-range port raises
    except ValueError as e:
        raise ValueError(f"is not a URL: {e}") from None
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.fragment or value.endswith("#") \
            or (not query and (parts.query or value.endswith("?"))):
        raise ValueError("is not an absolute http(s) URL without " + ("a fragment" if query else "query or fragment"))
    if parts.username is not None:
        raise ValueError("carries credentials")
    return parts


_DEFAULT_PORTS = {"http": 80, "https": 443}


def check_origin(value: str) -> str:
    """Scheme, host and optional port: no path (a trailing slash too), query or fragment. Written exactly as a
    browser sends it in `Origin` (lower case, no default port, an ASCII host), since requests are compared to it
    character for character; any other spelling is `ValueError`, naming the one to write. The API's frontend origin and
    the worker's (the screen link a ticket comment carries, #1471 W3) are both read by it."""
    parts = split_http_url(value)
    if parts.path:
        raise ValueError("must be a scheme, host and optional port only (no path, even a trailing slash)")
    host = parts.hostname or ""
    if not host.isascii():
        raise ValueError("must name its host in ASCII (an internationalized name in its xn-- form), as a browser sends it")
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None and parts.port != _DEFAULT_PORTS[parts.scheme]:
        netloc += f":{parts.port}"
    canonical = f"{parts.scheme}://{netloc}"
    if value != canonical:
        raise ValueError(f"must be written as a browser sends it: {canonical}")
    return value
