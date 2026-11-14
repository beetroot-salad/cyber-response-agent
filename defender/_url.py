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
