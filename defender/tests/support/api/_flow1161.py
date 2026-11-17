"""#1161 piece 1, test-only: reading the sign-in routes' 303 answers (S1, B4) and cookies (D6) — NO test functions."""
from __future__ import annotations

import urllib.parse
from collections.abc import Mapping
from typing import Any

SIGN_IN_FAILED = "/sign-in-failed"
REASONS = ("prelogin-missing", "login-attempt-invalid", "unknown-account", "otp-required", "unavailable",
           "bad-request", "error")


def location(response: Any) -> str:
    """A 303's `Location`, after checking it is a path on our own origin (S1, B3): no scheme, no host, one leading `/`."""
    assert response.status_code == 303, (response.status_code, response.text)
    value = response.headers["location"]
    split = urllib.parse.urlsplit(value)
    assert (split.scheme, split.netloc) == ("", ""), value
    assert value.startswith("/"), value
    assert not value.startswith("//"), value
    return str(value)


def failed(response: Any) -> tuple[str, Mapping[str, str]]:
    """`(reason, the rest of the query)` of a 303 to the sign-in-failed screen; each name appears once."""
    value = location(response)
    split = urllib.parse.urlsplit(value)
    assert split.path == SIGN_IN_FAILED, value
    pairs = urllib.parse.parse_qsl(split.query, keep_blank_values=True, strict_parsing=True)
    assert len({k for k, _ in pairs}) == len(pairs), value
    query = dict(pairs)
    assert set(query) <= {"reason", "return"}, value
    reason = query.pop("reason")
    return reason, query


def cookies_set(response: Any) -> dict[str, str]:
    """`{name: whole Set-Cookie header}` of a response (a name set twice is a failure)."""
    found: dict[str, str] = {}
    for header in response.headers.get_list("set-cookie"):
        name = header.split("=", 1)[0]
        assert name not in found, response.headers.get_list("set-cookie")
        found[name] = header
    return found
