"""The one rule for an absolute http(s) URL a setting names (#1083): the sign-in adapters' URLs and the API's
frontend origin are both read by it, so the two cannot refuse different inputs. Each reader adds only its own rules
on top (a realm path, an origin's lack of one) and names its setting in the refusal."""

from __future__ import annotations

import ipaddress
import re
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
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", re.ASCII)


def is_hostname(value: str) -> bool:
    """A bare lowercase hostname: dot-separated labels of ASCII letters, digits and inner hyphens, no empty label
    (a trailing dot included). The one hostname rule, for the artifact domain and an origin's host alike (#1566)."""
    return bool(value) and all(_LABEL.fullmatch(label) for label in value.split("."))


def _host_as_browsers_write_it(host: str) -> bool:
    """`host` (as urlsplit gives it, brackets removed) is an IPv6 address in compressed form, a dotted-decimal IPv4
    address, or a hostname whose last label is not a number: a browser reads `1.2.3` or `999.1.1.1` as an IPv4
    address (rewritten or refused), so such a host never comes back as it was written (#1566)."""
    if ":" in host:
        if "%" in host or "." in host:  # a zone (`fe80::1%eth0`) or a dotted tail (`::ffff:1.2.3.4`): browsers write neither
            return False
        try:
            return ipaddress.IPv6Address(host).compressed == host
        except ValueError:
            return False
    last = host.rsplit(".", 1)[-1]
    if last.isdigit() or last.startswith("0x"):
        try:
            return str(ipaddress.IPv4Address(host)) == host
        except ValueError:
            return False
    return is_hostname(host)


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
    if not _host_as_browsers_write_it(host):
        raise ValueError("must name a lowercase hostname (letters, digits, inner hyphens, no empty label), a dotted-"
                         "decimal IPv4 address or an IPv6 address in its compressed form, as a browser sends it")
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None and parts.port != _DEFAULT_PORTS[parts.scheme]:
        netloc += f":{parts.port}"
    canonical = f"{parts.scheme}://{netloc}"
    if value != canonical:
        raise ValueError(f"must be written as a browser sends it: {canonical}")
    return value
