"""What one path segment is (#1391 T2): the rule the shared transport fills a path template by,
and the separator test the credential proxy's scope check shares with it (O-T5). Also the
credential proxy's rules for a URL as a whole (`url_fault`), which the access declaration's
parser judges a base and an OAuth token URL by (#1366 R15), so the store refuses a base the
proxy could never send to.

A value the transport puts in a path is exactly one segment or the call is refused: never
escaped into one, since a service that decodes the path before routing would split an escaped
`/` all the same. A value that may hold a separator (a URL, a CIDR range, a file path) goes in
the query or the body instead (T3)."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

#: What a server may read as a separator inside a segment, once decoded.
SEPARATORS = "/\\"
#: The characters a path value may never hold: the separators, the start of a query or a
#: fragment, the escape character, and `;` (a path parameter some servers resolve).
REFUSED = f"{SEPARATORS}?#%;"
#: What a case key may never hold (#1359 P3): a key is named by the alert, not chosen by the
#: agent, and is escaped into its segment, so only what could split a segment (or that the
#: proxy refuses, `;`) is refused.
CASE_KEY_REFUSED = f"{SEPARATORS};"
#: Kept as written when a segment is filled, besides the letters, digits and `-._~`: the
#: index-pattern characters a search API reads (`logs-*,alerts-*`).
KEPT = "*,"


def holds_separator(decoded: str) -> bool:
    """Does `decoded` (a segment as a server reads it) hold a separator?"""
    return any(ch in SEPARATORS for ch in decoded)


def segment_fault(value: object, *, refused: str = REFUSED) -> str | None:
    """Why `value` is not exactly one path segment, or None when it is: text, not empty, not
    `.` or `..`, and holding none of `refused` (`REFUSED`, or `CASE_KEY_REFUSED` for a case
    key), no whitespace and no control character."""
    if not isinstance(value, str):
        return f"is {type(value).__name__}, not text"
    if not value:
        return "is empty"
    if value in (".", ".."):
        return f"is `{value}`"
    for ch in value:
        if ch in refused:
            return f"holds `{ch}`"
        if ch.isspace() or unicodedata.category(ch) == "Cc":
            return f"holds the character {ch!r}"
    return None


@dataclass(frozen=True)
class UrlFault:
    """Why the credential proxy never sends to a URL as written. `confinement` for a path that a
    server could resolve outside where it was sent (a `.` or `..` segment, a `;`), else the URL
    is one the proxy cannot read as one destination."""

    reason: str
    confinement: bool = False


#: What a path is split on once decoded: a server may read either as a separator.
_SPLIT = re.compile(f"[{re.escape(SEPARATORS)}]")


def url_form_fault(url: str) -> UrlFault | None:
    """The proxy's rules for how a URL is written (#1163 O2), judged as written, never
    normalised: no whitespace or control character (judged before any parse, which would strip
    some), a URL that parses with a port that is a port, no login part (an empty one included:
    the proxy applies the credential) and no fragment."""
    if any(ch <= " " or ch == "\x7f" for ch in url):
        return UrlFault("the URL holds whitespace or a control character")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 — read for its refusal: a port that is not a number in range raises
    except ValueError:
        return UrlFault("the URL does not parse (its host or port)")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return UrlFault("the URL carries a login part; the proxy applies the credential")
    if parts.fragment:
        return UrlFault("the URL carries a fragment")
    return None


def url_path_fault(path: str) -> UrlFault | None:
    """The proxy's rules for a URL's path (#1163 O2), wherever in it: once decoded and split on
    `/` and `\\`, no `.` or `..` segment, and no `;` (some servers read it as starting a path
    parameter and resolve `/..;/` as `/../`). An escaped `/` or `\\` is not judged here: the
    proxy refuses one only below the declared base, so a base may name one."""
    decoded = unquote(path or "/")
    if any(part in (".", "..") for part in _SPLIT.split(decoded)):
        return UrlFault("the URL path holds a `.` or `..` segment", confinement=True)
    if ";" in decoded:
        return UrlFault("the URL path holds a `;` (a path parameter)", confinement=True)
    return None


def url_fault(url: str) -> UrlFault | None:
    """Why the credential proxy would refuse every request to `url` as written, or None: THE
    proxy's own rules (`url_form_fault`, then `url_path_fault` over its path), shared by its
    scope check and the access declaration's parser (#1366 R15)."""
    return url_form_fault(url) or url_path_fault(urlsplit(url).path)


__all__ = [
    "CASE_KEY_REFUSED", "KEPT", "REFUSED", "SEPARATORS", "UrlFault", "holds_separator", "segment_fault",
    "url_fault", "url_form_fault", "url_path_fault",
]
