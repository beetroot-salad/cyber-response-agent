"""What one path segment is (#1391 T2): the rule the shared transport fills a path template by,
and the separator test the credential proxy's scope check shares with it (O-T5).

A value the transport puts in a path is exactly one segment or the call is refused: never
escaped into one, since a service that decodes the path before routing would split an escaped
`/` all the same. A value that may hold a separator (a URL, a CIDR range, a file path) goes in
the query or the body instead (T3)."""
from __future__ import annotations

import unicodedata

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


__all__ = ["CASE_KEY_REFUSED", "KEPT", "REFUSED", "SEPARATORS", "holds_separator", "segment_fault"]
