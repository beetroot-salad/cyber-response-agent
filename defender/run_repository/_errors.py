"""The runs repository's one error type, and the one way its refusals quote a name.

`RunRefused` is every refusal the repository makes that is not the tenant's (#1105 OP-5):
`RunId`'s, the lookups' and the episode record's. A fault of the tenant's runs folder or its
`_tenant.json` is `_tenant.TenantRefused` instead (P2). It is a plain `Exception`, not a
`ValueError`, so neither error's handler ever catches the other.

Pydantic-free: `RunId` imports it, and in-box code may import `RunId` (NM-05).
"""
from __future__ import annotations

#: How many characters of a quoted name a refusal carries before it truncates (NF-8): enough
#: to recognise any real name, short enough that a hostile 10 000-character one cannot flood
#: the one stderr line run setup exits with.
_QUOTE_LIMIT = 120


class RunRefused(Exception):  # noqa: N818 — the design's name (#1105 OP-5), as `TenantRefused`
    """The repository refused: a bad run id, an unexpected entry in a runs folder, a corrupt
    episode record, or a write it will not make. The message names the path and the fault.

    The message is `escaped` when the refusal is built, so no path or name spliced into it —
    the runs folder's own path included — can break its one line, whichever site raised it
    (an escaped message escapes to itself, so a re-built or unpickled refusal is unchanged)."""

    def __init__(self, message: object = "") -> None:
        super().__init__(escaped(message))


def quoted(text: object) -> str:
    """`text` as a refusal quotes it: repr-style, so a control character, DEL, a C1 control
    or a line separator is escaped and the message stays one line, and truncated with a
    marker past `_QUOTE_LIMIT` characters (NF-8). Every refusal in the package that names a
    caller-supplied or disk-read name goes through here."""
    text = str(text)
    if len(text) <= _QUOTE_LIMIT:
        return repr(text)
    return f"{text[:_QUOTE_LIMIT]!r}…(+{len(text) - _QUOTE_LIMIT} chars)"


def shown(text: object) -> str:
    """`text` as a refusal shows a name inside a path: verbatim when it is printable and short,
    else `quoted`. Keeps an ordinary path copy-pasteable while a hostile name read off disk
    still cannot break the message's one line."""
    text = str(text)
    return text if text.isprintable() and len(text) <= _QUOTE_LIMIT else quoted(text)


def escaped(text: object) -> str:
    """`text` with every character `str.isprintable` rejects escaped repr-style, nothing else
    changed: for passing on another refusal's message, which may carry text read off disk."""
    return "".join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in str(text))
