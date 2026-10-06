"""How a refusal shows a value it names — one rule for every owner that refuses on a value it
was handed or read off disk (the tenant owner `_tenant`, the runs repository).

A shown value is escaped, so no control character, line separator or escape sequence reaches a
terminal or a log raw and the refusal stays one line, and bounded, so a hostile 10 000-character
name cannot flood that line. Dependency-free: `RunId` (in-box code) reaches it.
"""
from __future__ import annotations

#: How much of a refused value a message carries (N16, NF-8): enough to recognise any real
#: name, never a megabyte of attacker-chosen bytes.
SHOWN_LIMIT = 120


def quoted(value: object) -> str:
    """`value` repr-style (a control character, DEL, a C1 control or a line separator escaped),
    bounded: escaped FIRST, then cut, so the bound is on what is shown. A longer `str` keeps
    the longest prefix whose quoted form fits in `SHOWN_LIMIT` characters (never half an
    escape, still one valid quoted string), with a marker saying how many characters went."""
    text = repr(value)
    if len(text) <= SHOWN_LIMIT:
        return text
    if not isinstance(value, str):
        return f"{text[:SHOWN_LIMIT]}…(+{len(text) - SHOWN_LIMIT} chars)"
    low, high = 0, min(len(value), SHOWN_LIMIT)
    while low < high:  # the longest prefix whose repr fits; repr grows with the prefix
        mid = (low + high + 1) // 2
        low, high = (mid, high) if len(repr(value[:mid])) <= SHOWN_LIMIT else (low, mid - 1)
    return f"{value[:low]!r}…(+{len(value) - low} chars)"


def shown(name: object) -> str:
    """A name inside a path, as a refusal shows it: verbatim when it is printable and short, so
    an ordinary path stays copy-pasteable, else `quoted`."""
    text = str(name)
    return text if text.isprintable() and len(text) <= SHOWN_LIMIT else quoted(text)


def escaped(text: object) -> str:
    """`text` with every character `str.isprintable` rejects escaped repr-style and nothing else
    changed: a whole message, or a path the operator spelled, which may still carry a byte read
    off disk. Escaping is idempotent: an escaped text escapes to itself."""
    return "".join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in str(text))
