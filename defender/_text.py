"""Does this text carry anything a reader would see?

`str.strip()` is the wrong test: `isspace()` is False for zero-width characters (U+200B,
U+FEFF, U+00AD, U+2060) and NUL, so text that renders as nothing counts as non-empty. Callers
decide things on model-produced text that an attacker can steer through alert content, so
decisions key off what renders.
"""
from __future__ import annotations

import unicodedata
from typing import Any

# Cc (controls, incl. NUL), Cf (formats: U+200B, U+FEFF, U+00AD, U+2060, tag block), Cs (lone
# surrogates). Co and Cn are excluded: private-use and not-yet-assigned codepoints can carry a
# glyph, and "empty" must not shift with the interpreter's Unicode version.
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})


def as_str(value: Any) -> str:
    """`value` when it is a `str`, else `""` — for a value typed as text that arrives from
    somewhere that cannot promise it (raw model tool arguments, nullable stored columns).
    `""` rather than `None` because every caller compares or hashes the result."""
    return value if isinstance(value, str) else ""


def as_int(value: Any) -> int | None:
    """`value` when it is an `int` and not a `bool`, else `None` — for a count from untrusted
    JSON/YAML. `bool` is excluded because `True` passes `isinstance(_, int)` and the strict
    records these values land in would raise `ValidationError`."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def is_content_less(text: str) -> bool:
    """Whether `text` carries no visible character. Empty text is content-less."""
    return all(
        ch.isspace() or unicodedata.category(ch) in _INVISIBLE_CATEGORIES for ch in text
    )


def strip_zero_width(text: str) -> str:
    """`text` with every zero-width character removed; whitespace is kept so token splitting
    still works. Use before matching model text against a keyword.
    """
    return "".join(
        ch for ch in text
        if ch.isspace() or unicodedata.category(ch) not in _INVISIBLE_CATEGORIES
    )
