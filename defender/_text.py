"""Does this text carry anything a reader would see?

`str.strip()` / `str.isspace()` is the obvious spelling of that question and the
wrong one. isspace() is True for the visible-width separators (U+00A0 NO-BREAK
SPACE, U+3000, U+2028, U+0085, U+001C-1F) and False for the zero-width ones
(U+200B, U+FEFF, U+00AD, U+2060) and for NUL — so a `.strip()` test calls text
that renders as *nothing at all* non-empty, and text that is only spacing empty.

Every caller here decides something on model-produced text, and that text is
steerable by the attacker-influenced alert/gather content the model was asked to
analyze. Decisions key off what RENDERS instead.
"""
from __future__ import annotations

import unicodedata

# Categories whose members occupy no visual space: Cc (controls, incl. NUL), Cf
# (formats — U+200B, U+FEFF, U+00AD, U+2060, the tag block), Cs (lone surrogates).
# Co and Cn are deliberately excluded: private-use codepoints and ones this
# interpreter's UCD has not seen yet can carry a glyph, and "empty" must not shift
# with the interpreter's Unicode version.
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})


def is_content_less(text: str) -> bool:
    """Whether `text` carries no visible character. Empty text is content-less.

    One visible character is content — including a character merely adjacent to
    invisible ones, so real prose never trips this by carrying a BOM or a soft
    hyphen.
    """
    return all(
        ch.isspace() or unicodedata.category(ch) in _INVISIBLE_CATEGORIES for ch in text
    )


def strip_zero_width(text: str) -> str:
    """`text` with every character that occupies no space at all removed.

    Whitespace SURVIVES — it separates tokens, and callers that split on it must
    keep doing so; what goes is the zero-width set `.strip()` cannot see (U+200B,
    U+FEFF, U+00AD, U+2060, NUL, the tag block). Use before matching model text
    against a keyword, so a token that reads as `caught` matches `caught` however
    the model spelled the gaps around it.
    """
    return "".join(
        ch for ch in text
        if ch.isspace() or unicodedata.category(ch) not in _INVISIBLE_CATEGORIES
    )
