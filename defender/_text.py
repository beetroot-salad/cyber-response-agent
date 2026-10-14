"""Does this text carry anything a reader would see?

`str.strip()` is the wrong test: `isspace()` is False for zero-width characters (U+200B,
U+FEFF, U+00AD, U+2060) and NUL, so text that renders as nothing counts as non-empty. Callers
decide things on model-produced text that an attacker can steer through alert content, so
decisions key off what renders.
"""
from __future__ import annotations

import math
import unicodedata
from typing import Any

from defender._tsv import flatten_cell

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


def one_line(text: str) -> str:
    """`text` as one printed line: every line break becomes a space, every other invisible or
    control character (ESC, NUL, zero-width) is dropped, and the ends are trimmed. For a value
    another party wrote that is printed where a line break or a terminal control would let it
    forge lines the reader takes for the printer's own (a header, a listing row)."""
    flat = flatten_cell(text)
    # Every remaining control drops, whitespace or not: U+001F is `isspace()` and no TSV breaker.
    return "".join(ch for ch in flat if unicodedata.category(ch) not in _INVISIBLE_CATEGORIES).strip()


def strip_zero_width(text: str) -> str:
    """`text` with every zero-width character removed; whitespace is kept so token splitting
    still works. Use before matching model text against a keyword.
    """
    return "".join(
        ch for ch in text
        if ch.isspace() or unicodedata.category(ch) not in _INVISIBLE_CATEGORIES
    )


def unwritable_value(value: Any, *, _depth: int = 0) -> str | None:
    """What in `value` (a parsed JSON/YAML value: mappings, lists, strings, numbers) no record
    can carry, or `None`: a lone surrogate in a string or a key (`json.loads('"\\ud800"')`
    yields one; UTF-8 cannot encode it, so the write that meets it raises), or a non-finite
    number (`json.loads` admits `NaN`/`Infinity`; strict JSON cannot carry them). Named, so a
    reader refuses the record by its cause instead of failing later at an encode or a
    canonical `json.dumps`. A nesting deeper than 200 is named too."""
    if _depth > 200:
        return "nesting deeper than 200 levels"
    if isinstance(value, str):
        lone = next((ch for ch in value if 0xD800 <= ord(ch) <= 0xDFFF), None)
        return None if lone is None else f"a lone surrogate (U+{ord(lone):04X})"
    if isinstance(value, float):
        return None if math.isfinite(value) else f"a non-finite number ({value!r})"
    children: Any = ()
    if isinstance(value, dict):
        children = [*value.keys(), *value.values()]
    elif isinstance(value, (list, tuple)):
        children = value
    for child in children:
        found = unwritable_value(child, _depth=_depth + 1)
        if found is not None:
            return found
    return None
