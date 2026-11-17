"""`treat(text, bound)`: the one treatment of model text (#1534 V-TEXT).

Used once when a closing record is built and by the invlang write gates, so a gate and the
builder measure the same thing. In order:

1. the whitespace-like controls (tab, LF, CR, VT, FF, NEL, U+001C-U+001F) become spaces;
2. every other Unicode category C character (Cc, Cf, Cs, Co, Cn) is removed;
3. whitespace runs collapse to one space, and the ends are trimmed;
4. links are defanged, never removed: a scheme URL's scheme becomes `hxxp`/`hxxps`/`fxp` and
   every dot of its authority `[.]`; a dotted run that holds a host-shaped token (a whole-label
   sub-run ending in an alphabetic label of two or more letters) or an IPv4 address gets `[.]`
   for every dot;
5. the bound: a cut at the last space before it, else a hard cut keeping `bound - 1`
   characters, backed off to the start of a raw dotted run whose defanging the cut would change.
   The ellipsis counts inside the bound and a cut never falls inside `[.]`.

The result is a fixed point: `treat(treat(x, b), b) == treat(x, b)`."""
from __future__ import annotations

import re
import unicodedata

from ._vocab import ELLIPSIS

#: Step 1's characters: the whitespace-like Cc code points.
_SPACE_LIKE = frozenset("\t\n\x0b\x0c\r\x85\x1c\x1d\x1e\x1f")
#: The dot set, each member defanged to `[.]`.
DOTS = ".。．｡"
_DEFANGED_DOT = "[.]"
#: A label character: a Unicode letter or digit, or `-`.
_LABEL_CHAR = r"(?:[^\W_]|-)"
#: A dotted run: labels joined by single dot-set characters (maximal, by leftmost-longest search).
_RUN = re.compile(rf"{_LABEL_CHAR}+(?:[{DOTS}]{_LABEL_CHAR}+)+")
_DOT_SPLIT = re.compile(f"[{DOTS}]")
#: An alphabetic label of two or more letters: what a host-shaped token ends in.
_ALPHABETIC_LABEL = re.compile(r"[^\W\d_]{2,}")
#: Four 1-3 digit groups joined by dot-set characters, not inside a longer digit string.
_IPV4 = re.compile(rf"(?<!\d)\d{{1,3}}(?:[{DOTS}]\d{{1,3}}){{3}}(?!\d)")
#: A scheme preceded by a non-letter or the start, matched case-insensitively.
_SCHEME = re.compile(r"(?<![^\W\d_])(https?|ftp)://", re.IGNORECASE)
_SCHEME_DEFANGED = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}
#: The authority after `scheme://`: up to whitespace or the first `/`, `?` or `#`.
_AUTHORITY = re.compile(r"[^\s/?#]*")
_WHITESPACE = re.compile(r"\s+")
_TRAILING_RUN = re.compile(rf"(?:{_LABEL_CHAR}|[{DOTS}])+\Z")


def treat(text: str, bound: int | None) -> str:
    """`text` cleaned, defanged and cut to at most `bound` characters (`None`: no bound)."""
    if not isinstance(text, str):
        raise TypeError(f"treat() takes text, not {type(text).__name__}")
    if bound is not None and (not isinstance(bound, int) or isinstance(bound, bool) or bound < 1):
        raise ValueError(f"a treatment bound is a positive character count, not {bound!r}")
    whole = _unbounded(text)
    if bound is None or len(whole) <= bound:
        return whole
    return _cut(whole, bound)


def _unbounded(text: str) -> str:
    """Steps 1-4."""
    spaced = "".join(" " if ch in _SPACE_LIKE else ch for ch in text)
    visible = "".join(ch for ch in spaced if not unicodedata.category(ch).startswith("C"))
    return _defang(_WHITESPACE.sub(" ", visible).strip())


def _defang(text: str) -> str:
    chars = list(text)
    marked: set[int] = set()
    for match in _SCHEME.finditer(text):
        word = match.group(1)
        chars[match.start(1):match.end(1)] = _SCHEME_DEFANGED[word.lower()]
        authority = _AUTHORITY.match(text, match.end())
        assert authority is not None  # `*` always matches
        marked.update(i for i in range(authority.start(), authority.end())
                      if text[i] in DOTS and not _already_defanged(text, i))
    for run in _RUN.finditer(text):
        if _is_host_or_address(run.group()):
            marked.update(i for i in range(run.start(), run.end()) if text[i] in DOTS)
    return "".join(_DEFANGED_DOT if i in marked else ch for i, ch in enumerate(chars))


def _already_defanged(text: str, i: int) -> bool:
    """Whether the dot at `i` is the middle of a `[.]` (a second pass leaves it as it is)."""
    return text[i - 1:i + 2] == _DEFANGED_DOT


def _is_host_or_address(run: str) -> bool:
    """A dotted run whose defanging is due: one holding an IPv4 address, or a whole-label
    sub-run ending in an alphabetic label of two or more letters (any label after the first)."""
    if _IPV4.search(run):
        return True
    return any(_ALPHABETIC_LABEL.fullmatch(label) for label in _DOT_SPLIT.split(run)[1:])


def _cut(whole: str, bound: int) -> str:
    """Step 5 over the treated text `whole`, which is longer than `bound`."""
    space = whole.rfind(" ", 0, bound)
    if space > 0:
        # Whole tokens only: a prefix ending before a space is already a fixed point.
        return whole[:space] + ELLIPSIS
    keep = bound - 1
    # Never inside a `[.]`: step back to its `[`.
    opened = whole.rfind(_DEFANGED_DOT, 0, keep + len(_DEFANGED_DOT) - 1)
    if opened != -1 and opened < keep < opened + len(_DEFANGED_DOT):
        keep = opened
    kept = whole[:keep]
    while _unbounded(kept) != kept:
        # The cut left a raw dotted run that would now defang: back off to its start.
        tail = _TRAILING_RUN.search(kept)
        kept = kept[:tail.start()] if tail is not None else kept[:-1]
    return kept + ELLIPSIS
