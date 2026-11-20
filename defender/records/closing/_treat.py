"""`treat(text, bound)`: the one treatment of model text (#1534 V-TEXT).

Used once when a closing record is built and by the invlang write gates, so a gate and the
builder measure the same thing. In order:

1. the whitespace-like controls (tab, LF, CR, VT, FF, NEL, U+001C-U+001F) become spaces;
2. every other Unicode category C character (Cc, Cf, Cs, Co, Cn) is removed;
3. whitespace runs collapse to one space, and the ends are trimmed;
4. links are defanged, never removed: a scheme URL's scheme becomes `hxxp`/`hxxps`/`fxp` and
   every dot of its authority `[.]`; a dotted run that holds a host-shaped token (a whole-label
   sub-run ending in a label of two or more letters-or-marks, or in an `xn--` label) or an IPv4
   address gets `[.]` for every dot. A label is letters, digits, `-` and Unicode marks
   (category M), so a script whose words carry vowel signs (`example.भारत`) still forms one;
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
_DOT_SPLIT = re.compile(f"[{DOTS}]")
#: The ASCII-compatible prefix of an internationalized label (punycode, RFC 3492).
_PUNYCODE_PREFIX = "xn--"
#: Four 1-3 digit groups joined by dot-set characters, not inside a longer digit string.
_IPV4 = re.compile(rf"(?<!\d)\d{{1,3}}(?:[{DOTS}]\d{{1,3}}){{3}}(?!\d)")
#: A scheme preceded by a non-letter or the start, matched case-insensitively.
_SCHEME = re.compile(r"(?<![^\W\d_])(https?|ftp)://", re.IGNORECASE)
_SCHEME_DEFANGED = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}
#: The authority after `scheme://`: up to whitespace or the first `/`, `?` or `#`.
_AUTHORITY = re.compile(r"[^\s/?#]*")
_WHITESPACE = re.compile(r"\s+")


def treat(text: str, bound: int | None) -> str:
    """`text` cleaned, defanged and cut to at most `bound` characters (`None`: no bound)."""
    if not isinstance(text, str):
        raise TypeError(f"treat() takes text, not {type(text).__name__}")
    if bound is not None and (not isinstance(bound, int) or isinstance(bound, bool) or bound < 1):
        raise ValueError(f"a treatment bound is a positive character count, not {bound!r}")
    whole = _unbounded(text)
    if bound is None or len(whole) <= bound:
        return whole
    return _cut_to_bound(whole, bound)


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
    for start, end in _dotted_runs(text):
        if _is_host_or_address(text[start:end]):
            marked.update(i for i in range(start, end) if text[i] in DOTS)
    return "".join(_DEFANGED_DOT if i in marked else ch for i, ch in enumerate(chars))


def _is_mark(ch: str) -> bool:
    return unicodedata.category(ch).startswith("M")


def _is_label_char(ch: str) -> bool:
    """A Unicode letter or digit (`str.isalnum`, what `[^\\W_]` matches), `-`, or a mark."""
    return ch.isalnum() or ch == "-" or _is_mark(ch)


def _is_segment_char(ch: str) -> bool:
    return ch in DOTS or _is_label_char(ch)


def _is_host_label(label: str) -> bool:
    """What a host-shaped token ends in: two or more letters-or-marks (a letter being what
    `[^\\W\\d_]` matches), or an `xn--` label with something after the prefix."""
    if label[:len(_PUNYCODE_PREFIX)].lower() == _PUNYCODE_PREFIX:
        return len(label) > len(_PUNYCODE_PREFIX)
    return len(label) >= 2 and all((ch.isalnum() and not ch.isdecimal()) or _is_mark(ch) for ch in label)


def _label_stretches(text: str) -> list[tuple[int, str]]:
    """Each maximal stretch of label and dot-set characters, with where it starts: where dotted
    runs are found. One pass over the characters, where a pattern for the run itself backtracks
    over every start of a long space-free label (quadratic)."""
    found: list[tuple[int, str]] = []
    start = None
    for i, ch in enumerate(text):
        if _is_segment_char(ch):
            if start is None:
                start = i
        elif start is not None:
            found.append((start, text[start:i]))
            start = None
    if start is not None:
        found.append((start, text[start:]))
    return found


def _dotted_runs(text: str) -> list[tuple[int, int]]:
    """The `(start, end)` of every dotted run in `text`, in order: maximal sequences of two or
    more non-empty labels joined by single dot-set characters (what a leftmost-longest search for
    `label (dot label)+` finds), in one linear pass. A doubled or end dot ends a run."""
    runs: list[tuple[int, int]] = []
    for position, segment in _label_stretches(text):
        first = last = position
        labels = 0
        for label in _DOT_SPLIT.split(segment):
            if label:
                if labels == 0:
                    first = position
                labels += 1
                last = position + len(label)
            else:
                if labels >= 2:
                    runs.append((first, last))
                labels = 0
            position += len(label) + 1
        if labels >= 2:
            runs.append((first, last))
    return runs


def _trailing_run_start(text: str) -> int | None:
    """Where the trailing stretch of label and dot-set characters begins, or `None` if `text`
    does not end in one."""
    start = len(text)
    while start > 0 and _is_segment_char(text[start - 1]):
        start -= 1
    return start if start < len(text) else None


def _already_defanged(text: str, i: int) -> bool:
    """Whether the dot at `i` is the middle of a `[.]` (a second pass leaves it as it is)."""
    return text[i - 1:i + 2] == _DEFANGED_DOT


def _is_host_or_address(run: str) -> bool:
    """A dotted run whose defanging is due: one holding an IPv4 address, or a whole-label
    sub-run ending in a host label (any label after the first)."""
    if _IPV4.search(run):
        return True
    return any(_is_host_label(label) for label in _DOT_SPLIT.split(run)[1:])


def _cut_to_bound(whole: str, bound: int) -> str:
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
        tail = _trailing_run_start(kept)
        kept = kept[:tail] if tail is not None else kept[:-1]
    return kept + ELLIPSIS
