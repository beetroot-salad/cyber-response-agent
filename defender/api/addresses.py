"""The frontend's addresses: a fixed list of shapes in one data file (`addresses.json`), read here at runtime and by
the frontend's build for its router (#1161 S2). A value is a member when the whole string matches a shape: ASCII,
case-sensitive, no decoding, normalising or trailing-`/` tolerance.

The file holds no regular expression. A placeholder is a list of pieces over named `alphabets` (each an explicit list
of segment characters): literal text, or `[alphabet, count]` / `[alphabet, least, most]`. Both readers build their
patterns from those pieces, so what a placeholder can match is checked as data, never by reading regex syntax."""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

from defender._io import read_text_utf8

_SEGMENT = re.compile(r"\{([a-z]+)\}")
#: The characters a placeholder may match: never `/`, `.` or anything else that could reach past its segment.
SEGMENT_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_PRINTABLE = re.compile(r"[\x20-\x7e]*", re.ASCII)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _placeholder(name: str, pieces: object, alphabets: dict[str, str]) -> str:
    """A placeholder's pattern, built here from its pieces: a piece is literal text, or `[alphabet, count]` /
    `[alphabet, least, most]`. No regular expression is read from the file, so none can be miswritten in it."""
    if not isinstance(pieces, list) or not pieces:
        raise _list_refused(f"placeholder {name} must be a non-empty list of pieces")
    parts = []
    for piece in pieces:
        if isinstance(piece, str) and piece and set(piece) <= SEGMENT_CHARACTERS:
            parts.append(re.escape(piece))
        elif (isinstance(piece, list) and len(piece) in (2, 3) and isinstance(piece[0], str) and piece[0] in alphabets
              and all(_is_count(n) for n in piece[1:]) and piece[1] <= piece[-1]):
            counts = f"{piece[1]}" if len(piece) == 2 or piece[1] == piece[2] else f"{piece[1]},{piece[2]}"
            parts.append("[" + "".join(re.escape(c) for c in alphabets[piece[0]]) + "]{" + counts + "}")
        else:
            raise _list_refused(f"placeholder {name} has a piece that is neither text of segment characters nor "
                                f"[a known alphabet, a count of at least 1, optionally a larger one]: {piece!r}")
    return "".join(parts)


def _alphabets(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise _list_refused("must hold `alphabets` (an object)")
    for name, characters in value.items():
        if not (isinstance(characters, str) and characters and set(characters) <= SEGMENT_CHARACTERS):
            raise _list_refused(f"alphabet {name} must list segment characters only (letters, digits, _ and -)")
    return value


def _list_refused(message: str) -> ValueError:
    return ValueError(f"addresses.json: {message}")


def _compile(document: object) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Each shape's name and pattern; `ValueError` for anything the frontend's build refuses (the same checks, in the
    same words: `tests/support/frontend/_shapes1161.py` REFUSED holds the cases both are tried on)."""
    held = document if isinstance(document, dict) else {}
    placeholders, shapes = held.get("placeholders"), held.get("shapes")
    if not isinstance(placeholders, dict) or not isinstance(shapes, list):
        raise _list_refused("must hold `placeholders` (an object) and `shapes` (an array)")
    alphabets = _alphabets(held.get("alphabets"))
    patterns = {name: _placeholder(name, pieces, alphabets) for name, pieces in placeholders.items()}
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for shape in shapes:
        if not (isinstance(shape, dict) and isinstance(shape.get("name"), str) and isinstance(shape.get("template"), str)
                and isinstance(shape.get("returnable"), bool)):
            raise _list_refused(f"a shape needs a string name, a string template and a boolean returnable: {shape!r}")
        if any(shape["name"] == seen for seen, _ in compiled):
            raise _list_refused(f"duplicate shape name {shape['name']}")
        compiled.append((shape["name"], _pattern(shape["template"], patterns)))
    return tuple(compiled)


def _pattern(template: str, placeholders: dict[str, str]) -> re.Pattern[str]:
    if not template.startswith("/"):
        raise _list_refused(f"template {template} does not start with /")
    parts = []
    for segment in template.split("/")[1:]:
        named = _SEGMENT.fullmatch(segment)
        grammar = placeholders.get(named.group(1)) if named else None
        if named and not isinstance(grammar, str):
            raise _list_refused(f"template {template} names an unknown placeholder {named.group(1)}")
        if not named and (not _PRINTABLE.fullmatch(segment) or "{" in segment or "}" in segment):
            raise _list_refused(f"template {template} has a bad literal segment {segment!r}")
        parts.append(grammar if isinstance(grammar, str) else re.escape(segment))
    return re.compile("/" + "/".join(parts), re.ASCII)


_DOCUMENT = json.loads(read_text_utf8(Path(str(resources.files("defender.api").joinpath("addresses.json")))))
_SHAPES = _compile(_DOCUMENT)

#: The shapes a person may be sent back to after sign-in.
RETURNABLE: frozenset[str] = frozenset(s["name"] for s in _DOCUMENT["shapes"] if s["returnable"])


def literal(name: str) -> str:
    """The one address of a shape with no placeholder (the frontend's `literalAddress`); `ValueError` otherwise."""
    for shape in _DOCUMENT["shapes"]:
        if shape["name"] == name and "{" not in shape["template"]:
            return str(shape["template"])
    raise ValueError(f"{name} has no literal address")


def match(value: str) -> str | None:
    """The name of the shape `value` is a member of, or None."""
    for name, pattern in _SHAPES:
        if pattern.fullmatch(value):
            return name
    return None
