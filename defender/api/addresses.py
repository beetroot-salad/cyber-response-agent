"""The frontend's addresses: a fixed list of shapes in one data file (`addresses.json`), read here at runtime and by
the frontend's build for its router (#1161 S2). A value is a member when the whole string matches a shape: ASCII,
case-sensitive, no decoding, normalising or trailing-`/` tolerance."""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

from defender._io import read_text_utf8

_SEGMENT = re.compile(r"\{([a-z]+)\}")
#: What a placeholder's grammar may be: a run of character classes, each with an optional count, and literal letters,
#: digits, `_` and `-`. No alternation, group, anchor or wildcard can be written, so a grammar pasted into a template's
#: pattern matches one segment and nothing around it. The frontend's build holds the same rule (`build.mjs`).
GRAMMAR = re.compile(r"(?:\[[A-Za-z0-9_-]+\](?:\{[0-9]+(?:,[0-9]+)?\}|\+)?|[A-Za-z0-9_-])+", re.ASCII)
#: The characters a placeholder may match. The form above is checked by what each class matches, not by how it is
#: written: a range such as `[--z]` is well formed and still reaches `.` and `/`.
SEGMENT_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_CLASS = re.compile(r"\[([^\]]*)\]")
_PRINTABLE = re.compile(r"[\x20-\x7e]*", re.ASCII)


def _within_a_segment(grammar: str) -> bool:
    """`grammar` has the allowed form and every class in it matches only segment characters (ASCII is tried whole)."""
    if not GRAMMAR.fullmatch(grammar):
        return False
    try:
        classes = [re.compile(f"[{body}]", re.ASCII) for body in _CLASS.findall(grammar)]
    except re.error:  # a backwards range such as `[z-a]`
        return False
    return not any(c.fullmatch(chr(code)) for c in classes for code in range(128) if chr(code) not in SEGMENT_CHARACTERS)


def _list_refused(message: str) -> ValueError:
    return ValueError(f"addresses.json: {message}")


def _compile(document: object) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Each shape's name and pattern; `ValueError` for anything the frontend's build refuses (the same checks, in the
    same words: `tests/support/frontend/_shapes1161.py` REFUSED holds the cases both are tried on)."""
    placeholders = document.get("placeholders") if isinstance(document, dict) else None
    shapes = document.get("shapes") if isinstance(document, dict) else None
    if not isinstance(placeholders, dict) or not isinstance(shapes, list):
        raise _list_refused("must hold `placeholders` (an object) and `shapes` (an array)")
    for name, grammar in placeholders.items():
        if not (isinstance(grammar, str) and _within_a_segment(grammar)):
            raise _list_refused(f"placeholder {name} has a grammar outside the allowed form: {grammar!r}")
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for shape in shapes:
        if not (isinstance(shape, dict) and isinstance(shape.get("name"), str) and isinstance(shape.get("template"), str)
                and isinstance(shape.get("returnable"), bool)):
            raise _list_refused(f"a shape needs a string name, a string template and a boolean returnable: {shape!r}")
        if any(shape["name"] == seen for seen, _ in compiled):
            raise _list_refused(f"duplicate shape name {shape['name']}")
        compiled.append((shape["name"], _pattern(shape["template"], placeholders)))
    return tuple(compiled)


def _pattern(template: str, placeholders: dict[str, object]) -> re.Pattern[str]:
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
