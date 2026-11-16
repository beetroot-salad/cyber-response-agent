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


def _compile(document: dict[str, object]) -> tuple[tuple[str, re.Pattern[str]], ...]:
    placeholders = document["placeholders"]
    assert isinstance(placeholders, dict)
    for name, grammar in placeholders.items():
        if not (isinstance(grammar, str) and GRAMMAR.fullmatch(grammar)):
            raise ValueError(f"addresses.json: placeholder {name} has a grammar outside the allowed form: {grammar!r}")
    compiled = []
    for shape in document["shapes"]:  # type: ignore[attr-defined]
        parts = []
        for segment in shape["template"].split("/")[1:]:
            named = _SEGMENT.fullmatch(segment)
            parts.append(placeholders[named.group(1)] if named else re.escape(segment))
        compiled.append((shape["name"], re.compile("/" + "/".join(parts), re.ASCII)))
    return tuple(compiled)


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
