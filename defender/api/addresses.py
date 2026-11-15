"""The frontend's addresses: a fixed list of shapes in one data file (`addresses.json`), read here at runtime and by
the frontend's build for its router (#1161 S2). A value is a member when the whole string matches a shape: ASCII,
case-sensitive, no decoding, normalising or trailing-`/` tolerance."""

from __future__ import annotations

import json
import re
from importlib import resources

_SEGMENT = re.compile(r"\{([a-z]+)\}")


def _compile(document: dict[str, object]) -> tuple[tuple[str, re.Pattern[str]], ...]:
    placeholders = document["placeholders"]
    assert isinstance(placeholders, dict)
    compiled = []
    for shape in document["shapes"]:  # type: ignore[attr-defined]
        parts = []
        for segment in shape["template"].split("/")[1:]:
            named = _SEGMENT.fullmatch(segment)
            parts.append(placeholders[named.group(1)] if named else re.escape(segment))
        compiled.append((shape["name"], re.compile("/" + "/".join(parts), re.ASCII)))
    return tuple(compiled)


_DOCUMENT = json.loads(resources.files("defender.api").joinpath("addresses.json").read_text(encoding="utf-8"))
_SHAPES = _compile(_DOCUMENT)

#: The shapes a person may be sent back to after sign-in.
RETURNABLE: frozenset[str] = frozenset(s["name"] for s in _DOCUMENT["shapes"] if s["returnable"])


def match(value: str) -> str | None:
    """The name of the shape `value` is a member of, or None."""
    for name, pattern in _SHAPES:
        if pattern.fullmatch(value):
            return name
    return None
