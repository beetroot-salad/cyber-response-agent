"""Single canonical YAML-frontmatter parser shared by learning/ and scripts/.

One contract for "parse the YAML frontmatter out of a markdown doc", so the six
former copies can't drift apart again. ``parse_frontmatter`` is strict and
returns ``(frontmatter, body)``; callers that only want the dict take ``[0]``,
and callers that want ``None`` on absence use ``parse_frontmatter_or_none``.

Lives at the ``defender.`` namespace root (no ``__init__.py`` — PEP 420
namespace package) so both ``defender.learning.*`` and ``defender.scripts.*``
import it without a ``sys.path`` dance (see #322/#323).
"""
from __future__ import annotations

from typing import Any

import yaml


class FrontmatterError(ValueError):
    """Text has no parseable leading '---' YAML-mapping frontmatter fence."""


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Split a markdown doc into ``(frontmatter mapping, stripped body)``.

    Normalizes CRLF, then requires a leading ``---\\n`` … ``\\n---`` fence
    enclosing a YAML *mapping*. Raises ``FrontmatterError`` on any of: no
    leading fence, no closing fence, invalid YAML, or a non-mapping document.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.startswith("---\n"):
        raise FrontmatterError("missing leading '---' frontmatter fence")
    end = text.find("\n---", 4)
    if end == -1:
        raise FrontmatterError("missing closing '---' frontmatter fence")
    try:
        fm = yaml.safe_load(text[4:end])
    except yaml.YAMLError as e:
        raise FrontmatterError(f"frontmatter is not valid YAML: {e}") from e
    if not isinstance(fm, dict):
        raise FrontmatterError("frontmatter is not a YAML mapping")
    nl = text.find("\n", end + 1)  # newline ending the closing '---' line
    body = text[nl + 1:].strip() if nl != -1 else ""
    return fm, body


def parse_frontmatter_or_none(text: str) -> dict[str, Any] | None:
    """Tolerant variant: the frontmatter mapping, or ``None`` when absent/malformed."""
    try:
        return parse_frontmatter(text)[0]
    except FrontmatterError:
        return None
