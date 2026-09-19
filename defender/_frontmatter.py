from __future__ import annotations

from typing import Any

import yaml

from defender._yaml import safe_load


class FrontmatterError(ValueError):
    pass


def split_frontmatter(text: str) -> tuple[dict[str, Any], str, str]:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.startswith("---\n"):
        raise FrontmatterError("missing leading '---' frontmatter fence")
    end = text.find("\n---", 4)
    if end == -1:
        raise FrontmatterError("missing closing '---' frontmatter fence")
    raw = text[4:end]
    try:
        fm = safe_load(raw)
    except yaml.YAMLError as e:
        raise FrontmatterError(f"frontmatter is not valid YAML: {e}") from e
    if not isinstance(fm, dict):
        raise FrontmatterError("frontmatter is not a YAML mapping")
    nl = text.find("\n", end + 1)
    body = text[nl + 1:].strip() if nl != -1 else ""
    return fm, raw, body


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    fm, _raw, body = split_frontmatter(text)
    return fm, body


def parse_frontmatter_or_none(text: str) -> dict[str, Any] | None:
    try:
        return parse_frontmatter(text)[0]
    except FrontmatterError:
        return None


def strip_frontmatter(text: str) -> str:
    """The body alone — for the callers that splice a SKILL into a PROMPT.

    Frontmatter is file metadata for humans and for the scaffold validator; a model reading it
    as prose is reading YAML that describes the file rather than instructions. It is also where
    a stale tool roster does the most damage: `allowed-tools` is a reader hint nothing
    enforces, so a model told it has a verb the `ToolSet` never registered spends turns calling
    it.

    Malformed frontmatter returns the text unchanged — a prompt loader must not lose a whole
    SKILL to a YAML slip."""
    try:
        return split_frontmatter(text)[2]
    except FrontmatterError:
        return text
