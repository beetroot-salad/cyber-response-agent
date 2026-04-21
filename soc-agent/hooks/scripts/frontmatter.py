"""YAML frontmatter parser.

Parses the YAML frontmatter block (between ``---`` delimiters) at the start
of a Markdown file using `python-frontmatter`.

Two small tolerances are layered on top of upstream:
    - UTF-8 BOM at file start is stripped.
    - Partial frontmatter (opening ``---`` with no closing delimiter) is
      tolerated by appending one before parsing — preserves the lenient
      behavior of the previous hand-rolled parser, which matters for
      mid-write report files.
"""

from __future__ import annotations

import re

import frontmatter

_CLOSING_RE = re.compile(r"^---\s*$", re.MULTILINE)


def parse_yaml_frontmatter(text: str) -> dict:
    """Parse YAML frontmatter from a Markdown file.

    Expects content between ``---`` delimiters at the start of the file.
    Returns an empty dict if no frontmatter is found or if parsing fails.
    """
    if text.startswith("﻿"):
        text = text[1:]

    stripped = text.lstrip()
    if stripped.startswith("---\n") or stripped.startswith("---\r\n") or stripped == "---":
        first_nl = text.find("\n", text.find("---"))
        has_close = (
            first_nl != -1
            and _CLOSING_RE.search(text, first_nl + 1) is not None
        )
        if not has_close:
            text = text.rstrip("\n") + "\n---\n"

    try:
        post = frontmatter.loads(text)
    except Exception:
        return {}
    meta = post.metadata
    return meta if isinstance(meta, dict) else {}
