"""YAML frontmatter parser.

Parses the YAML frontmatter block (between ``---`` delimiters) at the start
of a Markdown file using `python-frontmatter`. Returns ``{}`` when the input
has no frontmatter or fails to parse.
"""

from __future__ import annotations

import frontmatter


def parse_yaml_frontmatter(text: str) -> dict:
    try:
        meta = frontmatter.loads(text).metadata
    except Exception:
        return {}
    return meta if isinstance(meta, dict) else {}
