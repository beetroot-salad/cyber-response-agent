"""Shared markdown-it-py helpers for playbook parsing.

Two call sites — `screen.py::_load_screen_rows` and
`contextualize.py::_load_playbook_metadata` — need to walk a playbook's GFM
tables under a named `##` heading. This module hosts:

    - `parse_markdown(text)` — single MarkdownIt instance, commonmark +
      tables + strikethrough (matches GFM enough for our playbooks without
      pulling in linkify-it-py).
    - `iter_yaml_fences(raw)` — yield the body text of every ```yaml (or
      ~~~yaml) fenced block.
    - `table_rows_after_heading(tokens, heading_text)` — return the rows of
      the first GFM table following the given `##` heading, as a list of
      cell-string lists (header row first).
"""

from __future__ import annotations

from typing import Iterable, Iterator

from markdown_it import MarkdownIt
from markdown_it.token import Token


_MD = MarkdownIt("commonmark").enable("table").enable("strikethrough")


def parse_markdown(text: str) -> list[Token]:
    """Parse `text` into a flat list of markdown-it-py tokens."""
    return _MD.parse(text)


def iter_yaml_fences(raw: str) -> Iterator[str]:
    """Yield body text of every fenced block whose info string starts with
    ``yaml``.

    Tolerates:
        - ```` ``` ```` vs ``` ```` ```` ``` fences (any length >= 3 backticks)
        - ``~~~`` tilde fences
        - Info-string extras (e.g. ``yaml linenums=1``)
        - UTF-8 BOM at file start
    """
    for tok in parse_markdown(raw):
        if tok.type != "fence":
            continue
        info = tok.info.strip()
        if info == "yaml" or info.split(None, 1)[:1] == ["yaml"]:
            yield tok.content


def _heading_level(tag: str) -> int:
    """``h1`` -> 1, ``h2`` -> 2, etc. Non-heading tag returns 0."""
    if len(tag) == 2 and tag.startswith("h") and tag[1].isdigit():
        return int(tag[1])
    return 0


def table_rows_after_heading(
    tokens: Iterable[Token], heading_text: str,
) -> list[list[str]]:
    """Return rows of the first GFM table under the ``##`` heading matching
    `heading_text` (case-insensitive, stripped).

    Each row is a list of cell-inline-text strings, header row first. Empty
    list when the heading has no table before the next heading of equal or
    higher level.

    Escaped pipes (``\\|``) inside cells are handled natively by markdown-it-py.
    """
    tokens = list(tokens)
    target = heading_text.strip().lower()

    start_idx: int | None = None
    start_level: int = 0
    for i, tok in enumerate(tokens):
        if tok.type != "heading_open":
            continue
        level = _heading_level(tok.tag)
        # Inline token carries the heading's text in `.content`.
        inline = tokens[i + 1] if i + 1 < len(tokens) else None
        if inline is None or inline.type != "inline":
            continue
        if inline.content.strip().lower() == target:
            start_idx = i
            start_level = level
            break

    if start_idx is None:
        return []

    # Walk forward, stopping at the next heading of equal or higher level.
    rows: list[list[str]] = []
    in_table = False
    current_row: list[str] | None = None

    for tok in tokens[start_idx + 1:]:
        if tok.type == "heading_open" and _heading_level(tok.tag) <= start_level:
            break
        if tok.type == "table_open":
            if in_table:
                # Already captured the first table — don't extend into siblings.
                break
            in_table = True
            continue
        if not in_table:
            continue
        if tok.type == "table_close":
            break
        if tok.type == "tr_open":
            current_row = []
        elif tok.type == "tr_close":
            if current_row is not None:
                rows.append(current_row)
            current_row = None
        elif tok.type == "inline" and current_row is not None:
            current_row.append(tok.content)

    return rows
