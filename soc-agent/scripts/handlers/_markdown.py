"""Shared markdown-it-py helpers for playbook parsing."""

from __future__ import annotations

from typing import Any, Iterable, Iterator

import yaml

from markdown_it import MarkdownIt
from markdown_it.token import Token


_MD = MarkdownIt("commonmark").enable("table").enable("strikethrough")


def parse_markdown(text: str) -> list[Token]:
    return _MD.parse(text)


def iter_yaml_fences(raw: str) -> Iterator[str]:
    """Yield body text of every fenced block whose info string starts with ``yaml``."""
    for tok in parse_markdown(raw):
        if tok.type != "fence":
            continue
        info = tok.info.strip()
        if info == "yaml" or info.split(None, 1)[:1] == ["yaml"]:
            yield tok.content


def iter_companion_dicts(raw: str) -> Iterator[dict[str, Any]]:
    """Yield parsed companion-shape dicts from every structured fence in `raw`.

    Walks both ```yaml fences (one dict per fence via `yaml.safe_load`) and
    the unified ```invlang dense surface (one combined dict via
    `parse_dense_companion`). Non-dict YAML documents, malformed YAML, and
    malformed dense blocks are silently skipped — this is a permissive
    walker, not a substitute for the invlang validator (callers that need
    parse errors must go through `invlang_validate.py`).

    Ordering and merge semantics — important for callers that care about
    "first" or "last":
    - YAML fences are yielded first, in document order (one dict per fence).
    - The dense surface is yielded last as a single combined dict
      aggregating every ```invlang fence in the document, regardless of
      where those fences sit physically.
    During the strict-cutover migration both fence types coexist; in steady
    state only the dense fence will remain, so this ordering quirk is
    transient and does not affect call sites today.
    """
    for body in iter_yaml_fences(raw):
        try:
            doc = yaml.safe_load(body)
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict):
            yield doc

    # Lazy import — `_dense_parser` is heavier than `_markdown` consumers
    # who only want yaml fences should not pay for it on import.
    try:
        from scripts.handlers._dense_parser import (  # type: ignore
            parse_dense_companion,
            DenseParseError,
        )
    except ImportError:
        return
    try:
        dense_doc = parse_dense_companion(raw)
    except DenseParseError:
        return
    if dense_doc:
        yield dense_doc


def _heading_level(tag: str) -> int:
    if len(tag) == 2 and tag.startswith("h") and tag[1].isdigit():
        return int(tag[1])
    return 0


def table_rows_after_heading(
    tokens: Iterable[Token], heading_text: str,
) -> list[list[str]]:
    """Return rows of the first GFM table under the ``##`` heading matching
    `heading_text`. Header row first; empty list if no table found before the
    next heading of equal or higher level."""
    tokens = list(tokens)
    target = heading_text.strip().lower()

    start_idx: int | None = None
    start_level: int = 0
    for i, tok in enumerate(tokens):
        if tok.type != "heading_open":
            continue
        inline = tokens[i + 1] if i + 1 < len(tokens) else None
        if inline is None or inline.type != "inline":
            continue
        if inline.content.strip().lower() == target:
            start_idx = i
            start_level = _heading_level(tok.tag)
            break

    if start_idx is None:
        return []

    rows: list[list[str]] = []
    in_table = False
    current_row: list[str] | None = None

    for tok in tokens[start_idx + 1:]:
        if tok.type == "heading_open" and _heading_level(tok.tag) <= start_level:
            break
        if tok.type == "table_open":
            if in_table:
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
