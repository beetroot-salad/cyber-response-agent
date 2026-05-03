"""Shared markdown-it-py helpers for playbook parsing."""

from __future__ import annotations

from typing import Any, Iterable, Iterator

from markdown_it import MarkdownIt
from markdown_it.token import Token


_MD = MarkdownIt("commonmark").enable("table").enable("strikethrough")


def parse_markdown(text: str) -> list[Token]:
    return _MD.parse(text)


def iter_yaml_fences(raw: str) -> Iterator[str]:
    """Yield body text of every fenced block whose info string starts with ``yaml``.

    Used for parsing **subagent stdout** (still a yaml contract) — not
    for `investigation.md`, which post-cutover only carries ```invlang
    fences.
    """
    for tok in parse_markdown(raw):
        if tok.type != "fence":
            continue
        info = tok.info.strip()
        if info == "yaml" or info.split(None, 1)[:1] == ["yaml"]:
            yield tok.content


def iter_companion_dicts(raw: str) -> Iterator[dict[str, Any]]:
    """Yield the parsed companion-shape dict from every ```invlang fence in `raw`.

    Post-cutover the validator rejects ```yaml fences in `investigation.md`,
    so the dense surface is the only structured shape on disk. The dense
    parser projects every ```invlang fence in `raw` to one combined
    canonical companion dict, which is yielded once. Malformed dense
    blocks are silently skipped — this is a permissive walker, not a
    substitute for the invlang validator (callers that need parse errors
    must go through `invlang_validate.py`).
    """
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


def first_prologue_vertex_id(raw: str) -> str | None:
    """First `v-*` id declared in any prologue block of `raw`, or None.

    Default `target` for synthesized lead-pick / findings entries when the
    handler envelope didn't supply one.
    """
    for doc in iter_companion_dicts(raw):
        vertices = (doc.get("prologue") or {}).get("vertices") or []
        for v in vertices:
            if isinstance(v, dict) and isinstance(v.get("id"), str):
                return v["id"]
    return None


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
