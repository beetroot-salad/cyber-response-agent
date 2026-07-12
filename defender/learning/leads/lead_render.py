#!/usr/bin/env python3
"""Substitute ``params`` into a template's ``## Query`` body.

The lead-author driver includes the rendered query string in each
invocation's handoff so the agent can see what the dispatched query
actually looked like — surfacing unbound placeholders, wrong-shape
bindings, and other leaks without requiring it to read the payload.

Discipline: this is a *display* substitution, not the gather-side
dispatcher. Unbound placeholders pass through verbatim (``${host}``
stays ``${host}``) — the doc explicitly wants leaks visible.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


_FENCE_RE = re.compile(r"```(?:[\w-]+)?\n(.*?)```", re.DOTALL)
_QUERY_SECTION_RE = re.compile(
    r"^## Query\s*\n(.*?)(?=^## |\Z)", re.MULTILINE | re.DOTALL
)
_PLACEHOLDER_RE = re.compile(r"\$\{(\w+)\}|\{(\w+)\}")


def _extract_query_body(template_text: str) -> str:
    """Return the first fenced block of the ## Query section.

    If no fenced block is present, return the section body verbatim
    (some templates inline the query without a fence). Returns the
    empty string when there is no ## Query section.
    """
    section = _QUERY_SECTION_RE.search(template_text)
    if not section:
        return ""
    body = section.group(1)
    fenced = _FENCE_RE.search(body)
    if fenced:
        return fenced.group(1).rstrip("\n")
    return body.strip()


def render_query(template_path: Path, params: dict[str, Any]) -> str:
    """Render the template's ``## Query`` body with ``params`` bound.

    Unknown placeholders are left as-is (``${name}`` or ``{name}``).
    Returns the raw body when the template has no recognized query
    section.
    """
    text = template_path.read_text(encoding="utf-8")
    body = _extract_query_body(text)
    if not body:
        return ""

    def _sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        if name in params:
            return str(params[name])
        return m.group(0)

    return _PLACEHOLDER_RE.sub(_sub, body)
