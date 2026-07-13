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
import sys
from pathlib import Path
from typing import Any

# Same bootstrap as `lead_neighbors` — this file carries a shebang and the package has no
# top-level installable, so the `defender.*` import below must resolve whether it is imported by
# the lead-author driver or reached directly.
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _corpus  # noqa: E402


_FENCE_RE = re.compile(r"```(?:[\w-]+)?\n(.*?)```", re.DOTALL)
_PLACEHOLDER_RE = re.compile(r"\$\{(\w+)\}|\{(\w+)\}")


def _extract_query_body(template_text: str) -> str:
    """Return the first fenced block of the ## Query section.

    If no fenced block is present, return the section body verbatim
    (some templates inline the query without a fence). Returns the
    empty string when there is no ## Query section.

    The section split goes through ``_corpus.section_bodies`` — the ONE parser (#598). This
    function carried its own ``^## Query\\s*\\n(.*?)(?=^## |\\Z)`` copy, which, like the one it
    now calls, was blind to code fences: a ``## `` line inside the query's own fence ended the
    section early, and the fence it left behind was unterminated, so the ``_FENCE_RE`` search
    below missed it and this returned a truncated query body verbatim. That body is what the lead
    author renders as the template's query.
    """
    body = _corpus.section_bodies(template_text).get("Query", "")
    if not body:
        return ""
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
