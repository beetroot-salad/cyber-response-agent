#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path, PurePath
from typing import Any

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _corpus  # noqa: E402
from defender._io import Bound  # noqa: E402


_FENCE_RE = re.compile(r"```(?:[\w-]+)?\n(.*?)```", re.DOTALL)
_PLACEHOLDER_RE = re.compile(r"\$\{(\w+)\}|\{(\w+)\}")


def _extract_query_body(template_text: str) -> str:
    # `## Query` for a template, `## Executed query` for a draft (the same fallback as
    # `lead_neighbors.load_catalog`); otherwise every draft would render empty in the handoff.
    sections = _corpus.section_bodies(template_text)
    body = sections.get("Query") or sections.get("Executed query", "")
    if not body:
        return ""
    fenced = _FENCE_RE.search(body)
    if fenced:
        return fenced.group(1).rstrip("\n")
    return body.strip()


def render_query(source: Bound, name: str | PurePath, params: dict[str, Any]) -> str:
    """The template at `name` below the view `source`, with `params` substituted into its query
    body. Read through the view, so a link at the name or at a holding folder is refused, never
    followed (#1134); a refused or absent template raises `OSError` naming why."""
    rec = source.read(name)
    if rec.text is None:
        raise OSError(f"{rec.name}: {rec.reason or 'absent'}")
    text = rec.text
    body = _extract_query_body(text)
    if not body:
        return ""

    def _sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        if name in params:
            return str(params[name])
        return m.group(0)

    return _PLACEHOLDER_RE.sub(_sub, body)
