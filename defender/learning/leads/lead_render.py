#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _corpus  # noqa: E402


_FENCE_RE = re.compile(r"```(?:[\w-]+)?\n(.*?)```", re.DOTALL)
_PLACEHOLDER_RE = re.compile(r"\$\{(\w+)\}|\{(\w+)\}")


def _extract_query_body(template_text: str) -> str:
    # `## Query` for an established template, `## Executed query` for a draft — the same
    # fallback `lead_neighbors.load_catalog` reads templates through. A draft carries a
    # recording rather than an interface (`QueryTemplate.recording`), so keying on `## Query`
    # alone renders the empty string for every draft, which is precisely the file the
    # lead-author handoff was built to show (`build_handoff`'s `rendered_query`).
    sections = _corpus.section_bodies(template_text)
    body = sections.get("Query") or sections.get("Executed query", "")
    if not body:
        return ""
    fenced = _FENCE_RE.search(body)
    if fenced:
        return fenced.group(1).rstrip("\n")
    return body.strip()


def render_query(template_path: Path, params: dict[str, Any]) -> str:
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
