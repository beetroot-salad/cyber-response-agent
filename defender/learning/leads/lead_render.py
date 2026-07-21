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
    body = _corpus.section_bodies(template_text).get("Query", "")
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
