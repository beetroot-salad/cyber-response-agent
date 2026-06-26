"""Prologue (`:V prologue.vertices`) entity extraction.

Shared by the loop (the benign actor's retrieval input) and
``verify_forward_env`` (the forward-check's case entities). Kept
import-safe — stdlib only, no venv re-exec — so ``verify_forward_env``
can reuse it without dragging in ``loop.py``'s module-level ``os.execv``.
"""
from __future__ import annotations

from pathlib import Path


def extract_case_entities(investigation_path: Path) -> str:
    """Extract the prologue's classified entities as `type:class` tokens.

    The benign actor retrieves environment lessons by classification. The
    case entities come from the CONTEXTUALIZE prologue (`:V prologue.vertices`),
    which is alert-derived — not lead/gather output — so handing them to the
    actor preserves its blind-to-leads stance. Returns a comma-joined,
    de-duplicated `type:class` string (e.g. ``process:nc,socket:tcp``); empty
    string if the file or block is absent.

    The dense row is ``id|type|class|ident|attrs?`` and the `class` column is
    already the `type:class`-qualified token (`process:nc`, `socket:tcp`) — i.e.
    exactly the selector vocabulary ``lessons_env_retrieve`` parses. Emit it
    verbatim; re-joining it to the `type` column would double-prefix
    (`process:process:nc`) and never match a `{type, class}` lesson selector.
    """
    if not investigation_path.is_file():
        return ""
    seen: list[str] = []
    in_block = False
    for line in investigation_path.read_text().splitlines():
        s = line.strip()
        if s.startswith(":V prologue.vertices"):
            in_block = True
            continue
        if in_block:
            if not s or s.startswith(":") or s.startswith("```"):
                break
            cols = s.split("|")
            if len(cols) >= 3 and cols[0].strip().startswith("v-"):
                tok = cols[2].strip()
                if tok and tok not in seen:
                    seen.append(tok)
    return ",".join(seen)
