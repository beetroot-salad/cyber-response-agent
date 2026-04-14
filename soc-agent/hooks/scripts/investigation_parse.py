"""Shared investigation.md parsers used by hooks.

Centralizes the regexes and walkers so infer_state.py and validate_conclude.py
agree on what counts as a phase header, a GATHER block, a lead declaration,
or a CONCLUDE marker. The parsers are line-oriented and do not depend on a
full Markdown parser.
"""

import re
from typing import Iterator

from schemas.state import Phase

_PHASE_NAMES = "|".join(p.value for p in Phase)

PHASE_HEADER_RE = re.compile(rf"^## ({_PHASE_NAMES})\b", re.MULTILINE)

CONCLUDE_HEADER_RE = re.compile(r"^## CONCLUDE\b", re.MULTILINE)

SCREEN_HEADER_RE = re.compile(r"^## SCREEN\b", re.MULTILINE)

GATHER_SECTION_RE = re.compile(r"^## GATHER\b.*?(?=^## |\Z)", re.MULTILINE | re.DOTALL)

# Matches `**Lead:** name` or `**Leads:** a, b, c` — value runs to end of line.
LEAD_LINE_RE = re.compile(r"^\*\*Leads?:\*\*\s*(.+)$", re.MULTILINE)


def iter_phase_headers(text: str) -> Iterator[str]:
    """Yield phase names in document order from `## PHASE` headers."""
    return iter(PHASE_HEADER_RE.findall(text))


def has_conclude_header(text: str) -> bool:
    return bool(CONCLUDE_HEADER_RE.search(text))


def has_screen_block(text: str) -> bool:
    return bool(SCREEN_HEADER_RE.search(text))


def iter_gather_blocks(text: str) -> Iterator[str]:
    """Yield each `## GATHER ...` block as a string, up to the next `## ` header."""
    for m in GATHER_SECTION_RE.finditer(text):
        yield m.group(0)


def _names_from_lead_line(value: str) -> list[str]:
    """Split a `**Lead(s):**` value into a list of clean lead names.

    Strips a trailing parenthetical comment, splits on commas, and discards
    bold-marker leftovers and empties.
    """
    if "(" in value:
        value = value.split("(", 1)[0]
    names: list[str] = []
    for raw in value.split(","):
        name = raw.strip().strip("*").strip()
        if name:
            names.append(name)
    return names


def count_distinct_leads(text: str) -> int:
    """Count distinct named leads across all `## GATHER` blocks.

    Composite dispatches (`**Leads:** a, b, c`) contribute each named lead
    separately. The same lead name appearing in multiple GATHER blocks is
    counted once.
    """
    seen: set[str] = set()
    for block in iter_gather_blocks(text):
        for m in LEAD_LINE_RE.finditer(block):
            seen.update(_names_from_lead_line(m.group(1)))
    return len(seen)


def is_screen_resolved(text: str) -> bool:
    """True when the investigation followed the SCREEN fast-path: a SCREEN
    block exists and no GATHER blocks were entered.

    Used to exempt screen-resolved runs from the leads-floor and full
    self-check question set, both of which assume the hypothesis loop ran.
    """
    return has_screen_block(text) and next(iter_gather_blocks(text), None) is None
