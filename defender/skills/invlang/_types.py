"""Shared value types for the invlang dense-companion parser.

`Block` (one tokenized `:X name [cols]` block) and `RowError` (the per-row
projection failure the block driver catches) are used by both the schema-free
cell tokenizer (`_cells.py`) and the schema-aware projector (`parser.py`).
Housing them here lets `_cells.py` stay a pure tokenizer with no `parser.py`
import, and keeps the `Block` param on `_row_cells`/`_row_dict` unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class RowError(ValueError):
    """Raised inside a row projection. Caught by the block driver, which
    records the failure as a `ParseWarning` and moves on to the next
    row instead of aborting the file."""


@dataclass
class Block:
    tag: str
    name: str
    columns: list[str] | None
    rows: list[str] = field(default_factory=list)
