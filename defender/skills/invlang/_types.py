
from __future__ import annotations

from dataclasses import dataclass, field


class RowError(ValueError):
    pass


@dataclass
class Block:
    tag: str
    name: str
    columns: list[str] | None
    rows: list[str] = field(default_factory=list)
    #: How many leading cells this block's header REQUIRES — one past the last column not
    #: marked `?`. `columns` keeps the clean names (the `?` is stripped there, and every
    #: consumer reads it that way), so the optionality the header states would otherwise be
    #: discarded at tokenization and `_row_cells` would pad any short row in silence.
    #: 0 for a block that declares no header: there is nothing to require against, and the
    #: built-in `default_cols` the projectors fall back to carry no optionality either.
    required_cells: int = 0
