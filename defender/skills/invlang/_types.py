
from __future__ import annotations

from dataclasses import field

from defender._model import model


class RowError(ValueError):
    pass


@model
class Block:
    tag: str
    name: str
    columns: list[str] | None
    rows: list[str] = field(default_factory=list)
    #: How many leading cells the header requires: one past the last column not marked `?`.
    #: Kept separately because `columns` has the `?` stripped. 0 when no header is declared.
    required_cells: int = 0
