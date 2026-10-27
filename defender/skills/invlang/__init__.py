"""The investigation language: its corpus, queries, and the walkers and cell splitting other areas read it with."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

from .corpus import Companion, LoadReport, load_corpus
from .queries import (
    hypothesis_name_wildcard,
    lead_branch_effects,
    lead_sequence_pattern,
)

__all__ = [
    "Companion",
    "LoadReport",
    "load_corpus",
    "hypothesis_name_wildcard",
    "lead_branch_effects",
    "lead_sequence_pattern",
]

if TYPE_CHECKING:
    from defender.skills.invlang._cells import (
        split_cells as split_cells,
    )
    from defender.skills.invlang._walkers import (
        all_edges as all_edges,
        all_hypotheses as all_hypotheses,
        all_vertices as all_vertices,
        iter_resolutions as iter_resolutions,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("split_cells",), "_cells"),
    **dict.fromkeys(("all_edges", "all_hypotheses", "all_vertices", "iter_resolutions",), "_walkers"),
}

__getattr__ = lazy_door(globals(), _HOMES)
