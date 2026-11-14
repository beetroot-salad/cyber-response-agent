"""#1470 D-E: where the record rules live after the move. FORCED CHOICE: the design says "e.g. `defender.system_rules`" and
that the catalog read, the judgement and the registry names `RosterRead`, `read_roster` and `RegistryError` are public
there; the names below are those the code stage must supply or correct in this one place. NO test functions."""
from __future__ import annotations

import importlib
from typing import Any

PACKAGE = "defender.system_rules"


def rules(name: str) -> Any:
    """`name` from the rules package (an ImportError until the move is made)."""
    return getattr(importlib.import_module(PACKAGE), name)
