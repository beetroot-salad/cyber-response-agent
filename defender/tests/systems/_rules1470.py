"""#1470 D-E: where the record rules live after the move. FORCED CHOICE: the design says "e.g. `defender.system_rules`" and
that the catalog read, the judgement and the registry names `RosterRead`, `read_roster` and `RegistryError` are public
there; the names below are those the code stage must supply or correct in this one place. NO test functions."""
from __future__ import annotations

import importlib
import textwrap
from pathlib import Path
from typing import Any

PACKAGE = "defender.system_rules"


def rules(name: str) -> Any:
    """`name` from the rules package (an ImportError until the move is made)."""
    return getattr(importlib.import_module(PACKAGE), name)


def write_broken_adapter(folder: Path, counter: Path) -> None:
    """`broken_adapter.py` in `folder` (an `integrations/`): it declares itself cold and fails when imported, noting each
    import as one `x` in `counter` (#1470 D8); it carries the #1504 list and reference, so only its load fails."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "broken_adapter.py").write_text(textwrap.dedent(f'''\
        """An adapter whose import fails."""
        PREFIX = "BROKEN"
        REQUIRED_CONFIG_KEYS = ("TIMEOUT_SEC",)
        DISPLAY_NAME = "Broken"
        EXAMPLE = False
        READ_ROUTES = ()
        with open({str(counter)!r}, "a") as noted:
            noted.write("x")
        raise RuntimeError("the adapter failed on import 1470")
        '''))
    (folder / "broken_adapter.md").write_text("## Credential\n\nNone known.\n\n## Pitfalls\n\nNone known.\n")
