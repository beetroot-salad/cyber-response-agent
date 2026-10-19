"""#1256 r4 — gather's system index, as the tests that pinned the retired `descriptor_catalog` read
it now.

The run builds the index ONCE at run start (`descriptor_index(skills, roster, grant)`, a
`SystemIndex`) and renders it at use against the run's CURRENT down map (`.render(down)`;
`system_status.NONE_DOWN` when nothing is down) — "every surface reads the run state's current
status when it is rendered" (r4). Each such test renders it with nothing down, which is what
`descriptor_catalog` returned, and reads its system lines with `listing`, whatever the render
frames them with.

Late-bound (`importlib` per call), so a missing name is one failure per test, never a collection
error. Where the two names live is spelled once here (`INDEX_MODULE`, `STATUS_MODULE`): one edit
each if the implementation puts them elsewhere."""
from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType
from typing import Any

#: The module the index builder replaced `descriptor_catalog` in.
INDEX_MODULE = "defender.hooks.inject_system_skill_description"
#: The module holding the down map's "nothing down" value.
STATUS_MODULE = "defender.runtime.system_status"


def index_module() -> ModuleType:
    """The module that builds gather's system index (`descriptor_index`)."""
    return importlib.import_module(INDEX_MODULE)


def index_text(module: ModuleType, skills: Path, roster: Any, grant: Any) -> Any:
    """Gather's system index for `grant` over `roster` and `skills`, built through `module`'s
    `descriptor_index` and rendered with no system down."""
    none_down = importlib.import_module(STATUS_MODULE).NONE_DOWN
    return module.descriptor_index(skills, roster, grant).render(none_down)


def listing(text: str | None) -> list[str]:
    """The index's system lines (`- `<system>`: <description>`), in order — what
    `descriptor_catalog` returned joined by newlines, and nothing it is framed with."""
    return [ln for ln in (text or "").splitlines() if ln.startswith("- `")]
