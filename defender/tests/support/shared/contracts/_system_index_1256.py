"""#1256 r4 — gather's system index, as the tests that pinned the retired `descriptor_catalog` read
it now."""
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
