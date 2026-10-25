from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

from defender._git import REPO_ROOT
from defender._model import model


def process_defender_dir() -> Path:
    """The code tree a command-line process runs against: `$DEFENDER_DIR` when set, else the
    tree this package is in. Shared by every operator command and host-side writer so they all
    honour the override and read the same checkout's tenants."""
    import os

    env = os.environ.get("DEFENDER_DIR")
    return Path(env) if env else Path(__file__).resolve().parent


def adapters_under(defender_dir: Path) -> Path:
    """`<defender_dir>/integrations` for an arbitrary tree, e.g. a worktree handed to the
    commit gate or the lead author's permission gate rather than the running process's tree.
    """
    return defender_dir / "integrations"


def root_spellings(root: Path, name: str) -> dict[str, str]:
    """THE spellings of a host root that text shown to a model or an operator names rather than
    locates (#1256): the root as given and as resolved, each mapped to `name`. A one-character
    spelling (`/`) names no root worth hiding and is left out. Callers naming several roots merge
    these maps and hand them to `name_roots`."""
    return {spelling: name for spelling in (str(root), str(Path(root).resolve()))
            if len(spelling) > 1}


#: A spelling stands for its root only where it is a whole path: no path character before it
#: (`/data` is not the tail of `/mnt/data`), and nothing after it that continues the component
#: (`/data` is not the head of `/database` or `/data2`; a full stop ending a sentence is not a
#: suffix, `/data.bak` is).
_BEFORE_ROOT = r"(?<![\w.\-/])"
_AFTER_ROOT = r"(?![\w\-]|\.[\w\-])"


def name_roots(text: str, named: Mapping[str, str]) -> str:
    """`text` with each spelling in `named` (`root_spellings`' maps, merged) replaced by its name
    wherever it stands as a whole path — `/data/x` and `/data` become `<data root>/x` and
    `<data root>`, while `/database/x`, `/data2/x` and `/mnt/data` stay as they are. One pass,
    the longest spelling tried first at each place, so a root inside another's spelling cannot cut
    it in two and a name already put in is never matched again."""
    if not named:
        return text
    spellings = "|".join(re.escape(s) for s in sorted(named, key=len, reverse=True))
    pattern = re.compile(f"{_BEFORE_ROOT}(?:{spellings}){_AFTER_ROOT}")
    return pattern.sub(lambda found: named[found.group(0)], text)


@model(frozen=True)
class DefenderPaths:
    """The product checkout's own trees. It carries no tenant knowledge (#1108 P4, O1/O4): a
    tenant's corpora, skills and catalog are `KnowledgePaths` over an agent root."""

    repo_root: Path

    adapters_rel: ClassVar[str] = "defender/integrations/"

    @property
    def defender_dir(self) -> Path:
        return self.repo_root / "defender"

    @property
    def learning_dir(self) -> Path:
        return self.defender_dir / "learning"

    @property
    def adapters_dir(self) -> Path:
        return adapters_under(self.defender_dir)

    @property
    def worktree_base(self) -> Path:
        return self.repo_root / ".worktrees"


PATHS = DefenderPaths(REPO_ROOT)
