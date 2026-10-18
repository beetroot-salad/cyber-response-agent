from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

from defender._git import REPO_ROOT
from defender._knowledge import (
    CATALOG, CHECKOUT_KNOWLEDGE, LESSONS, LESSONS_QUESTIONER, SKILLS, KnowledgePaths,
)
from defender._model import model


def process_defender_dir() -> Path:
    """The code tree a command-line process runs against: `$DEFENDER_DIR` when set, else the
    tree this package is in. Shared by every operator command and host-side writer so they all
    honour the override and read the same checkout's tenants."""
    import os

    env = os.environ.get("DEFENDER_DIR")
    return Path(env) if env else Path(__file__).resolve().parent


def adapters_under(defender_dir: Path) -> Path:
    """`<defender_dir>/scripts/adapters` for an arbitrary tree, e.g. a worktree handed to the
    commit gate or the lead author's permission gate rather than the running process's tree.
    """
    return defender_dir / "scripts" / "adapters"


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

    repo_root: Path

    # The corpus spellings and folders below are pass-throughs: `defender._knowledge` owns
    # the knowledge layout (#1108), and the knowledge still sits inside the checkout.
    catalog_rel: ClassVar[str] = CHECKOUT_KNOWLEDGE.rel(CATALOG)
    skills_rel: ClassVar[str] = CHECKOUT_KNOWLEDGE.rel(SKILLS)
    adapters_rel: ClassVar[str] = "defender/scripts/adapters/"
    lessons_dir_rel: ClassVar[str] = CHECKOUT_KNOWLEDGE.rel(LESSONS)
    #: The questioner's own corpus — findings about a world, never a lesson for the defender,
    #: so kept separate from `lessons_dir_rel`.
    lessons_questioner_dir_rel: ClassVar[str] = CHECKOUT_KNOWLEDGE.rel(LESSONS_QUESTIONER)

    @property
    def defender_dir(self) -> Path:
        return self.repo_root / "defender"

    @property
    def learning_dir(self) -> Path:
        return self.defender_dir / "learning"

    @property
    def knowledge(self) -> KnowledgePaths:
        """The agent knowledge this checkout carries (#1108)."""
        return KnowledgePaths.of_defender_dir(self.defender_dir)

    @property
    def catalog_dir(self) -> Path:
        return self.knowledge.catalog_dir

    @property
    def skills_dir(self) -> Path:
        return self.knowledge.skills_dir

    @property
    def adapters_dir(self) -> Path:
        return adapters_under(self.defender_dir)

    @property
    def lessons_dir(self) -> Path:
        return self.knowledge.lessons_dir

    @property
    def lessons_questioner_dir(self) -> Path:
        return self.knowledge.lessons_questioner_dir

    @property
    def worktree_base(self) -> Path:
        return self.repo_root / ".worktrees"


PATHS = DefenderPaths(REPO_ROOT)
