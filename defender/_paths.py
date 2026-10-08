from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from defender._git import REPO_ROOT
from defender._knowledge import (
    CATALOG, LESSONS, LESSONS_QUESTIONER, SKILLS, KnowledgePaths, checkout_rel,
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


@model(frozen=True)
class DefenderPaths:

    repo_root: Path

    # The corpus spellings and folders below are pass-throughs: `defender._knowledge` owns
    # the knowledge layout (#1108), and the knowledge still sits inside the checkout.
    catalog_rel: ClassVar[str] = checkout_rel(CATALOG)
    skills_rel: ClassVar[str] = checkout_rel(SKILLS)
    adapters_rel: ClassVar[str] = "defender/scripts/adapters/"
    lessons_dir_rel: ClassVar[str] = checkout_rel(LESSONS)
    #: The questioner's own corpus — findings about a world, never a lesson for the defender,
    #: so kept separate from `lessons_dir_rel`.
    lessons_questioner_dir_rel: ClassVar[str] = checkout_rel(LESSONS_QUESTIONER)

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
