from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender._git import REPO_ROOT


@dataclass(frozen=True)
class DefenderPaths:

    repo_root: Path

    catalog_rel: ClassVar[str] = "defender/skills/gather/queries/"
    skills_rel: ClassVar[str] = "defender/skills/"
    lessons_dir_rel: ClassVar[str] = "defender/lessons/"
    lessons_actor_dir_rel: ClassVar[str] = "defender/lessons-actor/"
    lessons_environment_dir_rel: ClassVar[str] = "defender/lessons-environment/"

    @property
    def defender_dir(self) -> Path:
        return self.repo_root / "defender"

    @property
    def learning_dir(self) -> Path:
        return self.defender_dir / "learning"

    @property
    def catalog_dir(self) -> Path:
        return self.defender_dir / "skills" / "gather" / "queries"

    @property
    def skills_dir(self) -> Path:
        return self.defender_dir / "skills"

    @property
    def lessons_dir(self) -> Path:
        return self.defender_dir / "lessons"

    @property
    def lessons_actor_dir(self) -> Path:
        return self.defender_dir / "lessons-actor"

    @property
    def lessons_environment_dir(self) -> Path:
        return self.defender_dir / "lessons-environment"

    @property
    def worktree_base(self) -> Path:
        return self.repo_root / ".worktrees"


PATHS = DefenderPaths(REPO_ROOT)
