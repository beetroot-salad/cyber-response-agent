from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender._git import REPO_ROOT


def adapters_under(defender_dir: Path) -> Path:
    """`<defender_dir>/scripts/adapters` — the adapters directory of an ARBITRARY tree.

    `DefenderPaths.adapters_dir` answers for the tree an instance is rooted at, which is the
    main checkout for the `PATHS` singleton. The callers that matter here are not in the tree
    they ask about: the loop's commit gate and the lead author's permission gate are both
    handed a WORKTREE's `defender_dir` and must resolve its adapters, not the running process's
    (#772). Each of them spelled this join for itself, so the directory had four independent
    owners and moving it would have left them disagreeing silently — the write gate compiling
    lanes off a path that no longer exists while the commit gate read the real one.

    A function, not a second `ClassVar`: `adapters_rel` is the REPO-relative spelling git
    pathspecs and porcelain paths use, and this is the absolute join off a tree. Both exist
    because both questions are asked; neither is derivable from the other without a repo root.
    """
    return defender_dir / "scripts" / "adapters"


@dataclass(frozen=True)
class DefenderPaths:

    repo_root: Path

    catalog_rel: ClassVar[str] = "defender/skills/gather/queries/"
    skills_rel: ClassVar[str] = "defender/skills/"
    adapters_rel: ClassVar[str] = "defender/scripts/adapters/"
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
    def adapters_dir(self) -> Path:
        return adapters_under(self.defender_dir)

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
    def held_out_fixtures(self) -> Path:
        return self.defender_dir / "fixtures" / "held-out"

    @property
    def worktree_base(self) -> Path:
        return self.repo_root / ".worktrees"


PATHS = DefenderPaths(REPO_ROOT)
