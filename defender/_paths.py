"""``DefenderPaths`` — the repo-relative on-disk layout, as a value object.

One owner for every ``<repo_root>/defender/...`` offset (the catalog, the three
lesson corpora, the skills surface, the per-batch worktree base). Top-level (not
under ``learning/``) so the runtime, hooks, scripts, and the learning loop can all
name the layout from one place without coupling to the learning package — the same
neutral-primitive placement as ``_run_paths.RunPaths`` (#317) and ``_git``. Pure
pathlib; the only import is the ``_git`` facade for the single repo-root computation.

The offset strings live here and nowhere else: ``LoopPaths`` composes this (its
repo-relative properties delegate to ``self.defender``), and the leads scope-gate
constants (``path_validation``) alias these, so a catalog/skills/lessons offset is
written once. A path that is a pure function of the repo root belongs on this object
as a ``@property``; the root itself is the one field. Construct ``DefenderPaths(root)``
on whichever checkout you hold (main, a batch worktree, an eval tmp tree) — the
accessors are root-relative by design; the module-level ``PATHS`` singleton is the
resolved-once instance for callers that don't inject a root (the ``DEFAULT_PATHS``
analogue for repo layout).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender._git import REPO_ROOT


@dataclass(frozen=True)
class DefenderPaths:
    """The repo-relative layout rooted at ``repo_root``.

    ``repo_root`` is the only field; every directory is a ``@property`` derived from
    it, so the three roots #479 used to let drift (repo / worktree base / forge cwd)
    are one value here. The ``*_rel`` class constants are the repo-root-*independent*
    string twins — git-pathspec / scope-gate prefixes where the trailing slash is
    significant — so they are ``ClassVar`` literals, not root-derived.
    """

    repo_root: Path

    catalog_rel: ClassVar[str] = "defender/skills/gather/queries/"
    skills_rel: ClassVar[str] = "defender/skills/"
    lessons_dir_rel: ClassVar[str] = "defender/lessons/"
    lessons_actor_dir_rel: ClassVar[str] = "defender/lessons-actor/"
    lessons_environment_dir_rel: ClassVar[str] = "defender/lessons-environment/"
    # The author-time forward-check verifier scripts (verify_forward/{batch,forward,actor,env}.py).
    # The curators pin these on their bash lane as `python3 <script>` grants; the trailing slash is
    # significant (the rel is the repo-relative command spelling the agent types, cwd=worktree).
    verify_forward_dir_rel: ClassVar[str] = "defender/learning/author/verify_forward/"

    @property
    def defender_dir(self) -> Path:
        return self.repo_root / "defender"

    @property
    def learning_dir(self) -> Path:
        return self.defender_dir / "learning"

    @property
    def verify_forward_dir(self) -> Path:
        """The author-time forward-check verifier scripts dir (absolute, root-relative)."""
        return self.learning_dir / "author" / "verify_forward"

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
        """Repo-local scratch where each author drain cuts its per-batch worktree
        (one leaf per batch; see ``author/branch.py``). Derived from ``repo_root``,
        so a worktree base can't drift from the repo it belongs to (#479)."""
        return self.repo_root / ".worktrees"


# Resolved-once instance for callers that don't inject a root (the repo-layout twin
# of ``core.config.DEFAULT_PATHS``). Sources the root from the single ``_git``
# computation rather than re-counting ``__file__`` parents.
PATHS = DefenderPaths(REPO_ROOT)
