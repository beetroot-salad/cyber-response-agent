"""The claim session the scope-check gates take since #1175's amendment, for tests that call
`_verify_skills_state` / `_verify_pitfalls_state` directly."""
from __future__ import annotations

from pathlib import Path

from defender._claim_git import ClaimGit
from defender._paths import DefenderPaths
from defender.learning.author._config import GIT_TIMEOUT_SECONDS


def claim_git(repo_root: Path) -> ClaimGit:
    """A session over `repo_root`'s `skills/`, at the production bound."""
    return ClaimGit(Path(repo_root), DefenderPaths.skills_rel, timeout=GIT_TIMEOUT_SECONDS)
