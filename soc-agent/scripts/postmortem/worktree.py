"""Mechanical git-worktree helpers for the post-mortem orchestrator.

The orchestrator creates a per-run worktree off the current branch,
hands it to a coding agent for catalog edits, and (eventually) opens a
PR. The worktree itself is the audit trail — it is never auto-removed,
so a human can `git checkout <branch>` and inspect the agent's diff if
something looks wrong.

These helpers are deliberately narrow: a single create/remove pair plus
a `current_branch` resolver. Anything fancier (sparse checkout, shared
worktree pool, lockfiles) is out of scope until a second caller appears.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class WorktreeError(RuntimeError):
    """Raised on any git-worktree subprocess failure. Loud by design —
    the post-mortem pipeline's failure mode is a `failed` marker plus the
    captured `git` stderr in the run log."""


def _run_git(repo_root: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise WorktreeError(
            f"git {' '.join(args)} failed (rc={proc.returncode}): "
            f"{proc.stderr.strip()}"
        )
    return proc.stdout


def current_branch(repo_root: Path) -> str:
    """Return the branch HEAD currently points at. Raises if HEAD is
    detached — a post-mortem cannot fork off an anonymous commit."""
    out = _run_git(repo_root, ["rev-parse", "--abbrev-ref", "HEAD"]).strip()
    if not out or out == "HEAD":
        raise WorktreeError(
            f"refusing to create worktree off detached HEAD in {repo_root}"
        )
    return out


def create_worktree(
    repo_root: Path,
    worktree_path: Path,
    branch_name: str,
    base_ref: str = "HEAD",
) -> Path:
    """Create a worktree at `worktree_path` on a new branch
    `branch_name` rooted at `base_ref`.

    Fails loud if `worktree_path` already exists or if `branch_name`
    already exists locally — the orchestrator never silently overwrites.
    Re-running the post-mortem against an already-processed run is
    intentional: it should surface as a collision, not as a silent
    branch reset.
    """
    if worktree_path.exists():
        raise WorktreeError(
            f"worktree path already exists: {worktree_path}"
        )
    branches = _run_git(repo_root, ["branch", "--list", branch_name]).strip()
    if branches:
        raise WorktreeError(
            f"branch already exists: {branch_name} (delete or use a "
            f"different run id)"
        )
    worktree_path.parent.mkdir(parents=True, exist_ok=True)
    _run_git(
        repo_root,
        ["worktree", "add", "-b", branch_name, str(worktree_path), base_ref],
    )
    return worktree_path


def remove_worktree(worktree_path: Path) -> None:
    """Remove a worktree previously created with `create_worktree`. Used
    by tests; the production orchestrator does NOT call this on its own
    output — the user explicitly wants the worktree available for
    inspection until the PR is merged."""
    repo_root = _resolve_main_repo(worktree_path)
    _run_git(repo_root, ["worktree", "remove", "--force", str(worktree_path)])


def _resolve_main_repo(worktree_path: Path) -> Path:
    """Walk up from a worktree to find the main repo root.

    Worktrees have a `.git` *file* (not directory) whose contents read
    `gitdir: /path/to/main/.git/worktrees/<name>`. We resolve back to
    the main `.git` directory's parent to get the canonical repo root,
    which is what `git worktree remove` needs to be invoked from.
    """
    git_marker = worktree_path / ".git"
    if not git_marker.exists():
        raise WorktreeError(f"not a worktree: {worktree_path}")
    if git_marker.is_dir():
        # Caller passed a regular checkout, not a worktree. Fall back to
        # treating the path itself as the repo root.
        return worktree_path
    contents = git_marker.read_text().strip()
    prefix = "gitdir:"
    if not contents.startswith(prefix):
        raise WorktreeError(
            f"unexpected .git file contents in {worktree_path}: {contents!r}"
        )
    gitdir = Path(contents[len(prefix):].strip())
    # gitdir → /repo/.git/worktrees/<name>; main repo is two parents up.
    return gitdir.parent.parent.parent
