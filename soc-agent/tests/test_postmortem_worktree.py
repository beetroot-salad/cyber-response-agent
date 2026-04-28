"""Tests for `scripts.postmortem.worktree`. Each test stands up a fresh
git repo in a tmpdir and exercises the create/remove pair against it.
No network. No mocks of subprocess.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.postmortem.worktree import (
    WorktreeError,
    create_worktree,
    current_branch,
    remove_worktree,
)


def _init_repo(repo_root: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo_root)], check=True)
    # `git init` doesn't set user identity, and `git commit` needs one.
    for kv in (("user.email", "test@example.com"), ("user.name", "Test")):
        subprocess.run(
            ["git", "-C", str(repo_root), "config", *kv], check=True
        )
    (repo_root / "README.md").write_text("# test\n")
    subprocess.run(
        ["git", "-C", str(repo_root), "add", "README.md"], check=True
    )
    subprocess.run(
        ["git", "-C", str(repo_root), "commit", "-q", "-m", "initial"],
        check=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _init_repo(repo_root)
    return repo_root


class TestCurrentBranch:
    def test_returns_branch_name(self, repo: Path) -> None:
        assert current_branch(repo) == "main"

    def test_raises_on_detached_head(self, repo: Path) -> None:
        # checkout the commit hash directly to detach HEAD
        sha = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(repo), "checkout", "-q", sha], check=True,
        )
        with pytest.raises(WorktreeError, match="detached HEAD"):
            current_branch(repo)


class TestCreateWorktree:
    def test_creates_worktree_on_new_branch(self, repo: Path, tmp_path: Path) -> None:
        wt = tmp_path / "wt"
        out = create_worktree(repo, wt, "feature/x")
        assert out == wt
        assert wt.is_dir()
        assert (wt / "README.md").is_file()
        # branch should exist locally
        branches = subprocess.run(
            ["git", "-C", str(repo), "branch", "--list", "feature/x"],
            capture_output=True, text=True, check=True,
        ).stdout
        assert "feature/x" in branches

    def test_refuses_existing_path(self, repo: Path, tmp_path: Path) -> None:
        wt = tmp_path / "wt"
        wt.mkdir()
        with pytest.raises(WorktreeError, match="path already exists"):
            create_worktree(repo, wt, "feature/x")

    def test_refuses_existing_branch(self, repo: Path, tmp_path: Path) -> None:
        # pre-create the branch
        subprocess.run(
            ["git", "-C", str(repo), "branch", "feature/x"], check=True,
        )
        wt = tmp_path / "wt"
        with pytest.raises(WorktreeError, match="branch already exists"):
            create_worktree(repo, wt, "feature/x")

    def test_creates_parent_dirs(self, repo: Path, tmp_path: Path) -> None:
        wt = tmp_path / "nested" / "subdir" / "wt"
        create_worktree(repo, wt, "feature/x")
        assert wt.is_dir()


class TestRemoveWorktree:
    def test_remove_round_trip(self, repo: Path, tmp_path: Path) -> None:
        wt = tmp_path / "wt"
        create_worktree(repo, wt, "feature/x")
        remove_worktree(wt)
        assert not wt.exists()
