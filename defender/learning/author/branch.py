from __future__ import annotations

import contextlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable

from defender import _git
from defender._git import REPO_ROOT, GitError
from defender._paths import DefenderPaths
from defender.learning.author.forge import Forge, ForgeError, GhForge
from defender.learning.core.config import make_logger

_log = make_logger("branch")

LESSONS_BRANCH_PREFIX = "lessons/"
_BRANCH_BASE = "origin/main"
_PR_BASE = "main"


class BranchError(Exception):
    pass


def _lessons_pr_title(batch_id: str) -> str:
    return f"learning: lesson batch {batch_id}"


def _lessons_pr_body(branch: str) -> str:
    return (
        "Automated lessons batch from the lessons author drain "
        f"(branch `{branch}`, off freshly-fetched `{_BRANCH_BASE}`). Touches "
        "`defender/lessons/` only — distinct from the lead-author PR."
    )


def _is_non_fast_forward(err: GitError) -> bool:
    blob = err.stderr.lower()
    return "non-fast-forward" in blob or "fetch first" in blob


@dataclass
class AuthorBranch:
    forge: Forge | None = None
    repo_root: Path = REPO_ROOT
    branch_prefix: str = LESSONS_BRANCH_PREFIX
    pr_title: Callable[[str], str] = _lessons_pr_title
    pr_body: Callable[[str], str] = _lessons_pr_body
    worktree_base: Path | None = None

    @property
    def _forge(self) -> Forge:
        return self.forge if self.forge is not None else GhForge(cwd=self.repo_root)

    @property
    def _worktree_base(self) -> Path:
        if self.worktree_base is not None:
            return self.worktree_base
        return DefenderPaths(self.repo_root).worktree_base

    @property
    def quarantine_dir(self) -> Path:
        """Where a tainted worktree is preserved before cleanup destroys it (#747).

        A sibling of the live worktrees so it follows `worktree_base` wherever a caller
        redirects it, rather than being a second way to compute the same location. Inside
        the repo checkout is fine BECAUSE the artifact is an inert archive: the reason to
        push it out of tree would have been a preserved worktree's live symlinks, and a
        `.tar.gz` has none. `.worktrees/` is already gitignored.
        """
        return self._worktree_base / "quarantine"


    def branch_name(self, batch_id: str) -> str:
        return f"{self.branch_prefix}{batch_id}"

    def _worktree_path(self, batch_id: str) -> Path:
        slug = self.branch_prefix.rstrip("/").replace("/", "-") or "author"
        return self._worktree_base / f"{slug}-{batch_id}"

    def commits_ahead(self, wt: Path) -> int:
        return _git.git_rev_list_count(wt, rev_range=f"{_BRANCH_BASE}..HEAD")


    def open_pr_exists(self) -> bool:
        try:
            rows = self._forge.list_open_prs(self.branch_prefix)
        except ForgeError as e:
            raise BranchError(str(e)) from e
        return any(
            str(r.get("headRefName", "")).startswith(self.branch_prefix) for r in rows
        )

    def _open_revert_pr_ref(self, head: str) -> str | None:
        try:
            rows = self._forge.list_prs_for_head(head)
        except ForgeError as e:
            raise BranchError(str(e)) from e
        for r in rows:
            if str(r.get("headRefName", "")) == head:
                url = r.get("url")
                return str(url) if url is not None else head
        return None


    def start_batch(self, batch_id: str) -> Path:
        with contextlib.suppress(GitError):
            _git.git_worktree_prune(self.repo_root)
        wt = self._worktree_path(batch_id)
        try:
            _git.git_fetch(self.repo_root)
            self._worktree_base.mkdir(parents=True, exist_ok=True)
            _git.git_worktree_add(
                self.repo_root, wt, _BRANCH_BASE, branch=self.branch_name(batch_id)
            )
        except GitError as e:
            self.cleanup(wt)
            raise BranchError(str(e)) from e
        return wt

    def finish_batch(self, batch_id: str, wt: Path) -> str | None:
        if self.commits_ahead(wt) == 0:
            return None
        branch = self.branch_name(batch_id)
        try:
            _git.git_push(wt, branch)
            ref = self._forge.open_pr(
                base=_PR_BASE, head=branch,
                title=self.pr_title(batch_id), body=self.pr_body(branch),
            )
        except (GitError, ForgeError) as e:
            raise BranchError(str(e)) from e
        return ref or branch

    def cleanup(self, wt: Path) -> None:
        # Best-effort: a failed removal must not mask the fault that brought us here. But it
        # is never silent — a worktree that survives cleanup is one the box could have written
        # and, on the crash path, one the scrub never walked. The caller's own `except` cannot
        # see this: the suppression lives HERE, so the log has to as well.
        try:
            _git.git_worktree_remove(self.repo_root, wt, force=True)
        except GitError as e:
            _log(f"worktree cleanup failed: {e} — {wt} leaked")


    def revert_lesson_pr(self, lesson_rel_path: str, lesson_name: str) -> str | None:
        branch = f"{LESSONS_BRANCH_PREFIX}revert-{lesson_name}"
        wt = self._worktree_base / branch.replace("/", "-")
        if (existing := self._open_revert_pr_ref(branch)) is not None:
            return existing
        self.cleanup(wt)
        with contextlib.suppress(OSError):
            shutil.rmtree(wt)
        with contextlib.suppress(GitError):
            _git.git_worktree_prune(self.repo_root)
        try:
            _git.git_fetch(self.repo_root)
            if not _git.git_ok(
                ["cat-file", "-e", f"{_BRANCH_BASE}:{lesson_rel_path}"], cwd=self.repo_root
            ):
                raise BranchError(f"no such lesson on {_BRANCH_BASE}: {lesson_rel_path}")
            self._worktree_base.mkdir(parents=True, exist_ok=True)
            _git.git_worktree_add(self.repo_root, wt, _BRANCH_BASE, branch=branch)
            _git.git(["rm", lesson_rel_path], cwd=wt)
            _git.git(["commit", "-m", f"revert lesson: {lesson_name}"], cwd=wt)
            try:
                _git.git_push(wt, branch)
            except GitError as e:
                if _is_non_fast_forward(e):
                    raise BranchError(
                        f"a stale revert branch {branch!r} already exists on origin with no "
                        f"open PR (a prior revert of {lesson_name!r} pushed but did not open a "
                        "PR); delete the remote branch or merge/close its PR, then re-run"
                    ) from e
                raise
            return self._forge.open_pr(
                base=_PR_BASE, head=branch,
                title=f"revert lesson: {lesson_name}",
                body=(
                    f"One-click revert of `{lesson_rel_path}` (recommend-only/reversible "
                    "lesson, §4.4). The cited findings become eligible to re-author once "
                    "this merges."
                ),
            ) or branch
        except (GitError, ForgeError) as e:
            raise BranchError(str(e)) from e
        finally:
            self.cleanup(wt)
