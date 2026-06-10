"""Git/gh helpers for the serial author drain's in-place-branch + PR discipline.

The author drain is the only stage that commits. Per platform-design §4.4 it
branches off freshly-fetched ``origin/main`` per batch, lets the curators commit
on that branch, then pushes and opens **one** PR — and never more than one open
lessons PR at a time (the writer lease).

**In-place branch** (decided 2026-06-10, not a separate git worktree): the dev
checkout is moved onto the ``lessons/<batch_id>`` branch for the duration of the
batch and restored to its original ref afterward, so ``REPO_ROOT`` stays the
existing tree and the curators (which resolve their corpus dirs off ``REPO_ROOT``)
need no path injection. The drain refuses to start if the working tree is dirty —
``checkout -B`` would otherwise carry/clobber uncommitted dev edits.

``git`` / ``gh`` are injected callables so tests never shell out.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
LESSONS_BRANCH_PREFIX = "lessons/"
# The PR always targets main; we branch off origin/main so the base is the latest
# merged corpus, never the dev's possibly-stale local main.
_BRANCH_BASE = "origin/main"
_PR_BASE = "main"

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


class BranchError(Exception):
    """The drain can't safely start/finish a batch branch (dirty tree, git error)."""


def _default_git(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True
    )


def _default_gh(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["gh", *args], cwd=REPO_ROOT, capture_output=True, text=True
    )


@dataclass
class AuthorBranch:
    git: Runner = field(default=_default_git)
    gh: Runner = field(default=_default_gh)

    # -- low-level git state ------------------------------------------------

    def _git_ok(self, args: Sequence[str]) -> str:
        proc = self.git(args)
        if proc.returncode != 0:
            raise BranchError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc.stdout.strip()

    def working_tree_dirty(self) -> bool:
        return bool(self._git_ok(["status", "--porcelain"]))

    def current_ref(self) -> str:
        """The branch name if on one, else the detached HEAD sha — what to restore."""
        proc = self.git(["symbolic-ref", "--quiet", "--short", "HEAD"])
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
        return self._git_ok(["rev-parse", "HEAD"])

    def commits_ahead(self) -> int:
        out = self._git_ok(["rev-list", "--count", f"{_BRANCH_BASE}..HEAD"])
        return int(out or "0")

    # -- writer lease -------------------------------------------------------

    def open_lessons_pr_exists(self) -> bool:
        """True if any open PR has a ``lessons/`` head branch (the writer lease).

        ``gh pr list --head`` is an exact branch-name filter, not a glob, so we
        prefix-match with ``--search "head:lessons/"`` and read structured JSON.
        """
        proc = self.gh(
            ["pr", "list", "--search", "head:lessons/", "--state", "open",
             "--json", "number,headRefName"]
        )
        if proc.returncode != 0:
            raise BranchError(f"gh pr list failed: {proc.stderr.strip()}")
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as e:
            raise BranchError(f"gh pr list returned non-JSON: {e}") from e
        # `--search head:` is a substring match; confirm the head actually starts
        # with the lessons prefix so an unrelated PR can't hold the lease.
        return any(
            isinstance(r, dict) and str(r.get("headRefName", "")).startswith(
                LESSONS_BRANCH_PREFIX
            )
            for r in rows
        )

    # -- batch lifecycle ----------------------------------------------------

    def start_batch_branch(self, batch_id: str) -> str:
        """Refuse-if-dirty, then check out a fresh ``lessons/<batch_id>`` off a
        freshly-fetched ``origin/main``. Returns the original ref to restore."""
        if self.working_tree_dirty():
            raise BranchError(
                "working tree is dirty — refusing to start an author batch branch "
                "(commit or stash dev edits first)"
            )
        original_ref = self.current_ref()
        self._git_ok(["fetch", "origin"])
        self._git_ok(["checkout", "-B", f"{LESSONS_BRANCH_PREFIX}{batch_id}", _BRANCH_BASE])
        return original_ref

    def finish_batch(self, batch_id: str) -> str | None:
        """Push + open one PR if the batch produced commits. Returns the PR ref
        (URL/number from ``gh``), or None when the batch made no commits.

        Does NOT restore HEAD — the caller does that unconditionally via
        ``restore_ref`` in a ``finally`` so a mid-batch error still leaves the dev
        where they were (and we don't force a PR on a half-finished batch)."""
        if self.commits_ahead() == 0:
            return None
        branch = f"{LESSONS_BRANCH_PREFIX}{batch_id}"
        self._git_ok(["push", "--set-upstream", "origin", branch])
        proc = self.gh(
            ["pr", "create", "--base", _PR_BASE, "--head", branch,
             "--title", f"learning: lesson batch {batch_id}",
             "--body",
             "Automated lessons/templates batch from the serial author drain "
             f"(branch `{branch}`, off freshly-fetched `{_BRANCH_BASE}`)."]
        )
        if proc.returncode != 0:
            raise BranchError(f"gh pr create failed: {proc.stderr.strip()}")
        return proc.stdout.strip() or branch

    def restore_ref(self, ref: str) -> bool:
        """Check the dev's original ref back out. Best-effort (always called in a
        ``finally`` so the drain never raises while unwinding), but returns
        whether the checkout actually succeeded so the caller can surface a
        failure loudly instead of silently stranding the dev on the lessons
        branch."""
        return self.git(["checkout", ref]).returncode == 0

    def merge_pr(self, pr_ref: str, *, squash: bool = True) -> bool:
        """Enable auto-merge on the PR (GitHub merges it once required checks pass).
        Returns True if ``gh`` accepted the request. Best-effort: a gh failure (e.g.
        auto-merge not enabled on the repo) leaves the PR open for a manual merge."""
        args = ["pr", "merge", pr_ref, "--auto", "--squash" if squash else "--merge"]
        return self.gh(args).returncode == 0
