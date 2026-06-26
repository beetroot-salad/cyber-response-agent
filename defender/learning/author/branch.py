"""Git/gh helpers for the author drains' per-batch git-worktree + PR discipline.

Each author drain is the only stage that commits. Per platform-design §4.4 it
creates a throwaway ``git worktree`` off freshly-fetched ``origin/main`` per
batch, lets its curator(s) commit on that worktree's branch, then pushes and
opens **one** PR — and never more than one open PR per branch-prefix at a time
(the per-prefix writer lease).

**Per-author worktree** (supersedes the 2026-06-10 in-place-branch decision): the
drain operates on its **own** ``git worktree`` rather than moving the dev checkout
onto the batch branch. The dev checkout is never touched, so two drains (lessons +
lead-author) never race on a shared HEAD, a dirty dev tree never blocks a drain,
and there is no ref to restore. Each curator resolves its corpus dir off an
injected ``repo_root`` (a ``LoopPaths(repo_root=<worktree>)``), so pointing it at
the worktree is the whole adaptation — no module-global path mutation. The
original "in-place avoids path injection" rationale is moot now that the injection
seam (the two-root ``LoopPaths``) exists.

``AuthorBranch`` is parameterized on ``branch_prefix`` (+ PR title/body) so the
lessons author (``lessons/``) and the lead author (``lead-author/``) share this
plumbing while opening separate, per-prefix-leased PRs.

``git`` / ``gh`` are injected callables so tests never shell out. Worktree-scoped
git ops go through ``git -C <worktree> …``; ``worktree add/remove/prune`` and
``fetch`` run at ``REPO_ROOT`` against the shared object store.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_BRANCH_PREFIX = "lessons/"
# The PR always targets main; we branch off origin/main so the base is the latest
# merged corpus, never the dev's possibly-stale local main.
_BRANCH_BASE = "origin/main"
_PR_BASE = "main"

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


class BranchError(Exception):
    """The drain can't safely start/finish a batch worktree (git/gh error)."""


def _default_git(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True
    )


def _default_gh(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["gh", *args], cwd=REPO_ROOT, capture_output=True, text=True
    )


def _lessons_pr_title(batch_id: str) -> str:
    return f"learning: lesson batch {batch_id}"


def _lessons_pr_body(branch: str) -> str:
    return (
        "Automated lessons/templates batch from the serial author drain "
        f"(branch `{branch}`, off freshly-fetched `{_BRANCH_BASE}`)."
    )


@dataclass
class AuthorBranch:
    git: Runner = field(default=_default_git)
    gh: Runner = field(default=_default_gh)
    # Per-author identity: lessons defaults keep existing callers unchanged; the
    # lead author passes ``branch_prefix="lead-author/"`` + its own PR text.
    branch_prefix: str = LESSONS_BRANCH_PREFIX
    pr_title: Callable[[str], str] = _lessons_pr_title  # (batch_id) -> title
    pr_body: Callable[[str], str] = _lessons_pr_body    # (branch)   -> body
    # Where batch worktrees are created (one leaf dir per batch). Repo-local
    # scratch; the orchestrator passes ``LoopPaths.worktree_base``.
    worktree_base: Path = field(default_factory=lambda: REPO_ROOT / ".worktrees")

    # -- low-level git ------------------------------------------------------

    def _git_ok(self, args: Sequence[str]) -> str:
        proc = self.git(args)
        if proc.returncode != 0:
            raise BranchError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc.stdout.strip()

    def _git_wt_ok(self, wt: Path, args: Sequence[str]) -> str:
        """Run a worktree-scoped git op via ``git -C <wt> …``."""
        return self._git_ok(["-C", str(wt), *args])

    def _branch(self, batch_id: str) -> str:
        return f"{self.branch_prefix}{batch_id}"

    def _worktree_path(self, batch_id: str) -> Path:
        slug = self.branch_prefix.rstrip("/").replace("/", "-") or "author"
        return self.worktree_base / f"{slug}-{batch_id}"

    def commits_ahead(self, wt: Path) -> int:
        out = self._git_wt_ok(wt, ["rev-list", "--count", f"{_BRANCH_BASE}..HEAD"])
        return int(out or "0")

    # -- writer lease -------------------------------------------------------

    def open_pr_exists(self) -> bool:
        """True if any open PR has a head branch under this ``branch_prefix`` (the
        per-prefix writer lease).

        ``gh pr list --head`` is an exact branch-name filter, not a glob, so we
        prefix-match with ``--search "head:<prefix>"`` and read structured JSON.
        """
        proc = self.gh(
            ["pr", "list", "--search", f"head:{self.branch_prefix}", "--state", "open",
             "--json", "number,headRefName"]
        )
        if proc.returncode != 0:
            raise BranchError(f"gh pr list failed: {proc.stderr.strip()}")
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as e:
            raise BranchError(f"gh pr list returned non-JSON: {e}") from e
        # `--search head:` is a substring match; confirm the head actually starts
        # with the prefix so an unrelated PR can't hold the lease.
        return any(
            isinstance(r, dict) and str(r.get("headRefName", "")).startswith(
                self.branch_prefix
            )
            for r in rows
        )

    # -- batch lifecycle ----------------------------------------------------

    def start_batch(self, batch_id: str) -> Path:
        """Create a fresh worktree on ``<prefix><batch_id>`` off freshly-fetched
        ``origin/main`` and return its path.

        Prunes stale worktree registrations first so a crashed prior batch can't
        block the add. There is no refuse-if-dirty check: the dev checkout is never
        touched and the new worktree is a clean checkout of ``origin/main``."""
        self.git(["worktree", "prune"])  # best-effort; clears crashed-batch stragglers
        self._git_ok(["fetch", "origin"])
        self.worktree_base.mkdir(parents=True, exist_ok=True)
        wt = self._worktree_path(batch_id)
        self._git_ok(["worktree", "add", "-B", self._branch(batch_id), str(wt), _BRANCH_BASE])
        return wt

    def finish_batch(self, batch_id: str, wt: Path) -> str | None:
        """Push + open one PR if the batch produced commits in ``wt``. Returns the
        PR ref (URL/number from ``gh``), or None when the batch made no commits.

        Does NOT remove the worktree — the caller does that unconditionally via
        ``cleanup`` in a ``finally`` (and we don't force a PR on a half-finished
        batch)."""
        if self.commits_ahead(wt) == 0:
            return None
        branch = self._branch(batch_id)
        self._git_wt_ok(wt, ["push", "--set-upstream", "origin", branch])
        proc = self.gh(
            ["pr", "create", "--base", _PR_BASE, "--head", branch,
             "--title", self.pr_title(batch_id),
             "--body", self.pr_body(branch)]
        )
        if proc.returncode != 0:
            raise BranchError(f"gh pr create failed: {proc.stderr.strip()}")
        return proc.stdout.strip() or branch

    def cleanup(self, wt: Path) -> None:
        """Remove the batch worktree — best-effort, always called in a ``finally``.

        A failed remove is harmless: the dev checkout was never touched, so there
        is nothing to strand, and the next batch's ``worktree prune`` (plus the
        random batch id in the path) clears any stale registration."""
        self.git(["worktree", "remove", "--force", str(wt)])

    # -- one-click revert (in-place; not on the concurrent-drain path) ------

    def working_tree_dirty(self) -> bool:
        return bool(self._git_ok(["status", "--porcelain"]))

    def current_ref(self) -> str:
        """The branch name if on one, else the detached HEAD sha — what to restore."""
        proc = self.git(["symbolic-ref", "--quiet", "--short", "HEAD"])
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
        return self._git_ok(["rev-parse", "HEAD"])

    def restore_ref(self, ref: str) -> None:
        """Check the dev's original ref back out — best-effort, always called in a
        ``finally`` so the revert never strands them on the revert branch."""
        self.git(["checkout", ref])

    def revert_lesson_pr(self, lesson_rel_path: str, lesson_name: str) -> str | None:
        """Open a PR that removes one lesson file — the one-click revert (§4.4).

        Kept in-place (it moves the dev checkout onto a revert branch and restores
        it): it is a rare, manually-triggered corrective action (``ops/
        revert_lesson.py``), not part of the concurrent author drains, so it does
        not need worktree isolation. Branches off freshly-fetched ``origin/main``
        (NOT lease-gated — a revert may need to land while another PR is open),
        ``git rm`` + commit + PR, and always restores the dev's HEAD. Returns the PR
        ref. ``lesson_rel_path`` is repo-relative (``defender/lessons/<name>.md``)."""
        if self.working_tree_dirty():
            raise BranchError("working tree is dirty — refusing to start a revert branch")
        original_ref = self.current_ref()
        branch = f"{LESSONS_BRANCH_PREFIX}revert-{lesson_name}"
        self._git_ok(["fetch", "origin"])
        # Existence is checked against ``origin/main`` — the base we branch off — NOT
        # the dev's local tree (which may lag or lead it). Done before any branch
        # churn, so a missing lesson leaves HEAD where it was.
        if self.git(["cat-file", "-e", f"{_BRANCH_BASE}:{lesson_rel_path}"]).returncode != 0:
            raise BranchError(f"no such lesson on {_BRANCH_BASE}: {lesson_rel_path}")
        self._git_ok(["checkout", "-B", branch, _BRANCH_BASE])
        try:
            self._git_ok(["rm", lesson_rel_path])
            self._git_ok(["commit", "-m", f"revert lesson: {lesson_name}"])
            self._git_ok(["push", "--set-upstream", "origin", branch])
            proc = self.gh(
                ["pr", "create", "--base", _PR_BASE, "--head", branch,
                 "--title", f"revert lesson: {lesson_name}",
                 "--body",
                 f"One-click revert of `{lesson_rel_path}` (recommend-only/reversible "
                 "lesson, §4.4). The cited findings become eligible to re-author once "
                 "this merges."]
            )
            if proc.returncode != 0:
                raise BranchError(f"gh pr create failed: {proc.stderr.strip()}")
            return proc.stdout.strip() or branch
        finally:
            self.restore_ref(original_ref)
