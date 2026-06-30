"""Git/forge helpers for the author drains' per-batch git-worktree + PR discipline.

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
the worktree is the whole adaptation — no module-global path mutation.

``AuthorBranch`` is parameterized on ``branch_prefix`` (+ PR title/body) so the
lessons author (``lessons/``) and the lead author (``lead-author/``) share this
plumbing while opening separate, per-prefix-leased PRs.

Git goes through ``defender._git`` directly (local, deterministic, tested against a
real tmp repo); only the **forge** (``gh``) is injected, as a ``Forge`` port, since
it crosses a network/auth boundary tests can't hit. Worktree-scoped git ops pass
``cwd=<worktree>``; ``worktree add/remove/prune`` and ``fetch`` run at ``REPO_ROOT``
against the shared object store. ``BranchError`` is the lifecycle-level union: a
``GitError`` or ``ForgeError`` raised here is translated to it, so the worktree-batch
envelope's ``except BranchError`` skip/retry path is unchanged.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable

from defender import _git
from defender._git import GitError
from defender.learning.author.forge import Forge, ForgeError, GhForge

REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_BRANCH_PREFIX = "lessons/"
# The PR always targets main; we branch off origin/main so the base is the latest
# merged corpus, never the dev's possibly-stale local main.
_BRANCH_BASE = "origin/main"
_PR_BASE = "main"


class BranchError(Exception):
    """The drain can't safely start/finish a batch worktree (git/forge error)."""


def _lessons_pr_title(batch_id: str) -> str:
    return f"learning: lesson batch {batch_id}"


def _lessons_pr_body(branch: str) -> str:
    return (
        "Automated lessons batch from the lessons author drain "
        f"(branch `{branch}`, off freshly-fetched `{_BRANCH_BASE}`). Touches "
        "`defender/lessons/` only — distinct from the lead-author PR."
    )


@dataclass
class AuthorBranch:
    # Only the forge is injected (the network/auth boundary); git is direct.
    forge: Forge = field(default_factory=GhForge)
    # The checkout the repo-level git ops (fetch / worktree add+remove+prune / the
    # in-place revert) run against. Defaults to the real repo root in production;
    # threaded from a config / pointed at a tmp repo in tests (the #389 inject-the-root,
    # not-a-module-global pattern), so tests exercise real git without touching the
    # dev checkout. Worktree-scoped ops (push / commits_ahead) take the worktree path.
    repo_root: Path = REPO_ROOT
    # Per-author identity: lessons defaults keep existing callers unchanged; the
    # lead author passes ``branch_prefix="lead-author/"`` + its own PR text.
    branch_prefix: str = LESSONS_BRANCH_PREFIX
    pr_title: Callable[[str], str] = _lessons_pr_title  # (batch_id) -> title
    pr_body: Callable[[str], str] = _lessons_pr_body    # (branch)   -> body
    # Where batch worktrees are created (one leaf dir per batch). Repo-local
    # scratch; the orchestrator passes ``LoopPaths.worktree_base``.
    worktree_base: Path = field(default_factory=lambda: REPO_ROOT / ".worktrees")

    # -- naming -------------------------------------------------------------

    def _branch(self, batch_id: str) -> str:
        return f"{self.branch_prefix}{batch_id}"

    def _worktree_path(self, batch_id: str) -> Path:
        slug = self.branch_prefix.rstrip("/").replace("/", "-") or "author"
        return self.worktree_base / f"{slug}-{batch_id}"

    def commits_ahead(self, wt: Path) -> int:
        return _git.git_rev_list_count(wt, rev_range=f"{_BRANCH_BASE}..HEAD")

    # -- writer lease -------------------------------------------------------

    def open_pr_exists(self) -> bool:
        """True if any open PR has a head branch under this ``branch_prefix`` (the
        per-prefix writer lease).

        ``list_open_prs`` runs an exact-substring head search; we then confirm the
        head actually *starts with* the prefix so an unrelated PR can't hold the lease.
        """
        try:
            rows = self.forge.list_open_prs(self.branch_prefix)
        except ForgeError as e:
            raise BranchError(str(e)) from e
        return any(
            str(r.get("headRefName", "")).startswith(self.branch_prefix) for r in rows
        )

    # -- batch lifecycle ----------------------------------------------------

    def start_batch(self, batch_id: str) -> Path:
        """Create a fresh worktree on ``<prefix><batch_id>`` off freshly-fetched
        ``origin/main`` and return its path.

        Prunes stale worktree registrations first so a crashed prior batch can't
        block the add. There is no refuse-if-dirty check: the dev checkout is never
        touched and the new worktree is a clean checkout of ``origin/main``.

        If ``worktree add`` fails *after* partially creating the leaf dir / branch ref,
        we reclaim it here before re-raising — the caller's ``finally: cleanup`` only
        runs once ``start_batch`` has returned ``wt``, and ``worktree prune`` won't
        reclaim a dir that is *present* (only a missing one), so an un-handled partial
        would leak."""
        with contextlib.suppress(GitError):
            _git.git_worktree_prune(self.repo_root)  # best-effort; clears crashed-batch stragglers
        wt = self._worktree_path(batch_id)
        try:
            _git.git(["fetch", "origin"], cwd=self.repo_root)
            self.worktree_base.mkdir(parents=True, exist_ok=True)
            _git.git_worktree_add(
                self.repo_root, wt, _BRANCH_BASE, branch=self._branch(batch_id)
            )
        except GitError as e:
            self.cleanup(wt)  # best-effort remove of the partial worktree
            raise BranchError(str(e)) from e
        return wt

    def finish_batch(self, batch_id: str, wt: Path) -> str | None:
        """Push + open one PR if the batch produced commits in ``wt``. Returns the
        PR ref (URL/number from the forge), or None when the batch made no commits.

        Does NOT remove the worktree — the caller does that unconditionally via
        ``cleanup`` in a ``finally`` (and we don't force a PR on a half-finished
        batch)."""
        if self.commits_ahead(wt) == 0:
            return None
        branch = self._branch(batch_id)
        try:
            _git.git(["push", "--set-upstream", "origin", branch], cwd=wt)
            ref = self.forge.open_pr(
                base=_PR_BASE, head=branch,
                title=self.pr_title(batch_id), body=self.pr_body(branch),
            )
        except (GitError, ForgeError) as e:
            raise BranchError(str(e)) from e
        return ref or branch

    def cleanup(self, wt: Path) -> None:
        """Remove the batch worktree — best-effort, always called in a ``finally``.

        A failed remove is harmless: the dev checkout was never touched, so there
        is nothing to strand, and the next batch's ``worktree prune`` (plus the
        random batch id in the path) clears any stale registration."""
        with contextlib.suppress(GitError):
            _git.git_worktree_remove(self.repo_root, wt, force=True)

    # -- one-click revert (in-place; not on the concurrent-drain path) ------

    def working_tree_dirty(self) -> bool:
        return bool(_git.git_status(self.repo_root))

    def current_ref(self) -> str:
        """The branch name if on one, else the detached HEAD sha — what to restore."""
        # ``symbolic-ref --quiet`` prints the branch (rc 0) or nothing (rc 1, detached);
        # empty stdout is the detached signal, so no return-code inspection is needed.
        on_branch = _git.git(
            ["symbolic-ref", "--quiet", "--short", "HEAD"], cwd=self.repo_root, check=False
        )
        return on_branch or _git.git_head_sha(self.repo_root)

    def restore_ref(self, ref: str) -> None:
        """Check the dev's original ref back out — best-effort, always called in a
        ``finally`` so the revert never strands them on the revert branch."""
        _git.git(["checkout", ref], cwd=self.repo_root, check=False)

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
        try:
            _git.git(["fetch", "origin"], cwd=self.repo_root)
            # Existence is checked against ``origin/main`` — the base we branch off — NOT
            # the dev's local tree (which may lag or lead it). Done before any branch
            # churn, so a missing lesson leaves HEAD where it was.
            if not _git.git_ok(
                ["cat-file", "-e", f"{_BRANCH_BASE}:{lesson_rel_path}"], cwd=self.repo_root
            ):
                raise BranchError(f"no such lesson on {_BRANCH_BASE}: {lesson_rel_path}")
            _git.git(["checkout", "-B", branch, _BRANCH_BASE], cwd=self.repo_root)
        except GitError as e:
            raise BranchError(str(e)) from e
        try:
            _git.git(["rm", lesson_rel_path], cwd=self.repo_root)
            _git.git(["commit", "-m", f"revert lesson: {lesson_name}"], cwd=self.repo_root)
            _git.git(["push", "--set-upstream", "origin", branch], cwd=self.repo_root)
            return self.forge.open_pr(
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
            self.restore_ref(original_ref)
