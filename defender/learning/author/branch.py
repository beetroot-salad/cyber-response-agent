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
import shutil
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable

from defender import _git
from defender._git import REPO_ROOT, GitError
from defender._paths import DefenderPaths
from defender.learning.author.forge import Forge, ForgeError, GhForge

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


def _is_non_fast_forward(err: GitError) -> bool:
    """Does this push failure look like a diverged-remote-branch rejection — the branch
    already exists on ``origin`` and our fresh revert commit can't fast-forward it? git flags
    the rejected ref ``(non-fast-forward)`` or ``(fetch first)``. Match those parentheticals,
    not a bare ``rejected`` (which also covers protected-branch / pre-receive-hook denials the
    "stale revert branch" message would misdescribe)."""
    blob = err.stderr.lower()
    return "non-fast-forward" in blob or "fetch first" in blob


@dataclass
class AuthorBranch:
    # ``forge`` is the one explicit injection seam (the network/auth boundary); git is
    # direct. ``None`` (the default) means "derive from ``repo_root``": the ``_forge``
    # property resolves it to ``GhForge(cwd=repo_root)`` so ``gh`` runs where the branch
    # was pushed from, not a stale module global (#479). Pass a forge to inject one.
    forge: Forge | None = None
    # The one injected root: the checkout the repo-level git ops (fetch / worktree
    # add+remove+prune, for both the batch lifecycle and the revert) run against. The
    # other two roots (``worktree_base``, ``forge.cwd``) derive from it when left at their
    # ``None`` default, so a caller threading only ``repo_root`` can't get worktrees/PRs
    # pointed at a different repo (#479). Defaults to the real repo root in production;
    # threaded from a config / pointed at a tmp repo in tests (#389 inject-the-root).
    # Worktree-scoped ops (push / commits_ahead) take the worktree path, not this root.
    repo_root: Path = REPO_ROOT
    # Per-author identity: lessons defaults keep existing callers unchanged; the
    # lead author passes ``branch_prefix="lead-author/"`` + its own PR text.
    branch_prefix: str = LESSONS_BRANCH_PREFIX
    pr_title: Callable[[str], str] = _lessons_pr_title  # (batch_id) -> title
    pr_body: Callable[[str], str] = _lessons_pr_body    # (branch)   -> body
    # Where batch worktrees are created (one leaf dir per batch). ``None`` (the default)
    # derives ``repo_root/.worktrees`` via ``DefenderPaths`` (the single owner of that
    # offset) in the ``_worktree_base`` property; pass a path to place the leaf elsewhere.
    worktree_base: Path | None = None

    # ``forge``/``worktree_base`` are injected-or-``None``; resolve the ``None`` default
    # from ``repo_root`` at the point of use — the ``state_dir``→``state_root`` idiom in
    # ``core.config``. ``is not None`` distinguishes "injected" from "derive", so an
    # explicit override that happens to equal the derived value is never clobbered (the
    # value-equality sentinel it replaces silently would), and ``.worktrees`` stays owned
    # once by ``DefenderPaths`` (#476/#479).
    @property
    def _forge(self) -> Forge:
        return self.forge if self.forge is not None else GhForge(cwd=self.repo_root)

    @property
    def _worktree_base(self) -> Path:
        if self.worktree_base is not None:
            return self.worktree_base
        return DefenderPaths(self.repo_root).worktree_base

    # -- naming -------------------------------------------------------------

    def _branch(self, batch_id: str) -> str:
        return f"{self.branch_prefix}{batch_id}"

    def _worktree_path(self, batch_id: str) -> Path:
        slug = self.branch_prefix.rstrip("/").replace("/", "-") or "author"
        return self._worktree_base / f"{slug}-{batch_id}"

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
            rows = self._forge.list_open_prs(self.branch_prefix)
        except ForgeError as e:
            raise BranchError(str(e)) from e
        return any(
            str(r.get("headRefName", "")).startswith(self.branch_prefix) for r in rows
        )

    def _open_revert_pr_ref(self, head: str) -> str | None:
        """The forge ref (url) of an OPEN PR whose head is *exactly* ``head``, else ``None``.

        Reuses the same ``list_open_prs`` head-search ``open_pr_exists`` uses, but exact-matches
        ``headRefName`` instead of prefix-confirming: the revert is deliberately **not**
        lease-gated, so it must key on the exact ``lessons/revert-<name>`` head and never on the
        ``lessons/`` prefix — else an unrelated open batch PR would make the revert look "in
        flight". Falls back to ``head`` when a row carries no ``url`` (older ``gh`` json)."""
        try:
            rows = self._forge.list_open_prs(head)
        except ForgeError as e:
            raise BranchError(str(e)) from e
        for r in rows:
            if str(r.get("headRefName", "")) == head:
                return str(r.get("url") or head)
        return None

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
            _git.git_fetch(self.repo_root)
            self._worktree_base.mkdir(parents=True, exist_ok=True)
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
            _git.git_push(wt, branch)
            ref = self._forge.open_pr(
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

    # -- one-click revert (own worktree; HEAD-safe) -------------------------

    def revert_lesson_pr(self, lesson_rel_path: str, lesson_name: str) -> str | None:
        """Open a PR that removes one lesson file — the one-click revert (§4.4).

        Runs in its **own throwaway worktree** off freshly-fetched ``origin/main`` — the
        same HEAD-safe model as the batch lifecycle, so it never touches the dev checkout
        and can land while an author drain runs concurrently. NOT lease-gated (a revert
        may need to land while another PR is open). Verifies the lesson exists on
        ``origin/main`` *before* cutting the worktree (a missing lesson leaves no stray
        branch); if a revert PR for this exact head is **already open** it hands that PR's
        ref back (idempotent — a second click returns the same PR rather than non-ff-crashing
        on the stale branch, #482), else ``git rm`` + commit + push + PR. Always removes the
        worktree. Returns the PR ref. ``lesson_rel_path`` is repo-relative
        (``defender/lessons/<name>.md``)."""
        branch = f"{LESSONS_BRANCH_PREFIX}revert-{lesson_name}"
        wt = self._worktree_base / branch.replace("/", "-")  # branch↔worktree correspond
        # The revert worktree path is deterministic (per lesson), so unlike the random
        # batch id it can collide with a crashed prior revert's leaf — in any of the three
        # shapes that leaf can take. Reclaim each before ``worktree add``, or every future
        # revert of this lesson wedges: ``cleanup`` removes a *registered* worktree; the
        # ``rmtree`` clears a *non-registered* leftover dir (which ``worktree remove`` won't
        # touch, so ``worktree add`` would fail "already exists"); the trailing ``prune``
        # then drops any registration the rmtree orphaned.
        self.cleanup(wt)
        with contextlib.suppress(OSError):
            shutil.rmtree(wt)
        with contextlib.suppress(GitError):
            _git.git_worktree_prune(self.repo_root)
        try:
            _git.git_fetch(self.repo_root)
            # Existence is checked against ``origin/main`` — the base we branch off — NOT
            # the dev's local tree. Done before any worktree churn, so a missing lesson
            # creates no branch/worktree.
            if not _git.git_ok(
                ["cat-file", "-e", f"{_BRANCH_BASE}:{lesson_rel_path}"], cwd=self.repo_root
            ):
                raise BranchError(f"no such lesson on {_BRANCH_BASE}: {lesson_rel_path}")
            # Idempotent (#482): if a revert PR for THIS exact head is already open, hand it
            # back rather than cut a fresh commit that non-ff-crashes on push against the stale
            # branch. Keyed on the exact revert head (not the ``lessons/`` prefix), so an
            # unrelated open batch PR never blocks a revert — the not-lease-gated contract.
            if (existing := self._open_revert_pr_ref(branch)) is not None:
                return existing
            self._worktree_base.mkdir(parents=True, exist_ok=True)
            _git.git_worktree_add(self.repo_root, wt, _BRANCH_BASE, branch=branch)
            _git.git(["rm", lesson_rel_path], cwd=wt)
            _git.git(["commit", "-m", f"revert lesson: {lesson_name}"], cwd=wt)
            # A non-ff push means a stale revert branch (no open PR — we just checked) still
            # diverges on origin; translate the raw git rejection into an actionable message
            # instead of leaking it (#482). Any other GitError falls through to the wrap below.
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
