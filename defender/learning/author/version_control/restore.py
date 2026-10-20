"""Restore corpus edits while preserving the drain worktree boundary."""
from __future__ import annotations


import logging


from collections.abc import Callable

import contextlib


import functools




from pathlib import Path

from typing import Any


from defender import _git


from defender._git import GitError, GitTimeout


from defender._io import (
    ENTRY_FILE,
    ENTRY_OTHER,
    Held,
    NotPlainEntry,
)

from defender.learning.author import shared as author_shared

from defender.learning.author._config import CorpusAuthorConfig




from defender.learning.core.lane_trees import TreeFor, kind_at




_logger = logging.getLogger(__name__)




def _worktree_git(timeout: float | None) -> dict[str, Any]:
    """The keywords of a curator git call over the worktree: `timeout`, and an environment that
    reads attributes from HEAD's tree and ignores replace objects (`_git.committed_view_env`), so
    no `.gitattributes` the agent left is opened."""
    return {"timeout": timeout, "env": _git.committed_view_env()}




def _unanswered(e: GitError | GitTimeout) -> str:
    """How a git call failed, for a warning: its exit code, or the bound it did not answer within."""
    if isinstance(e, GitTimeout):
        return f"no answer within {e.timeout}s"
    return f"rc={e.returncode}"




def _put_back(
    repo_root: Path, rel: str, *, tree_for: TreeFor, timeout: float | None = None,
) -> None:
    """Return one path to what HEAD has: checked out if tracked, removed if not."""
    _git.git(["checkout", "-q", "--", rel], cwd=repo_root, check=False, **_worktree_git(timeout))
    tracked = _git.git_ok(["ls-files", "--error-unmatch", "--", rel], cwd=repo_root,
                          **_worktree_git(timeout))
    if tracked:
        return
    target = repo_root / rel
    kind = kind_at(repo_root, tree_for, rel)
    hit = tree_for(target)
    if hit is None:
        if kind == ENTRY_FILE:
            target.unlink()
        return
    held, name = hit
    if kind in (ENTRY_FILE, ENTRY_OTHER):
        held.unlink(name)




def _snapshot_corpus(
    repo_root: Path, corpus_dir: Path, head: str, *, timeout: float | None = None,
) -> dict[str, bytes]:
    """The corpus's before-state: every regular file the commit `head` carries under
    `corpus_dir`, nested folders included, with its exact stored bytes, keyed by its name under
    the corpus mount."""
    rel = corpus_dir.relative_to(repo_root).as_posix()
    prefix = "" if rel == "." else f"{rel}/"
    return {path[len(prefix):]: blob
            for path, blob in _git.git_tree_blobs(repo_root, head, rel, timeout=timeout).items()}




def _undo_agent_edits(
    cfg: CorpusAuthorConfig,
    snapshot: dict[str, bytes] | None,
    baseline_stray: list[str],
    head_before: str,
) -> None:
    """Put the worktree back the way the agent found it after a faulted tick."""
    if not _commit_landed(cfg.repo_root, head_before, timeout=cfg.git_timeout):
        _restore_corpus(cfg.repo_root, cfg.corpus_dir, snapshot, corpus=cfg.corpus,
                        head_before=head_before, timeout=cfg.git_timeout)
    _revert_strays(cfg.repo_root, cfg.corpus_dir_rel, baseline_stray, tree_for=cfg.tree_for,
                   timeout=cfg.git_timeout)




def _left_for_scrub(what: str, fn: Callable[..., Any], *args: Any) -> None:
    """Run one fault-path restore step; the core's leaf refusal (`NotPlainEntry`: an entry at the
    name that is not a plain file) is logged and passed over, the entry left in place. Any other
    `OSError` (a linked or non-directory folder on the way, EACCES, EIO, ENOSPC) propagates
    (#1134 O5.3)."""
    try:
        fn(*args)
    except NotPlainEntry as e:
        _logger.warning(f"warn: {what} left for the scrub: {e.strerror}")




def _commit_landed(repo_root: Path, head_before: str, *, timeout: float | None = None) -> bool:
    """Whether HEAD moved; True when git cannot say (or does not within `timeout`), so nothing
    gets deleted."""
    try:
        return author_shared.git_head_sha(repo_root, timeout=timeout) != head_before
    except (GitError, GitTimeout):
        return True




def _revert_strays(
    repo_root: Path, corpus_dir_rel: str, baseline_stray: list[str], *, tree_for: TreeFor,
    timeout: float | None = None,
) -> None:
    """Undo what the agent wrote outside the corpus this tick, leaving pre-existing dirt alone.

    Best-effort: it runs while a fault is propagating, and a second failure would replace that
    diagnosis — a git failure (or a git call not answering within `timeout`) listing the strays
    or putting one back, or a non-plain entry at one."""
    try:
        strays = sorted(
            set(author_shared.changes_outside(repo_root, corpus_dir_rel, **_worktree_git(timeout)))
            - set(baseline_stray)
        )
    except (GitError, GitTimeout):
        return
    for rel in strays:
        try:
            _left_for_scrub(rel, functools.partial(_put_back, tree_for=tree_for, timeout=timeout),
                            repo_root, rel)
        except GitTimeout as e:
            _logger.warning(f"warn: {rel} left for the scrub: git did not answer within "
                            f"{e.timeout}s")




def _unchanged_names(
    repo_root: Path, corpus_dir: Path, rev: str, *, timeout: float | None = None,
) -> frozenset[str]:
    """The names under the corpus mount of the regular files `rev` carries there that git still
    finds unchanged in the worktree (`_git.git_unchanged_since`, #1134 addendum 3 D1): the
    before-state files a restore need not write back. A git failure raises `GitError`; one not
    answering within `timeout`, `GitTimeout`."""
    rel = corpus_dir.relative_to(repo_root).as_posix()
    prefix = "" if rel == "." else f"{rel}/"
    return frozenset(path[len(prefix):]
                     for path in _git.git_unchanged_since(repo_root, rev, rel, timeout=timeout))




def _worktree_files_instead(
    repo_root: Path, corpus_dir: Path, status_fault: GitError | GitTimeout, *,
    timeout: float | None,
) -> list[str]:
    """`_restore_corpus`'s answer when its `git status` failed or did not answer within
    `timeout`: every non-ignored worktree file under the corpus that `git_worktree_files` names,
    or none when that fails too (a warning names both failures)."""
    try:
        made = _git.git_worktree_files(repo_root, str(corpus_dir), timeout=timeout)
    except (GitError, GitTimeout) as files_fault:
        _logger.warning(
            "warn: the corpus restore cannot ask git what changed (git status "
            f"{_unanswered(status_fault)}, git ls-files {_unanswered(files_fault)}); "
            "nothing swept")
        return []
    _logger.warning(
        f"warn: the corpus restore's git status failed ({_unanswered(status_fault)}); "
        "it swept the worktree files git ls-files names instead")
    return made




def _restore_corpus(
    repo_root: Path, corpus_dir: Path, snapshot: dict[str, bytes] | None, *, corpus: Held,
    head_before: str, timeout: float | None = None,
) -> None:
    """Put the corpus back to its pre-agent contents, through `corpus`, its held mount
    (`corpus_dir` is that folder's spelling, the git pathspec only), as the before-state read at
    `head_before` holds them."""
    if snapshot is None:
        return
    # Best-effort, like its unchecked exit: a reset that does not answer in time is passed over.
    with contextlib.suppress(GitTimeout):
        _git.git(["reset", "-q", "--", str(corpus_dir)], cwd=repo_root, check=False,
                 **_worktree_git(timeout))
    try:
        made = [rel for xy, rel in _git.git_status(repo_root, pathspec=corpus_dir,
                                                   no_renames=True, **_worktree_git(timeout))
                if "D" not in xy]
    except (GitError, GitTimeout) as status_fault:
        made = _worktree_files_instead(repo_root, corpus_dir, status_fault, timeout=timeout)
    for rel in made:
        name = (repo_root / rel).relative_to(corpus_dir).as_posix()
        if name not in snapshot:
            _left_for_scrub(name, corpus.unlink, name)
    unchanged: frozenset[str] = frozenset()
    try:
        unchanged = _unchanged_names(repo_root, corpus_dir, head_before, timeout=timeout)
    except (GitError, GitTimeout) as compare_fault:
        _logger.warning(
            "warn: the corpus restore cannot ask git which files still hold their before-state "
            f"bytes (git diff {_unanswered(compare_fault)}); it writes every one back")
    for name, blob in snapshot.items():
        if name not in unchanged:
            _left_for_scrub(name, functools.partial(corpus.write, mode="replace"), name, blob)
