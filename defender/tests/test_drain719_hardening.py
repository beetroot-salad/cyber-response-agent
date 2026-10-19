"""Drain hardening: read-only git probe failures, bounded append-lock wait at retire, and strays that must not whitelist themselves."""
from __future__ import annotations

from pathlib import Path

import pytest

import _drain719 as h
from _drain719 import drain  # noqa: F401 — the target; the shim keeps collection alive
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender._git import GitError  # type: ignore[import-not-found]


def _break_index(repo: Path) -> None:
    """Make `git status` fail for real while `git rev-parse HEAD` keeps working."""
    (repo / ".git" / "index").unlink()
    (repo / ".git" / "index").mkdir()


def _repair_index(repo: Path) -> None:
    (repo / ".git" / "index").rmdir()
    h.git(repo, "reset", "-q")


# A read-only git probe is repo contention, not a failing batch


def test_a_git_failure_in_a_read_only_probe_does_not_spend_an_attempt(tmp_path: Path):
    """`GitError` is a member of the retire set for one reason — decision 1 path 3, the commit-time
    failure."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    rows = [h.row_for("findings", "a/0")]
    h.seed(paths, ch, rows)

    cfg = h.cfg_for(
        paths,
        "findings",
        max_attempts=1,
        invoke_agent=h.committing("probe", also=lambda r, b, c: _break_index(c.repo_root)),
    )
    with pytest.raises(drain.GitProbeError):
        drain.run_batch(cfg=cfg)

    assert h.pending(paths, ch) == rows, "a read-only probe failure rewrote the queue"
    assert h.attempts_of(paths, ch, "a/0") is None, (
        "the batch was charged an attempt for a git failure that says nothing about it — "
        "at max_attempts=1 that is real work deleted on the first index-lock collision"
    )
    assert h.graveyard(paths, ch) == []
    assert h.stuck_records(paths, ch)[-1]["fault_class"] == "GitProbeError", (
        "the probe failure left no operator signal, so the row is stuck and silent"
    )

    _repair_index(paths.repo_root)
    author_shared.assert_clean_corpus_dir(paths.repo_root, cfg.corpus_dir, cfg.corpus_dir_rel,
                                          corpus=cfg.corpus)
    recovered = h.cfg_for(
        paths, "findings", max_attempts=1, invoke_agent=h.committing("after")
    )
    assert drain.run_batch(cfg=recovered) == 0, "the channel stayed wedged after the probe fault"
    assert h.pending(paths, ch) == []


# The retire seam does not wait forever while holding the repo lock


def test_the_retire_seams_append_lock_wait_ends_at_the_configured_deadline(tmp_path: Path):
    """The retire seam runs INSIDE the repo lock, which globally serialises all four corpus
    channels."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    rows = [h.row_for("findings", "a/0")]
    h.seed(paths, ch, rows)

    appender = h.Holder(paths.state_root / ch.append_lock)

    def curate_then_appender_takes_the_lock(rows, batch_id, cfg):
        appender.__enter__()
        raise GitError(["commit", "-F", "-"], 1, "fatal: unable to write new index file")

    cfg = h.cfg_for(
        paths,
        "findings",
        max_attempts=1,
        repo_lock_wait_seconds=1,
        invoke_agent=curate_then_appender_takes_the_lock,
    )
    tick = h.Background(lambda: drain.run_batch(cfg=cfg))
    try:
        tick._thread.start()
        assert tick.finished_within(20), (
            "the retire seam is still waiting on the append lock — it is holding the repo "
            "lock, and therefore every sibling channel's tick, with no deadline"
        )
    finally:
        appender.__exit__()

    assert isinstance(tick.error, TimeoutError), f"the tick ended as {tick.error!r}"
    assert h.pending(paths, ch) == rows, "the queue was rewritten by a retire that never got the lock"
    assert h.attempts_of(paths, ch, "a/0") is None, "a contended lock spent one of the row's lives"
    assert h.stuck_records(paths, ch)[-1]["fault_class"] == "TimeoutError"


# The out-of-scope-write guard stays armed across a faulted tick


def test_a_stray_the_agent_wrote_outside_the_corpus_does_not_whitelist_itself(tmp_path: Path):
    """The guard that refuses to commit when the agent touched anything outside the corpus compares
    against a baseline recomputed at the top of every tick."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    rows = [h.row_for("findings", "a/0")]
    h.seed(paths, ch, rows)
    stray = paths.repo_root / "scratch.txt"

    cfg = h.cfg_for(
        paths,
        "findings",
        max_attempts=5,
        invoke_agent=h.committing(
            "stray", also=lambda r, b, c: stray.write_text("written outside the corpus\n")
        ),
    )

    assert drain.run_batch(cfg=cfg) == 2
    assert not stray.exists(), "the out-of-corpus write survived the faulted tick"
    assert h.attempts_of(paths, ch, "a/0") == 1

    assert drain.run_batch(cfg=cfg) == 2, (
        "the second tick authored — the stray was absorbed into the new baseline and the "
        "out-of-scope-write guard is now permanently suppressed for this worktree"
    )
    assert h.attempts_of(paths, ch, "a/0") == 2
    assert not stray.exists()


# A fault AFTER the commit landed must not delete what the commit captured
