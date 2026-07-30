"""Issue #719, review hardening — four ways the drain charged a batch for something that
was not the batch's fault, or cleaned up too much, or waited forever.

Written AFTER the implementation, unlike the five spec modules beside this one, and kept
separate from them so the spec graph's demand-to-test accounting stays exact. Each test
below is a regression an `xhigh` review found in the shipped fold and the human ratified;
each drives the real primitive rather than a stand-in, and each is written so it FAILS on
the pre-fix behaviour rather than merely passing on the new one.

The project idiom holds here too: faults enter through `dataclasses.replace` seams and
through genuinely broken git state, never through `monkeypatch.setattr`.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import _drain719 as h
from _drain719 import drain  # noqa: F401 — the target; the shim keeps collection alive
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender._git import GitError  # type: ignore[import-not-found]


def _break_index(repo: Path) -> None:
    """Make `git status` fail for real while `git rev-parse HEAD` keeps working.

    An occupied `index.lock` is the wrong instrument: `git status` succeeds under one (it
    simply declines to write the refreshed index), so it fails the COMMIT and not the
    read-only probes. Replacing the index with a directory fails exactly the probes and
    leaves the ref layer intact, which is the split under test."""
    (repo / ".git" / "index").unlink()
    (repo / ".git" / "index").mkdir()


def _repair_index(repo: Path) -> None:
    (repo / ".git" / "index").rmdir()
    h.git(repo, "reset", "-q")


def _git_log(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "log", "--oneline"],
        capture_output=True, text=True, check=True,
    ).stdout


# =======================================================================================
# A read-only git probe is repo contention, not a failing batch
# =======================================================================================


def test_a_git_failure_in_a_read_only_probe_does_not_spend_an_attempt(tmp_path: Path):
    """`GitError` is a member of the retire set for one reason — decision 1 path 3, the
    commit-time failure. But the drain also READS repo state after the agent returns, and
    those reads shell out to `git status` too. On a busy repo an index-lock collision there
    raised `GitError` from a step that had nothing to say about the batch, and the batch
    paid for it: three such collisions over a queue's life and `max_attempts=3` deleted
    correct, fully authored work into the graveyard.

    The agent SUCCEEDS here and breaks git afterwards, so the fault is unambiguously in the
    post-agent probe rather than in the work. What must follow is the non-member
    disposition: nothing bumped, nothing retired, the row still queued, and a stuck record
    naming the class — stuck and loud, which is what every other non-member gets.

    Discriminating in both directions. Before the fix the row bumped and (at this ceiling)
    retired, so the attempt assertion fails; an implementation that swallowed the probe
    failure instead would author nothing and write no stuck record, so the signal assertion
    fails. The tail then shows the channel is not wedged: with git repaired the same rows
    author normally, which also proves the corpus was restored rather than left dirty."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    rows = [h.row_for("actor_observations", "a/0")]
    h.seed(ch, rows)

    cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.committing("probe", also=lambda r, b, c: _break_index(c.repo_root)),
    )
    with pytest.raises(drain.GitProbeError):
        drain.run_batch(cfg=cfg)

    assert h.pending(ch) == rows, "a read-only probe failure rewrote the queue"
    assert h.attempts_of(ch, "a/0") is None, (
        "the batch was charged an attempt for a git failure that says nothing about it — "
        "at max_attempts=1 that is real work deleted on the first index-lock collision"
    )
    assert h.graveyard(ch) == []
    assert h.stuck_records(ch)[-1]["fault_class"] == "GitProbeError", (
        "the probe failure left no operator signal, so the row is stuck and silent"
    )

    _repair_index(paths.repo_root)
    author_shared.assert_clean_corpus_dir(paths.repo_root, cfg.corpus_dir, cfg.corpus_dir_rel)
    recovered = h.cfg_for(
        paths, "actor_observations", max_attempts=1, invoke_agent=h.committing("after")
    )
    assert drain.run_batch(cfg=recovered) == 0, "the channel stayed wedged after the probe fault"
    assert h.pending(ch) == []


# =======================================================================================
# The retire seam does not wait forever while holding the repo lock
# =======================================================================================


def test_the_retire_seams_append_lock_wait_ends_at_the_configured_deadline(tmp_path: Path):
    """The retire seam runs INSIDE the repo lock, which globally serialises all four corpus
    channels. Acquiring the append lock there with an unbounded blocking wait re-introduces
    exactly the stall the drain's own deadline-bounded read was added to prevent: one
    channel's wedged appender holds the repo lock, and therefore every sibling channel's
    tick, with no bound at all.

    Driven through `run_batch` rather than at the seam, because the wiring is the thing that
    was wrong — the seam took no deadline to pass. The commit fails (a member, so the tick
    retires) and an appender takes the channel's append lock in the same breath, so the
    retire meets a held lock. The tick must give up at the configured wait and surface as
    stuck; it must not bump, because a busy lock is not the batch's fault.

    `finished_within` rather than a bare call: the pre-fix behaviour is a HANG, and a
    regression that hangs should fail this test rather than stall the suite."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    rows = [h.row_for("actor_observations", "a/0")]
    h.seed(ch, rows)

    appender = h.Holder(ch.append_lock)

    def commit_then_appender_takes_the_lock(message, cfg):
        appender.__enter__()
        raise GitError(["commit", "-F", "-"], 1, "fatal: unable to write new index file")

    cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        repo_lock_wait_seconds=1,
        invoke_agent=h.committing("retire-wait"),
        commit_fn=commit_then_appender_takes_the_lock,
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
    assert h.pending(ch) == rows, "the queue was rewritten by a retire that never got the lock"
    assert h.attempts_of(ch, "a/0") is None, "a contended lock spent one of the row's lives"
    assert h.stuck_records(ch)[-1]["fault_class"] == "TimeoutError"


# =======================================================================================
# The out-of-scope-write guard stays armed across a faulted tick
# =======================================================================================


def test_a_stray_the_agent_wrote_outside_the_corpus_does_not_whitelist_itself(tmp_path: Path):
    """The guard that refuses to commit when the agent touched anything outside the corpus
    compares against a baseline recomputed at the top of every tick. So a stray that
    SURVIVED a faulted tick was, on the next one, indistinguishable from pre-existing dirt
    the drain did not cause: the guard fired once and was then disarmed for the life of the
    worktree, with the stray silently permitted into every batch after it.

    The corpus restore was never the whole cleanup — reverting only inside the corpus leaves
    precisely the file the guard exists to catch. The commit is pathspec-limited to the
    corpus and can never have captured a stray, so undoing it costs nothing and is
    unconditional.

    The second tick is the discriminating half. Before the fix it AUTHORED, because the
    stray had become baseline; the row rotated out and the guard never spoke again."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    rows = [h.row_for("actor_observations", "a/0")]
    h.seed(ch, rows)
    stray = paths.repo_root / "scratch.txt"

    cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=5,
        invoke_agent=h.committing(
            "stray", also=lambda r, b, c: stray.write_text("written outside the corpus\n")
        ),
    )

    assert drain.run_batch(cfg=cfg) == 2
    assert not stray.exists(), "the out-of-corpus write survived the faulted tick"
    assert h.attempts_of(ch, "a/0") == 1

    assert drain.run_batch(cfg=cfg) == 2, (
        "the second tick authored — the stray was absorbed into the new baseline and the "
        "out-of-scope-write guard is now permanently suppressed for this worktree"
    )
    assert h.attempts_of(ch, "a/0") == 2
    assert not stray.exists()


# =======================================================================================
# A fault AFTER the commit landed must not delete what the commit captured
# =======================================================================================


def test_a_git_failure_after_the_commit_lands_does_not_delete_the_committed_lessons(
    tmp_path: Path,
):
    """The corpus restore exists so a failed commit does not leave edits that wedge the next
    tick. But the commit primitive reads HEAD after committing, so a `GitError` can arrive
    with the lessons already in history — and an unconditional restore then deletes exactly
    the files that commit captured. `git status` shows deletions, the next tick's
    cleanliness gate aborts, and the channel wedges: the precise failure the restore was
    written to prevent, caused by the restore.

    Induced at the one seam where a commit can land and still fault: the real
    `commit_corpus` runs, and the step after it fails. Both halves are asserted, because the
    commit surviving in history is not enough — the working tree has to still hold the files
    that commit names, or the next tick sees deletions."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "environment_observations")
    h.seed(ch, [h.row_for("environment_observations", "b/0")])

    def commit_then_fail_reading_head(message, cfg):
        author_shared.commit_corpus(cfg.repo_root, cfg.corpus_dir, message)
        raise GitError(["rev-parse", "HEAD"], 128, "fatal: bad object HEAD")

    cfg = h.cfg_for(
        paths,
        "environment_observations",
        max_attempts=1,
        invoke_agent=h.committing("landed"),
        commit_fn=commit_then_fail_reading_head,
    )
    assert drain.run_batch(cfg=cfg) == 2

    assert "author landed batch" in _git_log(paths.repo_root), "the commit must have landed"
    lessons = sorted(p.name for p in cfg.corpus_dir.glob("landed-*.md"))
    assert lessons, "the restore deleted the lessons the commit had already captured"
    author_shared.assert_clean_corpus_dir(paths.repo_root, cfg.corpus_dir, cfg.corpus_dir_rel)
