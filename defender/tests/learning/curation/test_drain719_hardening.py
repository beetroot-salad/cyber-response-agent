"""Drain hardening: read-only git probe failures, bounded append-lock wait at retire, and strays that must not whitelist themselves."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from pathlib import Path


from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation import _drain719 as h
from defender.tests.support.learning.curation._drain719 import drain  # noqa: F401 — the target; the shim keeps collection alive
from defender._git import GitError  # type: ignore[import-not-found]


# #1108 P4 OD12(i): `test_a_git_failure_in_a_read_only_probe_does_not_spend_an_attempt` deleted.
# It pinned only `git status` over a writable worktree's index (`GitProbeError`'s no-attempt
# carve-out); a git-free draft has no index to probe. The claim is the draft against the batch
# base's blobs: tests/tenancy/tenant_1108_delivery/test_changes.py::
# test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files (the same
# deletion as test_773_commit_list.py's GitProbeError cases).


# The retire seam does not wait forever while holding the repo lock


def test_the_retire_seams_append_lock_wait_ends_at_the_configured_deadline(tmp_path: Path):
    """The retire seam runs INSIDE the repo lock, which globally serialises all four corpus
    channels."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    rows = [h.row_for("findings", "a/0")]
    h.seed(paths, ch, rows)

    appender = h.Holder(location_path(paths.state_root) / ch.append_lock)

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
    # #1108 P4 (OD12 class ii): over a batch's git-free draft, the stray sits in the drain's
    # other lane (the box writes only its lanes) — outside this channel's corpus, so the lane's
    # scope gate refuses it (a path outside every lane is U10's refused claim instead).
    lane = C.draft_lane(tmp_path)
    paths = lane.paths
    ch = h.channel_of("findings")
    rows = [h.row_for("findings", "a/0")]
    h.seed(paths, ch, rows)
    stray = lane.sibling_dir / "scratch.txt"

    cfg = C.draft_author_cfg(
        lane,
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
