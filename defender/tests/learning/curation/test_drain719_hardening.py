"""Drain hardening: a bounded append-lock wait at retire, and strays that must not whitelist
themselves."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from pathlib import Path


from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation import _drain719 as h
from defender.learning.author import drain
from defender._git import GitError  # type: ignore[import-not-found]


# The retire seam does not wait forever while holding the repo lock


def test_the_retire_seams_append_lock_wait_ends_at_the_configured_deadline(tmp_path: Path):
    """The retire seam runs inside the repo lock, which serialises every channel's tick, so its
    append-lock wait must end at the configured deadline."""
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
        assert tick.finished_within(20), "the retire seam waited on the append lock with no deadline"
    finally:
        appender.__exit__()

    assert isinstance(tick.error, TimeoutError), f"the tick ended as {tick.error!r}"
    assert h.pending(paths, ch) == rows, "the queue was rewritten by a retire that never got the lock"
    assert h.attempts_of(paths, ch, "a/0") is None, "a contended lock spent one of the row's lives"
    assert h.stuck_records(paths, ch)[-1]["fault_class"] == "TimeoutError"


# The out-of-scope-write guard stays armed across a faulted tick


def test_a_stray_the_agent_wrote_outside_the_corpus_does_not_whitelist_itself(tmp_path: Path):
    """The guard against writes outside the corpus stays armed across a faulted tick: the stray
    is reset away, and a second tick that writes it again faults again."""
    # Over a batch draft the stray sits in the drain's other lane (the box writes only its
    # lanes): outside this channel's corpus, so the scope gate refuses it.
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

    assert drain.run_batch(cfg=cfg) == 2, "the second tick authored: the stray was absorbed into the baseline"
    assert h.attempts_of(paths, ch, "a/0") == 2
    assert not stray.exists()
