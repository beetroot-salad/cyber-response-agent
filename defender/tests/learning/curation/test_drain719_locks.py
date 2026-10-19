"""Drain append/drain lock split: rotation and retirement exclude appends, non-blocking drain lock, declared lock order."""
from __future__ import annotations

from pathlib import Path


from defender.tests.support.learning.curation import _drain719 as h
from defender.tests.support.learning.curation._drain719 import drain  # the not-yet-written target, via the suite's own shim
from defender.learning.core.state import (
    AUTHOR_DRAIN_LOCK, FINDINGS, REPO_LOCK, TRY_ONCE, LearningState,
)
from defender.learning.core import drains  # type: ignore[import-not-found]


# D1 — a channel carries its own lock topology


# D2 — merge_concurrent deleted; rotation always merges (O1)


# O2 — appending does not block on an author batch


# O7 — rotation and retirement are mutually exclusive with appends


def test_rotate_blocks_while_append_lock_held(tmp_path: Path):
    """O7 is the oracle O1 and O2 were standing in for and could not provide: an implementation that
    simply deleted the lock from the rotation passes both of those and fails this."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "a/0")])

    def rotate():
        LearningState.open(paths).rotate(
            FINDINGS, [], [h.row_for("findings", "a/0")], None,
        )

    worker = h.Background(rotate)
    with h.Holder(paths.state_root / ch.append_lock):
        worker._thread.start()
        assert not worker.finished_within(1.0), "the rotation proceeded under a held append lock"
        assert h.pending_by_id(paths, ch) == {"a/0": h.row_for("findings", "a/0")}
    assert worker.finished_within(20), "the rotation never completed after release"
    assert h.pending(paths, ch) == []


def test_retire_blocks_while_append_lock_held(tmp_path: Path):
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "a/0")])

    worker = h.Background(
        lambda: drain.retire(
            LearningState.open(paths), channel=FINDINGS, batch_ids=["a/0"], reason="excluded",
            max_attempts=1)
    )
    with h.Holder(paths.state_root / ch.append_lock):
        worker._thread.start()
        assert not worker.finished_within(1.0), "the retire seam proceeded under a held lock"
        assert h.graveyard(paths, ch) == [], "not even the graveyard append happened"
    assert worker.finished_within(20)
    assert h.pending(paths, ch) == []
    assert len(h.graveyard(paths, ch)) == 1


def test_every_channels_read_batch_happens_under_the_append_lock(tmp_path: Path):
    paths = h.make_paths(tmp_path)
    for name in h.AUTHOR_CHANNELS:
        ch = h.channel_of(name)
        rid = "run-R/0" if name == "findings" else "r/0"
        h.seed(paths, ch, [h.row_for(name, rid)])
        agent = h.recording(h.committing(f"lock-{name}"))
        cfg = h.cfg_for(paths, name, invoke_agent=agent, repo_lock_wait_seconds=1)
        with h.Holder(paths.state_root / ch.append_lock):
            assert drain.run_batch(cfg=cfg) == 0
        assert agent.calls == [], f"{name}: the read proceeded without the append lock"
        assert h.pending_by_id(paths, ch), f"{name}: the queue was rewritten anyway"


def test_the_drains_nonblocking_acquisition_excludes_a_real_blocking_appender_through_run_batch(
    tmp_path: Path,
):
    """Design hole 2's SOLE discharge, REPLACED at §7 round 2 (F2)."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    rows = [h.row_for("findings", "a/0")]

    h.seed(paths, ch, rows)
    blocked = h.recording(h.committing("blocked"))
    cfg = h.cfg_for(
        paths, "findings", invoke_agent=blocked, repo_lock_wait_seconds=1
    )
    with h.Holder(paths.state_root / ch.append_lock, blocking_discipline=True):
        assert drain.run_batch(cfg=cfg) == 0
    assert blocked.calls == [], "the drain proceeded past a real blocking appender"
    assert h.pending(paths, ch) == rows, "the queue was rewritten while an appender held the lock"

    free = h.recording(h.committing("free"))
    control = h.cfg_for(
        paths, "findings", invoke_agent=free, repo_lock_wait_seconds=1
    )
    assert drain.run_batch(cfg=control) == 0
    assert len(free.calls) == 1, "the control tick did not author, so the exclusion proves nothing"
    assert h.pending(paths, ch) == []


def test_the_drains_append_lock_wait_ends_at_the_configured_repo_lock_deadline(tmp_path: Path):
    """Design hole 1, the WEAKEST-SUPPORTED resolution in the set — an analogy, not a probe, a claim
    or a design sentence — and flagged for override."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    rows = [h.row_for("findings", "a/0")]
    observed = {}

    for deadline in (1, 2):
        h.seed(paths, ch, rows)
        agent = h.recording(h.committing("never"))
        cfg = h.cfg_for(
            paths, "findings", invoke_agent=agent, repo_lock_wait_seconds=deadline
        )
        with h.Holder(paths.state_root / ch.append_lock):
            rc, seconds = h.elapsed(lambda cfg=cfg: drain.run_batch(cfg=cfg))
        assert rc == 0
        assert agent.calls == []
        assert h.pending(paths, ch) == rows
        observed[deadline] = seconds

    assert 0.8 <= observed[1] < 2.5, f"the 1s deadline was not what ended the wait: {observed}"
    assert 1.8 <= observed[2] < 4.0, f"the 2s deadline was not what ended the wait: {observed}"
    # Each give-up tracks its own deadline: a hard-coded wait gives both the same length.
    assert observed[2] - observed[1] >= 0.6, f"the wait did not follow the deadline: {observed}"


# The locks the fold must not change


def test_the_drain_acquires_its_three_locks_in_one_declared_order(tmp_path: Path):
    """C4 (P66 + P12): the acquisition order is pinned by construction in one place rather than
    trusted from an actor census, and enumerated by a test rather than read off the code."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "a/0")])
    assert tuple(drain.LOCK_ORDER) == ("drain_lock", "repo_lock", "append_lock")

    agent = h.recording(h.committing("ordered"))
    cfg = h.cfg_for(paths, "findings", invoke_agent=agent, repo_lock_wait_seconds=1)
    with h.Holder(paths.state_root / ch.drain_role.file, blocking_discipline=False):
        assert drain.run_batch(cfg=cfg) == 0
        with LearningState.open(paths).lock(REPO_LOCK, wait=TRY_ONCE) as took:
            assert took, "the skipped tick was still holding the repo lock"
    assert agent.calls == []


def test_a_bare_module_invocation_beside_a_live_drain_skips_its_tick(tmp_path: Path):
    """C8/P51: a direct module invocation bypasses the outer `.author-drain.lock` gate, so the per-
    channel drain lock is what stops it — and it SKIPS rather than waiting."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    rows = [h.row_for("findings", "a/0")]
    h.seed(paths, ch, rows)
    tmp_name = (paths.state_root / ch.queue).with_name((paths.state_root / ch.queue).name + ".tmp")

    agent = h.recording(h.committing("second"))
    with h.Holder(paths.state_root / ch.drain_role.file, blocking_discipline=False):
        rc, seconds = h.elapsed(
            lambda: drain.run_batch(cfg=h.cfg_for(paths, "findings", invoke_agent=agent))
        )
    assert rc == 0
    assert seconds < 10, "the second invocation waited instead of skipping"
    assert agent.calls == []
    assert h.pending(paths, ch) == rows
    assert not tmp_name.exists()


def test_second_author_drain_invocation_returns_without_blocking(tmp_path: Path):
    """P61: the fold does not touch `author_drain`'s OUTER gate."""
    paths = h.make_paths(tmp_path)
    triggered: list[str] = []

    with h.Holder(paths.state_root / AUTHOR_DRAIN_LOCK.file, blocking_discipline=False):
        rc, seconds = h.elapsed(
            lambda: drains.author_drain(
                paths, trigger_author=lambda *a, **k: triggered.append(a)
            )
        )
    assert rc == 0
    assert seconds < 10, "the second drainer blocked instead of exiting"
    assert triggered == [], "the second drainer reached a channel"
