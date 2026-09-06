"""Issue #719, part 3/5 — the append/drain lock split (D1, D2) and the obligations it
discharges: O1 (no row with an unprocessed id is lost), O2 (an append never waits on the
agent call) and O7 (rotation and retirement are mutually exclusive with appends).

Executable spec, pre-implementation. Contention is driven with real `fcntl` locks held from
worker threads, because PJ2a probed that `flock(LOCK_EX)` excludes two OS threads of one
process from each other — so the exclusion under test is the production one, not a stand-in.
Where a genuinely separate actor is needed, a subprocess is used instead: `DEFAULT_PATHS` is
frozen at import (F7), so an in-process environment change never reaches a second actor.

PJ1a is carried as a constraint: the whole-batch timeout is SOFT (`asyncio.wait_for` cannot
preempt a synchronous blocking box call), so no oracle here treats
`LEARNING_AUTHOR_TIMEOUT_SECONDS` as the bound on a stall.
"""
from __future__ import annotations

import inspect
import threading
from pathlib import Path


import _drain719 as h
from _drain719 import drain  # the not-yet-written target, via the suite's own shim
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender.learning.core import drains, persist  # type: ignore[import-not-found]


def _judge_doc(n: int) -> dict:
    return {
        "outcome": "survived",
        "defender_findings": [
            {
                "type": "lead-set",
                "subject_anchor": f"anchor-{i}",
                "subject_topic": "topic",
                "finding": "narrative",
                "citations": [{"source": "investigation", "quote": "..."}],
            }
            for i in range(n)
        ],
    }


# D1 — QueueChannel carries its own lock topology


def test_every_channel_declares_its_lock_topology(tmp_path: Path):
    """D1 gives every `QueueChannel` both roles as fields, and a channel no drain holds
    exclusively carries `None` for the drain role rather than a dangling path (P64: branch on
    `None`, take no exclusive lock).

    The enumeration only picks the subjects; each is then DRIVEN, because a field that merely
    exists certifies nothing. Holding a channel's declared drain lock must make that channel's
    tick skip without authoring, and pitfalls — whose drain-role field is `None` — must have
    no exclusive lock to hold at all."""
    paths = h.make_paths(tmp_path)

    for name in h.AUTHOR_CHANNELS:
        ch = h.channel_of(paths, name)
        assert ch.drain_lock is not None
        assert ch.drain_lock != ch.append_lock
        h.seed(ch, [h.row_for(name, "x/0" if name != "findings" else "run-T/0")])
        h.write_source_refs(paths, "run-T")
        agent = h.recording(h.skipping())
        with h.Holder(ch.drain_lock, blocking_discipline=False):
            assert drain.run_batch(cfg=h.cfg_for(paths, name, invoke_agent=agent)) == 0
        assert agent.calls == [], f"{name}: the declared drain lock did not exclude the tick"

    pit = h.channel_of(paths, "pitfalls")
    assert pit.drain_lock is None, "a channel no drain holds exclusively carries None"
    assert pit.append_lock == paths.pitfalls_pending_dir / ".pitfalls.lock"






# D2 — merge_concurrent deleted; rotation always merges (O1)


def test_rotation_has_no_merge_knob_and_always_merges(tmp_path: Path):
    """D2 deletes the knob rather than parameterising it, because the `if merge_concurrent:`
    branch is the ONLY lock acquisition in the rotation path (C27) — a boolean here preserves
    the row-loss bug in a less visible place.

    Both halves: the parameter is gone from the rotation's signature, and a row appended
    between a batch's read and its rotate is still in pending afterward. The signature check
    alone is satisfiable by a default; the drive is what discharges it."""
    assert "merge_concurrent" not in inspect.signature(persist.rotate_queue_locked).parameters, (
        "the merge knob survives on rotate_queue_locked's signature"
    )

    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "a/0")])
    persist._append_observations(
        ch.file, ch.consumed, ch.append_lock, "late", [{"o": 0}],
        lambda i, obs, oid: {"observation_id": oid, "judge_outcome": "caught"},
    )
    persist.rotate_queue_locked(
        pending_file=ch.file,
        consumed_file=ch.consumed,
        lock_file=ch.append_lock,
        id_key=ch.id_key,
        held=[],
        consumed=[h.row_for("findings", "a/0")],
        commit_sha=None,
    )
    assert sorted(h.pending_by_id(ch)) == ["late/0"], "the unprocessed row survived rotation"


def test_rotation_retains_row_appended_mid_batch(tmp_path: Path):
    """O1 as re-worded by A2: no row with an UNPROCESSED id is lost. The drain is parked in
    its agent call, a live run appends through the real appender, and the row is still in
    pending after the rotate — and was never written to the consumed ledger.

    Discriminating: on the observation channels today this survives only because the envelope
    holds the append lock across the whole batch, which D1 removes."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "a/0")])
    gate, entered = threading.Event(), threading.Event()
    cfg = h.cfg_for(
        paths, "findings", invoke_agent=h.blocking(gate, entered, h.committing())
    )

    with h.Background(lambda: drain.run_batch(cfg=cfg)) as batch:
        assert entered.wait(timeout=20), f"the batch never reached its agent call ({batch.error!r})"
        persist._append_observations(
            ch.file, ch.consumed, ch.append_lock, "mid", [{"o": 0}],
            lambda i, obs, oid: {"observation_id": oid, "judge_outcome": "caught"},
        )
        gate.set()

    assert batch.error is None
    assert batch.result == 0
    assert sorted(h.pending_by_id(ch)) == ["mid/0"]
    assert "mid/0" not in {r.get("observation_id") for r in h.consumed(ch)}




# O2 — appending does not block on an author batch


def test_append_completes_while_drain_batch_in_flight(tmp_path: Path):
    """O2, scoped exactly as §7 resolved it: an append never waits on the AGENT CALL. The
    rotate/retire window is an explicit exception (O7 holds the append lock there), and no
    latency number is claimed — the oracle is pinned to the LLM phase.

    The batch is parked inside its agent call; an append on the same channel then completes
    while the batch is still in flight. Today, on the three observation channels, the envelope
    holds the append lock across exactly this phase and the append blocks unboundedly."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "a/0")])
    gate, entered = threading.Event(), threading.Event()
    cfg = h.cfg_for(
        paths, "findings", invoke_agent=h.blocking(gate, entered, h.committing())
    )

    with h.Background(lambda: drain.run_batch(cfg=cfg)) as batch:
        assert entered.wait(timeout=20), f"the batch never reached its agent call ({batch.error!r})"
        appender = h.Background(
            lambda: persist._append_observations(
                ch.file, ch.consumed, ch.append_lock, "live", [{"o": 0}],
                lambda i, obs, oid: {"observation_id": oid, "judge_outcome": "caught"},
            )
        )
        appender._thread.start()
        landed = appender.finished_within(10)
        gate.set()

    assert landed, "the append waited on the agent call"
    assert appender.error is None
    assert appender.result == 1
    assert batch.error is None




# O7 — rotation and retirement are mutually exclusive with appends


def test_rotate_blocks_while_append_lock_held(tmp_path: Path):
    """O7 is the oracle O1 and O2 were standing in for and could not provide: an
    implementation that simply deleted the lock from the rotation passes both of those and
    fails this. With the append lock held from another actor, the rotation does not proceed;
    when the lock is released it completes."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "a/0")])

    def rotate():
        persist.rotate_queue_locked(
            pending_file=ch.file, consumed_file=ch.consumed, lock_file=ch.append_lock,
            id_key=ch.id_key, held=[], consumed=[h.row_for("findings", "a/0")],
            commit_sha=None,
        )

    worker = h.Background(rotate)
    with h.Holder(ch.append_lock):
        worker._thread.start()
        assert not worker.finished_within(1.0), "the rotation proceeded under a held append lock"
        assert h.pending_by_id(ch) == {"a/0": h.row_for("findings", "a/0")}
    assert worker.finished_within(20), "the rotation never completed after release"
    assert h.pending(ch) == []


def test_retire_blocks_while_append_lock_held(tmp_path: Path):
    """O7 on the path D2 does not reach. Today's dead-letter rewrite takes no lock at all and
    loses a concurrently appended row (G13/C16); D9 removes it as a separate write path, so
    the retire seam must be excluded by the same append lock rotation is."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "a/0")])

    worker = h.Background(
        lambda: drain.retire(channel=ch, batch_ids=["a/0"], reason="excluded", max_attempts=1)
    )
    with h.Holder(ch.append_lock):
        worker._thread.start()
        assert not worker.finished_within(1.0), "the retire seam proceeded under a held lock"
        assert h.graveyard(ch) == [], "not even the graveyard append happened"
    assert worker.finished_within(20)
    assert h.pending(ch) == []
    assert len(h.graveyard(ch)) == 1


def test_every_channels_read_batch_happens_under_the_append_lock(tmp_path: Path):
    """C1/P15, fork 3: the folded read takes the append lock on EVERY channel, so "every touch
    of a pending file happens under `append_lock`" becomes one stateable property rather than
    two divergent lock disciplines. Today `curator.read_batch` is a bare unlocked read and
    `lessons.read_batch` wraps its read in the append lock (C25); folding to either shape
    without deciding regresses one of them.

    Parity across all four drained channels: with the append lock held, no channel's tick
    reaches its agent call."""
    paths = h.make_paths(tmp_path)
    h.write_source_refs(paths, "run-R")
    for name in h.AUTHOR_CHANNELS:
        ch = h.channel_of(paths, name)
        rid = "run-R/0" if name == "findings" else "r/0"
        h.seed(ch, [h.row_for(name, rid)])
        agent = h.recording(h.committing(f"lock-{name}"))
        cfg = h.cfg_for(paths, name, invoke_agent=agent, repo_lock_wait_seconds=1)
        with h.Holder(ch.append_lock):
            assert drain.run_batch(cfg=cfg) == 0
        assert agent.calls == [], f"{name}: the read proceeded without the append lock"
        assert h.pending_by_id(ch), f"{name}: the queue was rewritten anyway"


def test_the_drains_nonblocking_acquisition_excludes_a_real_blocking_appender_through_run_batch(
    tmp_path: Path,
):
    """Design hole 2's SOLE discharge, REPLACED at §7 round 2 (F2). The previous version
    compared `persist._flock` and `shared.acquire_flock` against each other in isolation — two
    primitives this design does not modify — so it was green against unmodified base code and
    would have held for every possible implementation of the drain, including one that took no
    append lock at all. A parity demand discharged by an oracle that cannot fail is not
    discharged.

    Rewritten to drive the DRAIN's own acquisition through `run_batch`, against a real appender
    holding the lock with the blocking primitive appends actually use. If the folded drain
    forgets the append lock, or trades the non-blocking discipline for one that ignores a
    blocking holder, the agent gets called and this fails.

    The control is the same config with nothing held: it authors normally, so the exclusion
    assertion is not passing merely because the tick never worked."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    rows = [h.row_for("findings", "a/0")]
    h.write_source_refs(paths, "a")

    h.seed(ch, rows)
    blocked = h.recording(h.committing("blocked"))
    cfg = h.cfg_for(
        paths, "findings", invoke_agent=blocked, repo_lock_wait_seconds=1
    )
    with h.Holder(ch.append_lock, blocking_discipline=True):
        assert drain.run_batch(cfg=cfg) == 0
    assert blocked.calls == [], "the drain proceeded past a real blocking appender"
    assert h.pending(ch) == rows, "the queue was rewritten while an appender held the lock"

    free = h.recording(h.committing("free"))
    control = h.cfg_for(
        paths, "findings", invoke_agent=free, repo_lock_wait_seconds=1
    )
    assert drain.run_batch(cfg=control) == 0
    assert len(free.calls) == 1, "the control tick did not author, so the exclusion proves nothing"
    assert h.pending(ch) == []


def test_the_drains_append_lock_wait_ends_at_the_configured_repo_lock_deadline(tmp_path: Path):
    """Design hole 1, the WEAKEST-SUPPORTED resolution in the set — an analogy, not a probe, a
    claim or a design sentence — and flagged for override. Applied as resolved: the drain's wait
    on the append lock inherits the repo lock's configured wait deadline.

    REWRITTEN at §7 round 2 (F3). The previous version asserted only an upper bound, so an
    implementation with NO deadline at all passed it, and the override invitation was hollow:
    nothing in the suite moved either way. The observation is now bound to the CONFIGURED value
    — the same contention is driven at two different deadlines and each give-up must track its
    own — which fails for a drain that never waits, one that waits forever, and one that waits a
    hard-coded constant."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    rows = [h.row_for("findings", "a/0")]
    h.write_source_refs(paths, "a")
    observed = {}

    for deadline in (1, 4):
        h.seed(ch, rows)
        agent = h.recording(h.committing("never"))
        cfg = h.cfg_for(
            paths, "findings", invoke_agent=agent, repo_lock_wait_seconds=deadline
        )
        with h.Holder(ch.append_lock):
            rc, seconds = h.elapsed(lambda cfg=cfg: drain.run_batch(cfg=cfg))
        assert rc == 0
        assert agent.calls == []
        assert h.pending(ch) == rows
        observed[deadline] = seconds

    assert 0.8 <= observed[1] < 3.0, f"the 1s deadline was not what ended the wait: {observed}"
    assert 3.2 <= observed[4] < 8.0, f"the 4s deadline was not what ended the wait: {observed}"




# The locks the fold must not change


def test_the_drain_acquires_its_three_locks_in_one_declared_order(tmp_path: Path):
    """C4 (P66 + P12): the acquisition order is pinned by construction in one place rather
    than trusted from an actor census, and enumerated by a test rather than read off the code.

    The declared order is drain lock, then repo lock, then append lock. Driven, not merely
    read: with the drain lock held, the tick must skip WITHOUT ever having taken the repo
    lock — observed by another actor acquiring the repo lock while the contended tick runs —
    which is what an order that took the repo lock first would fail."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    h.seed(ch, [h.row_for("findings", "a/0")])
    assert tuple(drain.LOCK_ORDER) == ("drain_lock", "repo_lock", "append_lock")

    agent = h.recording(h.committing("ordered"))
    cfg = h.cfg_for(paths, "findings", invoke_agent=agent, repo_lock_wait_seconds=1)
    with h.Holder(ch.drain_lock, blocking_discipline=False):
        assert drain.run_batch(cfg=cfg) == 0
        repo_fh = author_shared.acquire_flock(paths.author_lock_file)
        assert repo_fh is not None, "the skipped tick was still holding the repo lock"
        author_shared.release_flock(repo_fh)
    assert agent.calls == []


def test_a_bare_module_invocation_beside_a_live_drain_skips_its_tick(tmp_path: Path):
    """C8/P51: a direct module invocation bypasses the outer `.author-drain.lock` gate, so the
    per-channel drain lock is what stops it — and it SKIPS rather than waiting. That is the
    property that makes the shared `<pending>.tmp` name safe: two ticks never rewrite one
    pending file at once, so the tmp path cannot be contended.

    Observed at the queue: the second invocation authors nothing, rewrites nothing, and leaves
    no `.tmp` artifact behind."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    rows = [h.row_for("findings", "a/0")]
    h.write_source_refs(paths, "a")
    h.seed(ch, rows)
    tmp_name = ch.file.with_name(ch.file.name + ".tmp")

    agent = h.recording(h.committing("second"))
    with h.Holder(ch.drain_lock, blocking_discipline=False):
        rc, seconds = h.elapsed(
            lambda: drain.run_batch(cfg=h.cfg_for(paths, "findings", invoke_agent=agent))
        )
    assert rc == 0
    assert seconds < 10, "the second invocation waited instead of skipping"
    assert agent.calls == []
    assert h.pending(ch) == rows
    assert not tmp_name.exists()


def test_second_author_drain_invocation_returns_without_blocking(tmp_path: Path):
    """P61: the fold does not touch `author_drain`'s OUTER gate. A second `author_drain()`
    invocation still returns immediately at `.author-drain.lock` rather than descending and
    blocking on some per-channel drain lock, so the one-drainer-per-role property is unchanged
    by the split below it. Parity-with-today, stated as such."""
    paths = h.make_paths(tmp_path)
    triggered: list[str] = []

    with h.Holder(paths.author_drain_lock_file, blocking_discipline=False):
        rc, seconds = h.elapsed(
            lambda: drains.author_drain(
                paths, trigger_author=lambda *a, **k: triggered.append(a)
            )
        )
    assert rc == 0
    assert seconds < 10, "the second drainer blocked instead of exiting"
    assert triggered == [], "the second drainer reached a channel"


