"""#773: bounded deferral, conservation of findings, and the tick's deferral/attempt counters."""
from __future__ import annotations

from pathlib import Path
import time

import pytest

from defender.tests.support.learning.curation import _spec773 as S

LESSON = "defender/lessons/l1.md"
LESSON2 = "defender/lessons/l2.md"


def _orphan_tick(tmp_path, **kw):
    """The plainest deferral: a finding reported committed that no approved file cites."""
    return S.build_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("orphan", run_id="orphan")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("a")}, committed=["a", "orphan"]),
        **kw,
    )


def _defer_again(sc, filler_id: str) -> int:
    """Reseed the queue with whatever is pending plus a fresh, disposable finding, and drive
    one more tick over `orphan` riding uncited alongside it."""
    filler = S.finding_row(filler_id, run_id=filler_id)
    S.seed(sc.paths, sc.channel, [*sc.pending(), filler])
    sc.curator.writes = {f"{filler_id}.md": S.lesson(filler_id)}
    sc.curator.committed = ["orphan", filler_id]
    return sc.run()


def _hold_append_lock(store: dict):
    """Grab the queue's append lock the moment the curator spawn runs."""

    def grab(*args):
        cfg = args[2]
        holder = S.Holder(Path(cfg.state.describe(cfg.channel)).parent / Path(cfg.channel.append_lock).name)
        holder.__enter__()
        store["holder"] = holder

    return grab


def test_a_deferred_row_bumps_the_deferrals_counter_and_graveyards_at_the_ceiling_773(
    tmp_path,
):
    """A deferred row is re-queued carrying an incremented `deferrals` count, and at the
    ceiling it leaves the queue for the graveyard."""
    sc = _orphan_tick(tmp_path, max_attempts=2)
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1

    assert _defer_again(sc, "filler1") == 0
    assert "orphan" not in sc.pending_by_id()
    assert [r["finding_id"] for r in sc.graveyard()] == ["orphan"]


def test_every_deferred_finding_is_named_in_the_held_reports_deferred_group_773(tmp_path):
    """Every deferred finding is named in the held report's `deferred` group each tick, with
    its ID and its COUNT — and no per-row free-text reason field."""
    sc = _orphan_tick(tmp_path)
    assert sc.run() == 0
    [line] = sc.report_lines()
    assert "deferred=1" in line
    assert "deferred_ids=['orphan']" in line


def test_the_deferral_rotation_passes_the_configured_repo_lock_wait_773(tmp_path):
    """M7's deferral bump threads `timeout_seconds=cfg.repo_lock_wait_seconds`, the same wait
    #952 threads through every locked rotation."""
    held: dict = {}
    sc = _orphan_tick(tmp_path, repo_lock_wait_seconds=1)
    sc.curator.also = _hold_append_lock(held)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            sc.run()
    finally:
        held["holder"].__exit__()
    assert time.monotonic() - started < 10
    # The row that would have been deferred is still queued with its counter untouched: the
    # bump never happened, so the wait was spent on the deferral's own rotation.
    assert "deferrals" not in sc.pending_by_id()["orphan"]


def test_deferrals_and_attempts_counters_move_independently_across_ticks_773(tmp_path):
    """Two named counters on one row, each bumped only by its own event."""
    sc = _orphan_tick(tmp_path)
    assert sc.run() == 0
    row = sc.pending_by_id()["orphan"]
    assert row["deferrals"] == 1
    assert "attempts" not in row

    S.seed(sc.paths, sc.channel, sc.pending())
    sc.curator.raises = S.author_error("now a fault")
    assert sc.run() == 2
    row = sc.pending_by_id()["orphan"]
    assert row["deferrals"] == 1
    assert row["attempts"] == 1


def test_a_deferred_rows_count_after_ten_consecutive_deferring_ticks_773(tmp_path):
    """A row cannot still be live and re-queued after ten deferring ticks."""
    sc = _orphan_tick(tmp_path, max_attempts=3)
    for _ in range(10):
        S.seed(sc.paths, sc.channel, sc.pending() or [])
        if not sc.pending():
            break
        sc.run()
    assert "orphan" not in sc.pending_by_id()
    assert [r["finding_id"] for r in sc.graveyard()] == ["orphan"]


def test_a_deferral_that_reaches_the_ceiling_773(tmp_path):
    sc = _orphan_tick(tmp_path, max_attempts=1)
    assert sc.run() == 0
    assert "orphan" not in sc.pending_by_id()
    [record] = sc.graveyard()
    assert record["attempts"] == 1
    assert record["deadletter_reason"] == S.DEFERRED_CEILING_REASON


def test_a_deferred_row_as_the_wake_gate_sees_it_773(tmp_path):
    """The wake gate is UNCHANGED — a deferred row is ordinary pending work, not a held one
    — and the spin that buys is bounded."""
    from defender.learning.core import drains

    sc = _orphan_tick(tmp_path, max_attempts=3)
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1, (
        "nothing was deferred, so the spin this bounds never started"
    )
    ticks = 1
    while sc.pending_by_id().get("orphan") and ticks < 10:
        authorable, held = drains._pending_queue_counts(sc.cfg.state, sc.cfg.channel)
        assert authorable >= 1, "a deferred row must still read as work to the wake gate"
        assert held == 0, "a deferred row is not a permanent hold"
        _defer_again(sc, f"filler{ticks}")
        ticks += 1
    assert ticks <= 3
    assert "orphan" not in sc.pending_by_id()


def test_max_attempts_one_retires_on_the_first_failure_773(tmp_path):
    """With `max_attempts = 1`, a single `RETIRE_SET`-class fault retires the batch on that
    same tick."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(raises=S.author_error("first and only failure")),
        max_attempts=1,
    )
    assert sc.run() == 2
    assert sc.pending() == []
    assert [r["finding_id"] for r in sc.graveyard()] == ["f1"]


def test_a_finding_cited_by_two_approved_files_is_consumed_committed_exactly_once_773(tmp_path):
    """The POSITIVE CONTROL for the test above."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("shared", run_id="shared")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("shared"), "l2.md": S.lesson("shared")},
            committed=["shared"],
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON, LESSON2]
    assert [r["finding_id"] for r in sc.consumed()] == ["shared"]
    assert sc.category_of("shared") == "consumed_committed"
    assert sc.pending_by_id() == {}


def test_every_batch_row_reaches_exactly_one_disposition_773(tmp_path):
    """The conservation invariant, over a tick that produces all three endings at once."""
    sc = S.build_scene(
        tmp_path,
        rows=[
            S.finding_row("ok", run_id="ok"),
            S.finding_row("skip", run_id="skip"),
            S.finding_row("orphan", run_id="orphan"),
        ],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("ok")},
            committed=["ok", "orphan"],
            consumed_skip=[{"finding_id": "skip", "reason": "already taught"}],
        ),
    )
    assert sc.run() == 0
    consumed = sc.consumed_by_id()
    queued = sc.pending_by_id()
    assert set(consumed) | set(queued) == {"ok", "skip", "orphan"}
    assert not (set(consumed) & set(queued))
    assert consumed["ok"]["consumed_category"] == "consumed_committed"
    assert consumed["skip"]["consumed_category"] == "consumed_skip"
    assert queued["orphan"]["deferrals"] == 1


def test_a_batch_row_the_curator_mentions_nowhere_and_no_file_cites_773(tmp_path):
    """A row the curator mentions in no bucket and that no changed file cites stays queued
    EXACTLY as it was, with no counter of any kind bumped."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("named", run_id="named"), S.finding_row("ghost", run_id="ghost")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("named")}, committed=["named"]),
    )
    assert sc.run() == 0
    ghost = sc.pending_by_id()["ghost"]
    assert ghost == sc.rows[1]
    assert "deferrals" not in ghost
    assert "attempts" not in ghost


def test_rotation_runs_exactly_once_per_tick_even_when_the_commit_step_returned_none_773(
    tmp_path,
):
    """Rotation runs exactly once per tick whatever M5 returned."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("dup", run_id="dup"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            committed=[],
            consumed_skip=[{"finding_id": "dup", "reason": "dup"},
                           {"finding_id": "skip", "reason": "dup"}],
        ),
    )
    assert sc.run() == 0
    assert sc.commit_count() == 1
    ids = [r["finding_id"] for r in sc.consumed()]
    assert sorted(ids) == ["dup", "skip"]


def test_a_tick_that_both_defers_a_row_and_closes_its_rotation_773(tmp_path):
    """A tick that defers a row and then closes its rotation writes the queue ONCE."""
    sc = _orphan_tick(tmp_path, max_attempts=9)
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1

    assert _defer_again(sc, "filler1") == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 2


def test_a_finding_faulted_and_deferred_in_the_same_tick_773(tmp_path):
    """A `RETIRE_SET` fault unwinds BEFORE M5–M7 run at all, so no finding is ever charged
    both counters in one tick."""
    sc = _orphan_tick(tmp_path, max_attempts=9)
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1

    S.seed(sc.paths, sc.channel, sc.pending())
    sc.curator.raises = S.author_error("faulted before M5")
    assert sc.run() == 2
    row = sc.pending_by_id()["orphan"]
    assert row["deferrals"] == 1
    assert row["attempts"] == 1


def test_a_tick_whose_batch_faults_before_reaching_the_deferred_list_computation_773(
    tmp_path,
):
    """A NEGATIVE demand."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("orphan", run_id="orphan")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad")},
            committed=["bad", "orphan"],
            raises=S.author_error("faulted in the authoring region"),
        ),
    )
    assert sc.run() == 2
    assert "deferrals" not in sc.pending_by_id()["orphan"]
    assert sc.head_files() == []

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("orphan", run_id="orphan")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad")}, committed=["bad", "orphan"]
        ),
    )
    assert control.run() == 0
    assert control.pending_by_id()["orphan"]["deferrals"] == 1
    assert control.head_files() == ["defender/lessons/l1.md"]


def test_repo_lock_wait_exceeded_at_the_closing_rotation_773(tmp_path):
    """A commit that already LANDED is never undone by a later rotation failure."""
    held: dict = {}
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        repo_lock_wait_seconds=1,
    )
    sc.curator.also = _hold_append_lock(held)
    try:
        with pytest.raises(TimeoutError):
            sc.run()
    finally:
        held["holder"].__exit__()
    assert sc.head_files() == [LESSON]
    assert "f1" in sc.pending_by_id()


def test_repo_lock_wait_exceeded_specifically_on_the_deferral_bump_773(tmp_path):
    """The deferral bump is ATOMIC with its lock acquisition."""
    held: dict = {}
    sc = _orphan_tick(tmp_path, repo_lock_wait_seconds=1, max_attempts=9)
    sc.curator.also = _hold_append_lock(held)
    try:
        with pytest.raises(TimeoutError):
            sc.run()
    finally:
        held["holder"].__exit__()
    assert "deferrals" not in sc.pending_by_id()["orphan"]

    sc.curator.also = None
    assert _defer_again(sc, "filler1") == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1


def test_a_locked_rotation_that_expires_waiting_for_the_append_lock_773(tmp_path):
    """A rotation that expires against a busy appender leaves the queue exactly as it was —
    no row half-rotated, no counter half-bumped — and surfaces as a stuck tick."""
    held: dict = {}
    sc = _orphan_tick(tmp_path, repo_lock_wait_seconds=1)
    before = sc.pending()
    sc.curator.also = _hold_append_lock(held)
    try:
        with pytest.raises(TimeoutError):
            sc.run()
    finally:
        held["holder"].__exit__()
    assert sc.pending() == before
    assert [r["fault_class"] for r in S.stuck_records(sc.paths, sc.channel)] == ["TimeoutError"]
