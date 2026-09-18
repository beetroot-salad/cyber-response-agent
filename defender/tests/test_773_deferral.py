"""#773 — M7's bounded deferral, O9's conservation, and the tick's two counters.

RED AGAINST HEAD BY CONSTRUCTION: there is no `deferrals` counter on this channel today —
`counter_key` is used only by the pitfalls lane (C14/C18) — and no disposition for a
finding that "could not land through no fault of its own".

O9's shape is the reason every test here asserts THREE things about a deferral: that it is
bounded (the counter moves and the ceiling graveyards), that it is reported (the held
report names it with its count), and that it is not silent (the row is neither consumed nor
lost).
"""
from __future__ import annotations

import time

import pytest

from defender.tests import _spec773 as S

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


def _hold_append_lock(store: dict):
    """Grab the queue's append lock the moment the curator spawn runs.

    `_tick` releases that lock after reading the batch, so this is the one seam from which a
    test can make the tick's CLOSING rotation contend for it — the window every lock-wait
    demand below is about."""

    def grab(*args):
        cfg = args[2]
        holder = S.Holder(cfg.channel.append_lock)
        holder.__enter__()
        store["holder"] = holder

    return grab


# ---------------------------------------------------------------------------
# O9 — bounded, reported, never silent
# ---------------------------------------------------------------------------


def test_a_deferred_row_bumps_the_deferrals_counter_and_graveyards_at_the_ceiling_773(
    tmp_path,
):
    """A deferred row is re-queued carrying an incremented `deferrals` count, and at the
    ceiling it leaves the queue for the graveyard.

    Both halves of "bounded": the counter moves on every deferring tick, and the ceiling
    `cfg.max_attempts` ends it. Driven over real consecutive ticks, not asserted of one."""
    sc = _orphan_tick(tmp_path, max_attempts=2)
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1

    S.seed(sc.channel, [r for r in sc.pending()])
    sc.curator.committed = ["orphan"]
    sc.curator.writes = {}
    assert sc.run() == 0
    assert "orphan" not in sc.pending_by_id()
    assert [r["finding_id"] for r in sc.graveyard()] == ["orphan"]


def test_every_deferred_finding_is_named_in_the_held_reports_deferred_group_773(tmp_path):
    """Every deferred finding is named in the held report's `deferred` group each tick, with
    its ID and its COUNT — and no per-row free-text reason field.

    §7 FK-16: "count" sits inside O9's own obligation text, and the reason is always one of
    two shapes the group name already implies. A deferral with no report line is the
    "silently" O9 forbids."""
    sc = _orphan_tick(tmp_path)
    assert sc.run() == 0
    [line] = sc.report_lines()
    assert "deferred=1" in line
    assert "deferred_ids=['orphan']" in line


def test_the_deferral_rotation_passes_the_configured_repo_lock_wait_773(tmp_path):
    """M7's deferral bump threads `timeout_seconds=cfg.repo_lock_wait_seconds`, the same wait
    #952 threads through every locked rotation.

    The drain holds the repo lock while it waits here, and that lock serialises every
    channel — an unbounded wait would let one wedged appender stall all of them. Observed as
    a bound: with a 1-second wait and the append lock held, the tick gives up quickly rather
    than blocking."""
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


def test_a_bad_verdict_does_not_bump_the_attempts_counter_773(tmp_path):
    """A NEGATIVE demand: a BAD verdict is not a fault, so it bumps NO `attempts` on any row
    of the batch — not the refused finding's and not its batch-mates'.

    N5. The two counters are independent budgets; folding a verdict into the fault budget
    would graveyard a batch for producing lessons the checker disagreed with. Positive
    control on the same address: a genuine `RETIRE_SET` fault DOES bump `attempts`."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("ok", run_id="ok")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("ok")},
            committed=["bad", "ok"],
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD"}),
    )
    assert sc.run() == 0
    # The BAD must actually have fired, or "no attempts were bumped" is also green on a
    # tick where nothing was ever refused — which is HEAD's state.
    assert sc.category_of("bad") == "consumed_forward_bad"
    assert LESSON not in sc.head_files()
    assert all("attempts" not in row for row in sc.pending())
    assert all("attempts" not in row for row in sc.consumed())

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(raises=S.author_error("a real fault")),
    )
    assert control.run() == 2
    assert control.pending_by_id()["f1"]["attempts"] == 1


def test_deferrals_and_attempts_counters_move_independently_across_ticks_773(tmp_path):
    """Two named counters on one row, each bumped only by its own event: a deferring tick
    moves `deferrals` and leaves `attempts` alone, and a faulting tick moves `attempts` and
    leaves `deferrals` alone.

    C18 grounds the primitive — `retire`'s `counter_key` names WHAT is being counted, and
    the pitfalls lane already runs two ceilings through it. Both directions, one row."""
    sc = _orphan_tick(tmp_path)
    assert sc.run() == 0
    row = sc.pending_by_id()["orphan"]
    assert row["deferrals"] == 1
    assert "attempts" not in row

    S.seed(sc.channel, sc.pending())
    sc.curator.raises = S.author_error("now a fault")
    assert sc.run() == 2
    row = sc.pending_by_id()["orphan"]
    assert row["deferrals"] == 1
    assert row["attempts"] == 1


def test_a_deferred_rows_count_after_ten_consecutive_deferring_ticks_773(tmp_path):
    """A row cannot still be live and re-queued after ten deferring ticks: the ceiling
    graveyards it long before, so `deferrals` never reaches ten on a queued row.

    "Never forever" is the half of O9 a counter alone does not deliver — the ceiling has to
    actually end it, which is asserted over real repeated ticks."""
    sc = _orphan_tick(tmp_path, max_attempts=3)
    for _ in range(10):
        S.seed(sc.channel, sc.pending() or [])
        if not sc.pending():
            break
        sc.run()
    assert "orphan" not in sc.pending_by_id()
    assert [r["finding_id"] for r in sc.graveyard()] == ["orphan"]


def test_a_deferral_that_reaches_the_ceiling_773(tmp_path):
    """The bump that REACHES the ceiling graveyards on that same call — `retire`'s boundary
    is `>=`, evaluated and acted on in the call that does the bump, with no grace tick — and
    the graveyard record carries its own `deferred_ceiling` reason.

    §7 FK-17: the boundary is pinned as the EXISTING primitive behaves, so this lane cannot
    silently diverge from the pitfalls lane using the same primitive; the distinct reason is
    the observability gap the probe surfaced, so a deferral exit is greppable apart from a
    fault exit."""
    sc = _orphan_tick(tmp_path, max_attempts=1)
    assert sc.run() == 0
    assert "orphan" not in sc.pending_by_id()
    [record] = sc.graveyard()
    assert record["attempts"] == 1
    assert record["deadletter_reason"] == S.DEFERRED_CEILING_REASON


def test_a_deferred_row_as_the_wake_gate_sees_it_773(tmp_path):
    """The wake gate is UNCHANGED — a deferred row is ordinary pending work, not a held one
    — and the spin that buys is bounded: a row deferred on consecutive ticks reaches the
    graveyard within `max_attempts` ticks.

    §7 FK-18: changing the wake gate widens this change into #881's territory, so the
    ceiling is what bounds the waste. "Never forever" is only a sentence until the bound is
    tested, so the tick count is asserted, not the mechanism."""
    from defender.learning.core import drains

    sc = _orphan_tick(tmp_path, max_attempts=3)
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1, (
        "nothing was deferred, so the spin this bounds never started"
    )
    ticks = 1
    while sc.pending_by_id().get("orphan") and ticks < 10:
        authorable, held = drains._pending_queue_counts(sc.channel.file)
        assert authorable >= 1, "a deferred row must still read as work to the wake gate"
        assert held == 0, "a deferred row is not a permanent hold"
        S.seed(sc.channel, sc.pending())
        sc.curator.writes = {}
        sc.curator.committed = ["orphan"]
        sc.run()
        ticks += 1
    assert ticks <= 3
    assert "orphan" not in sc.pending_by_id()


def test_drain_ticks_own_loop_continuation_is_unaffected_by_the_new_row_fields_773(tmp_path):
    """The drain tick's own reading of the pending queue — does the tick continue or stop —
    is unchanged by M6/M7 adding `consumed_forward_bad` rows and a `deferrals` counter to
    the row shape.

    R7 obligation g10, driven at the UNMOVED reader's own edge: `_pending_queue_counts` is
    what the wake gate compares against its threshold, and `held_reason` is still the one
    field it reads as "not work" (#881/O2). A tick over a queue carrying the new fields
    still finds its work and still returns 0."""
    from defender.learning.core import drains

    sc = _orphan_tick(tmp_path, max_attempts=5)
    assert sc.run() == 0
    authorable, held = drains._pending_queue_counts(sc.channel.file)
    assert (authorable, held) == (1, 0)

    S.seed(sc.channel, sc.pending())
    sc.curator.writes = {"l2.md": S.lesson("orphan")}
    sc.curator.committed = ["orphan"]
    assert sc.run() == 0
    assert LESSON2 in sc.head_files()


def test_max_attempts_one_retires_on_the_first_failure_773(tmp_path):
    """With `max_attempts = 1`, a single `RETIRE_SET`-class fault retires the batch on that
    same tick: the row leaves the queue for the graveyard immediately.

    R4 obligation g3 — the tightest boundary value of the ceiling M7 threads through
    `retire()`, exercised directly rather than inferred from the shipped default of 3.
    GL2 grounds the fault's membership."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(raises=S.author_error("first and only failure")),
        max_attempts=1,
    )
    assert sc.run() == 2
    assert sc.pending() == []
    assert [r["finding_id"] for r in sc.graveyard()] == ["f1"]


# ---------------------------------------------------------------------------
# Conservation — every finding ends somewhere, exactly once
# ---------------------------------------------------------------------------


def test_a_finding_cited_by_one_approved_file_and_one_refused_file_773(tmp_path):
    """A finding cited by two files that DISAGREE about approval this tick is DEFERRED — it
    is added to neither the committed set nor the forward_bad set, and reports the same way
    any other O9 deferral does.

    §7 FK-2, the human's decision, taken over both offered priorities: the drain never has
    to guess between two legitimate-but-incomplete pictures, and it never produces the
    "committed in git, refused in the ledger" state the safer option accepted as a cost. The
    approved FILE still commits — this is a finding-level disposition, not a file-level
    one."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("x", run_id="x"), S.finding_row("solo", run_id="solo")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("x"), "l2.md": S.lesson("x", "solo")},
            committed=["x", "solo"],
        ),
        verifier=S.FakeVerifier(verdicts={("l2.md", "solo"): "BAD"}),
    )
    assert sc.run() == 0
    assert LESSON in sc.head_files()
    assert sc.category_of("x") is None
    assert sc.pending_by_id()["x"]["deferrals"] == 1
    assert sc.category_of("solo") == "consumed_forward_bad"
    assert [r["finding_id"] for r in sc.gap_records()] == ["solo"]


def test_a_finding_cited_by_two_approved_files_is_consumed_committed_exactly_once_773(tmp_path):
    """The POSITIVE CONTROL for the test above: two files citing the SAME finding, every pair
    GOOD or EXEMPT, and the finding lands `consumed_committed` exactly ONCE — one row in
    consumed.jsonl, not two, and absent from every other list.

    The companion clause FK-2 added to `o4_committed_recomputed_from_tree` reads
    "consumed_committed iff an approved file cites it AND no other approved-or-refused-in-this-batch
    file citing the same finding disagrees". The disagreement arm is pinned by the test above;
    this is the agreement arm, and without it the suite never distinguished "the drain defers on
    disagreement" from "the drain defers whenever a finding is multiply cited" — the conflated
    reading passes every assertion in the disagreement test.

    ONCE IS THE LOAD-BEARING WORD. M5 recomputes `committed` by walking the approved files and
    asking which batch ids each cites, so a finding cited by N approved files is reached N times;
    whether that yields one consumption or N depends on the recompute collecting into a set
    rather than a list. Both files really commit, so the multiplicity is genuine and not an
    artifact of the fixture. Asserted as a count over the raw consumed rows, because
    `consumed_by_id()` is keyed BY finding id and would silently collapse a duplicate into one
    entry — the exact failure this test exists to catch.

    (Added at the phase-F repair; the blind conservation reader found the symmetric case
    untested.)"""
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
    assert sorted(sc.verifier.pairs_seen) == [("l1.md", "shared"), ("l2.md", "shared")]
    assert [r["finding_id"] for r in sc.consumed()] == ["shared"]
    assert sc.category_of("shared") == "consumed_committed"
    assert sc.pending_by_id() == {}
    assert sc.gap_records() == []


def test_every_batch_row_reaches_exactly_one_disposition_773(tmp_path):
    """The conservation invariant, over a tick that produces all four endings at once: every
    batch row ends in exactly one of `consumed_committed`, `consumed_forward_bad`,
    `consumed_skip`, or deferred-and-re-queued.

    §7 FK-2 added the fourth ending. A row in two endings, or in none, is the failure this
    pins — and it is the property phase F's conservation reconciliation is written against."""
    sc = S.build_scene(
        tmp_path,
        rows=[
            S.finding_row("ok", run_id="ok"),
            S.finding_row("bad", run_id="bad"),
            S.finding_row("skip", run_id="skip"),
            S.finding_row("orphan", run_id="orphan"),
        ],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("ok"), "l2.md": S.lesson("bad")},
            committed=["ok", "bad", "orphan"],
            consumed_skip=[{"finding_id": "skip", "reason": "already taught"}],
        ),
        verifier=S.FakeVerifier(verdicts={"l2.md": "BAD"}),
    )
    assert sc.run() == 0
    consumed = sc.consumed_by_id()
    queued = sc.pending_by_id()
    assert set(consumed) | set(queued) == {"ok", "bad", "skip", "orphan"}
    assert not (set(consumed) & set(queued))
    assert consumed["ok"]["consumed_category"] == "consumed_committed"
    assert consumed["bad"]["consumed_category"] == "consumed_forward_bad"
    assert consumed["skip"]["consumed_category"] == "consumed_skip"
    assert queued["orphan"]["deferrals"] == 1


def test_a_file_carrying_one_terminal_pair_and_one_approved_pair_after_pass_two_773(tmp_path):
    """The GOOD pair's finding on a file another finding made terminal is re-queued as
    DEFERRED with a bounded, reported count — not committed, not consumed, not lost.

    O9 names this case verbatim in its own failing-by column: "a GOOD pair on a file another
    finding made terminal". The file itself is restored whole, so there is no approved file
    left citing the cleared finding."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("good", run_id="good"), S.finding_row("bad", run_id="bad")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("good", "bad")},
                              committed=["good", "bad"]),
        verifier=S.FakeVerifier(verdicts={"bad": "BAD"}),
        repair=S.FakeRepair(writes={}),
    )
    assert sc.run() == 0
    assert sc.category_of("bad") == "consumed_forward_bad"
    assert sc.pending_by_id()["good"]["deferrals"] == 1
    assert "deferred_ids=['good']" in sc.report_lines()[0]


def test_a_pair_good_in_pass_one_on_a_file_that_later_goes_terminal_for_a_different_pair_773(
    tmp_path,
):
    """Same O9 case reached through pass 2: the file is restored whole, finding A then has
    no approved file citing it, and A is deferred with its counted, reported deferral.

    Not lost, not consumed, not committed — the three ways a deferral can go wrong, each
    asserted."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("b", run_id="b")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("a", "b")}, committed=["a", "b"]),
        verifier=S.FakeVerifier(verdicts={"b": "BAD"}),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("a", "b", body="still wrong")}),
    )
    assert sc.run() == 0
    assert sc.category_of("a") is None
    assert sc.pending_by_id()["a"]["deferrals"] == 1
    assert sc.category_of("b") == "consumed_forward_bad"
    assert sc.head_files() == []


def test_a_file_cited_by_one_refused_finding_and_one_cleared_finding_773(tmp_path):
    """A cleared finding whose ONLY citing file was refused is deferred under O9's "could not
    land through no fault of its own" — by way of M5's "a reported-committed finding no
    approved file cites → deferred".

    The two routes into deferral, M4's and M5's, converge on one disposition and one
    counter."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("x", run_id="x"), S.finding_row("y", run_id="y")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("x", "y")}, committed=["x", "y"]),
        verifier=S.FakeVerifier(verdicts={"x": "BAD"}),
        repair=S.FakeRepair(writes={}),
    )
    assert sc.run() == 0
    assert sc.category_of("x") == "consumed_forward_bad"
    assert sc.pending_by_id()["y"]["deferrals"] == 1


def test_a_batch_row_the_curator_mentions_nowhere_and_no_file_cites_773(tmp_path):
    """A row the curator mentions in no bucket and that no changed file cites stays queued
    EXACTLY as it was, with no counter of any kind bumped.

    C3: a row named in neither the held nor the consumed list of `rotate_queue_locked` is
    left untouched — the probe watched `r2` survive a rotation that named only `r0` and
    `r1`. It is distinct from O4's deferral case, which is a row the curator DID report and
    no approved file cites."""
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
    """Rotation runs exactly once per tick whatever M5 returned: the `None` branch does not
    short-circuit it, and the tick's consumed rows land exactly once.

    Observed as a count over the consumed ledger — a second rotation would write a second
    copy of every consumed row."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad")},
            committed=["bad"],
            consumed_skip=[{"finding_id": "skip", "reason": "dup"}],
        ),
        verifier=S.FakeVerifier(default="BAD"),
    )
    assert sc.run() == 0
    assert sc.commit_count() == 1
    ids = [r["finding_id"] for r in sc.consumed()]
    assert sorted(ids) == ["bad", "skip"]


def test_a_tick_that_both_defers_a_row_and_closes_its_rotation_773(tmp_path):
    """A tick that defers a row and then closes its rotation writes the queue ONCE: the
    deferred row is re-queued carrying its incremented counter in the same rewrite, so a
    closing rotation holding pre-bump copies cannot silently reset the count.

    §7 FK-23 removes the race by construction rather than by discipline. This is the
    QUIETEST way the change can break — the count simply never reaches the ceiling and O9's
    "never forever" fails with no symptom — so the assertion is that a SECOND deferring tick
    reads 2, not 1."""
    sc = _orphan_tick(tmp_path, max_attempts=9)
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1

    S.seed(sc.channel, sc.pending())
    sc.curator.committed = ["orphan"]
    sc.curator.writes = {}
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 2


def test_a_finding_faulted_and_deferred_in_the_same_tick_773(tmp_path):
    """A `RETIRE_SET` fault unwinds BEFORE M5–M7 run at all, so no finding is ever charged
    both counters in one tick: a faulting tick bumps `attempts` only and leaves every
    `deferrals` counter exactly where it was.

    §7 FK-24 confirms the structural reading all three readers inferred from N8's ordering —
    what was missing was a sentence, and this is that sentence made executable."""
    sc = _orphan_tick(tmp_path, max_attempts=9)
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1

    S.seed(sc.channel, sc.pending())
    sc.curator.raises = S.author_error("faulted before M5")
    assert sc.run() == 2
    row = sc.pending_by_id()["orphan"]
    assert row["deferrals"] == 1
    assert row["attempts"] == 1


def test_a_tick_whose_batch_faults_before_reaching_the_deferred_list_computation_773(
    tmp_path,
):
    """A NEGATIVE demand: the fault path bypasses M4–M7 entirely — no gap record, no
    deferral bump, no commit. All three are downstream of the try/undo region completing.

    Its positive control is the same scene without the fault, where all three DO happen, so
    "none of them fired" cannot pass on a tick that never does any of them."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("orphan", run_id="orphan")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad")},
            committed=["bad", "orphan"],
            raises=S.author_error("faulted in the authoring region"),
        ),
        verifier=S.FakeVerifier(default="BAD"),
    )
    assert sc.run() == 2
    assert sc.gap_records() == []
    assert "deferrals" not in sc.pending_by_id()["orphan"]
    assert sc.head_files() == []

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("orphan", run_id="orphan")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad")}, committed=["bad", "orphan"]
        ),
        verifier=S.FakeVerifier(default="BAD"),
    )
    assert control.run() == 0
    assert len(control.gap_records()) == 1
    assert control.pending_by_id()["orphan"]["deferrals"] == 1


# ---------------------------------------------------------------------------
# §7 FK-19 — what a lock wait actually costs
# ---------------------------------------------------------------------------


def test_repo_lock_wait_exceeded_at_the_closing_rotation_773(tmp_path):
    """A commit that already LANDED is never undone by a later rotation failure: the tick
    fails loudly, the tree is correct, and the queue is stale until a retry.

    §7 FK-19(1). M5's commit precedes the closing rotation, so this window is real, and the
    only outcome that does not require a new rollback mechanism is the one the key flow's
    ordering already implies. Undoing the commit here would delete lessons already in
    history and leave the next tick staring at a corpus full of deletions."""
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
    """The deferral bump is ATOMIC with its lock acquisition: a timeout leaves the counter
    exactly where it was, and the retry that follows cannot double-bump it.

    §7 FK-19(2). This is the property O9's ceiling depends on — a double bump graveyards a
    finding early, which O9 calls a violation in the other direction ("never re-authored on
    more than `max_attempts` ticks" cuts both ways)."""
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
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1


def test_a_locked_rotation_that_expires_waiting_for_the_append_lock_773(tmp_path):
    """A rotation that expires against a busy appender leaves the queue exactly as it was —
    no row half-rotated, no counter half-bumped — and surfaces as a stuck tick.

    `TimeoutError` is deliberately outside `RETIRE_SET` (GL2's three members): a busy lock is
    not the batch's fault, so the row keeps its attempt budget and the channel says so on its
    stuck report rather than wedging in silence."""
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
    assert [r["fault_class"] for r in S.stuck_records(sc.channel)] == ["TimeoutError"]
