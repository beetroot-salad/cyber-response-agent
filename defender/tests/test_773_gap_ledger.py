"""#773 — M6's gap ledger, the held report's new groups, and the commit-message block.

RED AGAINST HEAD BY CONSTRUCTION: there is no gap ledger today; a forward-BAD lesson is
HELD on the queue with no ceiling and re-authored every tick (C14), which is the disposition
D2 replaces.

O3's ordering — the record is durably written BEFORE the queue rotation — is the whole
crash-safety story, so it is observed here as an ordering, not assumed from the code's
line order.
"""
from __future__ import annotations

import shutil

import pytest

from defender.tests import _spec773 as S

LESSON = "defender/lessons/l1.md"
LESSON2 = "defender/lessons/l2.md"


def _refused(tmp_path, **kw):
    """The one-terminal-finding tick every record-shape demand reads its record off."""
    return S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="r1", direction="adversarial")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1", body="over-broad")}),
        verifier=S.FakeVerifier(default="BAD", reasoning="it flips r1's benign call"),
        **kw,
    )


# ---------------------------------------------------------------------------
# D0 / M6 — the record's shape and its home
# ---------------------------------------------------------------------------


def test_a_gap_record_carries_finding_run_direction_batch_path_text_verdicts_and_time_773(
    tmp_path,
):
    """One record per terminal finding, carrying `finding_id`, `run_id`, `direction`,
    `batch_id`, `lesson_path`, `lesson_text`, `verdicts[]` and `recorded_at`.

    The record is the ONLY durable account of a refusal — M4 restores the file away — so
    every field is asserted for presence, and the ones the operator navigates by
    (`finding_id`, `run_id`, `direction`, `lesson_path`) for value."""
    sc = _refused(tmp_path)
    assert sc.run() == 0
    [record] = sc.gap_records()
    assert set(record) >= {
        "finding_id", "run_id", "direction", "batch_id",
        "lesson_path", "lesson_text", "verdicts", "recorded_at",
    }
    assert record["finding_id"] == "f1"
    assert record["run_id"] == "r1"
    assert record["direction"] == "adversarial"
    assert record["lesson_path"] == LESSON
    assert record["batch_id"]
    assert record["recorded_at"]


def test_the_gap_record_carries_every_verdict_with_its_reasoning_773(tmp_path):
    """O3's "every verdict with its reasoning": the record carries one `verdicts[]` entry per
    `PairVerdict` for that finding across BOTH passes, in pass order, each with the
    verifier's own reasoning text.

    Not every TERMINAL verdict — every verdict, so a human can read what the repair attempt
    was told and what it produced."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="r1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1", body="first")}),
        verifier=S.FakeVerifier(
            default="BAD",
            reasonings={("l1.md", "r1"): "pass one's account"},
        ),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("f1", body="second")}),
    )
    assert sc.run() == 0
    [record] = sc.gap_records()
    assert [v["pass"] for v in record["verdicts"]] == [1, 2]
    assert all(v["reasoning"] == "pass one's account" for v in record["verdicts"])


def test_a_ledger_record_for_a_finding_refused_in_both_passes_on_two_different_files_773(
    tmp_path,
):
    """A finding whose lesson moved between passes is fully recoverable from its ONE record:
    each `verdicts[]` entry carries its own `rel_path`, and the top-level `lesson_path` is
    the terminal (pass-2) location.

    §7 FK-14: the in-memory `PairVerdict` already carries `rel_path`, so nothing has to be
    recovered — the field just has to survive serialization."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="r1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1", body="first home")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(writes={"l2.md": S.lesson("f1", body="moved here")}),
    )
    assert sc.run() == 0
    [record] = sc.gap_records()
    assert {v["rel_path"] for v in record["verdicts"]} == {LESSON, LESSON2}
    assert record["lesson_path"] == LESSON2


def test_the_ledger_gains_its_entries_only_once_both_passes_have_settled_every_pair_773(
    tmp_path,
):
    """The ledger is written ONCE, after both passes settle every pair — a pair BAD in pass 1
    and recovered in pass 2 produces no record at all.

    A pass-1 BAD that pass 2 clears is transient, held only in the tick's in-memory
    structures; writing it durably would hand an operator a gap that was already closed."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="r1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1", body="over-broad")}),
        # PHASE F REPAIR: was a content-sniffing `on_call` hook inspecting
        # `ctx.lesson_text` — a fake deciding a verdict from payload content rather than
        # returning a pre-declared one (rules.md: fakes inject faults, never policy).
        # A per-attempt SCHEDULE says the same thing declaratively: pass 1 = BAD, pass 2
        # (after the repair spawn) = GOOD.
        verifier=S.FakeVerifier(verdicts={"l1.md": ["BAD", "GOOD"]}),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("f1", body="narrowed")}),
    )
    assert sc.run() == 0
    assert sc.gap_records() == []
    assert sc.head_files() == [LESSON]
    assert sc.category_of("f1") == "consumed_committed"
    # The positive control the negative needs: the same address under the complementary
    # condition. Without it "no record was written" is also green on a drain that writes no
    # records at all, which is exactly HEAD's state.
    unrecovered = _refused(tmp_path / "control")
    assert unrecovered.run() == 0
    assert len(unrecovered.gap_records()) == 1


def test_the_recorded_lesson_text_of_a_file_that_is_restored_773(tmp_path):
    """The record's `lesson_text` captures the bytes AS THEY STOOD AT REFUSAL; the ledger
    outlives the restore, which is its purpose.

    The file is gone from the worktree by the time the tick ends, so the text in the record
    is the only copy of what the verifier judged."""
    sc = _refused(tmp_path)
    assert sc.run() == 0
    [record] = sc.gap_records()
    assert record["lesson_text"] == S.lesson("f1", body="over-broad")
    assert not (sc.corpus / "l1.md").exists()


def test_a_terminal_finding_whose_file_never_existed_before_the_tick_773(tmp_path):
    """`lesson_path` is recorded even though M4 unlinked the file, so the path no longer
    resolves after the tick. The record is a standalone ACCOUNT, not a live pointer.

    A reader that treats `lesson_path` as openable finds nothing; `lesson_text` is where the
    content lives."""
    sc = _refused(tmp_path)
    assert sc.run() == 0
    [record] = sc.gap_records()
    assert record["lesson_path"] == LESSON
    assert not (sc.repo / record["lesson_path"]).exists()
    assert record["lesson_text"]


def test_the_gap_ledger_is_written_under_the_host_side_pending_dir_773(tmp_path):
    """The ledger is `pending_dir / "findings.forward_bad.jsonl"` — host-side, under the
    state root, outside every box mount.

    S5/G6: `LoopPaths.with_repo_root` preserves `state_root` and `pending_dir` derives from
    it, not from `repo_root`. It is NOT `pending_delivery_dir` (#952's retained-branch dir),
    which is a different host-side directory the two must not be conflated."""
    state = tmp_path / "state"
    sc = _refused(tmp_path, state_dir=state)
    assert sc.run() == 0
    ledger = sc.cfg.pending_dir / S.GAP_LEDGER_NAME
    assert ledger.is_file()
    assert state in ledger.parents
    assert sc.repo not in ledger.parents


def test_the_ledger_after_the_worktree_is_discarded_773(tmp_path):
    """The ledger SURVIVES the drain worktree being discarded: it is rooted at `state_root`,
    which `with_repo_root` preserves, so throwing the checkout away loses no gap record.

    The worktree is genuinely removed here, not simulated — the record is then read back off
    disk."""
    state = tmp_path / "state"
    sc = _refused(tmp_path, state_dir=state)
    assert sc.run() == 0
    assert len(sc.gap_records()) == 1
    shutil.rmtree(sc.repo)
    assert len(sc.gap_records()) == 1


# ---------------------------------------------------------------------------
# O3 — consumption, ordering, and what a crash in the window costs
# ---------------------------------------------------------------------------


def test_a_terminal_bad_finding_leaves_the_pending_file_as_consumed_forward_bad_773(tmp_path):
    """A finding whose lesson ends BAD after D1 is CONSUMED by this drain with
    `consumed_category: consumed_forward_bad` — off the pending file, never re-queued here.

    D2's decision, replacing today's retryable hold that `_gate_findings` re-admits every
    tick with no ceiling (C14)."""
    sc = _refused(tmp_path)
    assert sc.run() == 0
    assert "f1" not in sc.pending_by_id()
    assert sc.category_of("f1") == "consumed_forward_bad"


def test_a_consumed_forward_bad_row_carries_no_consumed_commit_field_773(tmp_path):
    """A `consumed_forward_bad` row carries NO commit sha: `persist._rotate_queue` stamps
    `consumed_commit` only on `consumed_category == "consumed_committed"` rows (#952).

    Asserted as ABSENCE, not as a value — there is no commit this row belongs to, and a sha
    on it would tell an operator the refused lesson landed. Positive control on the same
    address: the committed batch-mate's row DOES carry one."""
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
    rows = sc.consumed_by_id()
    assert "consumed_commit" not in rows["bad"]
    assert rows["ok"].get("consumed_commit")


def test_the_gap_record_is_written_before_the_queue_rotates_773(tmp_path):
    """The gap record is durably written BEFORE `rotate_queue_locked`. Observed as an
    ordering: with the queue's append lock held by another party, the rotation expires — and
    the record is already on disk while the row is still pending.

    That asymmetry IS O3's guarantee. The reverse order costs a finding consumed as
    `consumed_forward_bad` with no gap record, which is exactly the failure the obligation
    names."""
    held: dict = {}

    def grab_the_append_lock(rows, batch_id, cfg):
        holder = S.Holder(cfg.channel.append_lock)
        holder.__enter__()
        held["holder"] = holder

    sc = _refused(tmp_path, repo_lock_wait_seconds=1)
    sc.curator.also = grab_the_append_lock
    try:
        with pytest.raises(TimeoutError):
            sc.run()
    finally:
        held["holder"].__exit__()
    assert len(sc.gap_records()) == 1
    assert "f1" in sc.pending_by_id()


def test_ledger_append_and_rotation_observed_mid_sequence_by_a_reader_773(tmp_path):
    """A reader in the window between the append and the rotation sees the row STILL PENDING
    and the gap record ALREADY WRITTEN.

    That is O3's intended crash-safety property, not an inconsistency to hide: a duplicate
    record on replay is cheap, a silent consumption is not."""
    held: dict = {}

    def grab_the_append_lock(rows, batch_id, cfg):
        holder = S.Holder(cfg.channel.append_lock)
        holder.__enter__()
        held["holder"] = holder

    sc = _refused(tmp_path, repo_lock_wait_seconds=1)
    sc.curator.also = grab_the_append_lock
    try:
        with pytest.raises(TimeoutError):
            sc.run()
        observed_pending = sc.pending_by_id()
        observed_records = sc.gap_records()
    finally:
        held["holder"].__exit__()
    assert "f1" in observed_pending
    assert [r["finding_id"] for r in observed_records] == ["f1"]


def test_a_crash_between_the_ledger_append_and_the_rotation_replayed_on_a_later_tick_773(
    tmp_path,
):
    """M6 accepts the duplicate by name: a crash in that window costs ONE duplicate gap
    record on the replayed tick and never a silent consumption.

    Driven as two ticks over the same finding — the first's rotation never lands, the second
    re-derives from `git status` and records again. Two records, one finding, and the
    consumption happens exactly once."""
    held: dict = {}

    def grab_the_append_lock(rows, batch_id, cfg):
        holder = S.Holder(cfg.channel.append_lock)
        holder.__enter__()
        held["holder"] = holder

    sc = _refused(tmp_path, repo_lock_wait_seconds=1)
    sc.curator.also = grab_the_append_lock
    try:
        with pytest.raises(TimeoutError):
            sc.run()
    finally:
        held["holder"].__exit__()

    sc.curator.also = None
    assert sc.run() == 0
    assert [r["finding_id"] for r in sc.gap_records()] == ["f1", "f1"]
    assert [r["finding_id"] for r in sc.consumed()] == ["f1"]


def test_a_crash_between_the_commit_and_the_gap_ledger_write_773(tmp_path):
    """A crash between the commit and the ledger write consumes NOTHING: the terminal
    finding's file was restored and never entered the commit list, so the row is still
    pending, no gap record exists, and the next tick re-derives from `git status` (O5).

    O3's ledger-before-rotation ordering is what makes this window safe; no further
    obligation is owed. The crash is induced at the ledger's own sink — the path is a
    directory, so `append_jsonl` genuinely cannot write."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("ok", run_id="ok")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("ok")},
            committed=["bad", "ok"],
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD"}),
    )
    sc.cfg.pending_dir.mkdir(parents=True, exist_ok=True)
    (sc.cfg.pending_dir / S.GAP_LEDGER_NAME).mkdir()
    with pytest.raises(IsADirectoryError):
        sc.run()
    assert "bad" in sc.pending_by_id()
    assert sc.category_of("bad") is None


def test_gap_ledger_append_raises_an_io_error_773(tmp_path):
    """A failing ledger append PROPAGATES: it aborts the tick before the rotation, the
    corpus is restored, the row stays pending, and the batch is re-authored next tick.

    §7 FK-20: O3's ordering exists precisely so that no consumption outruns its record — a
    finding consumed as `consumed_forward_bad` with no gap record is the failure the
    obligation names outright. A retry loop inside the repo lock is the wrong place to be
    patient. The I/O fault is real: the ledger path is a directory."""
    sc = _refused(tmp_path)
    sc.cfg.pending_dir.mkdir(parents=True, exist_ok=True)
    (sc.cfg.pending_dir / S.GAP_LEDGER_NAME).mkdir()
    with pytest.raises(IsADirectoryError):
        sc.run()
    assert sc.consumed() == []
    assert "f1" in sc.pending_by_id()
    assert sc.corpus_files() == []


def test_producer_reenqueues_a_finding_id_mid_ledger_write_window_773(tmp_path):
    """A producer re-minting the same `finding_id` in the ledger-write window still finds it
    on the PENDING file (N7): the row survives a tick that timed out before it could rotate,
    so a producer racing that window sees the same row it already wrote, not an empty queue.

    `enqueue.append_rows` (the JUDGE's own appender, #1007) carries NO idempotency of its own
    at append time — that guard is deliberately downstream, at AUTHOR time
    (`test_921_gate_family_is_idempotent_over_a_replayed_batch`: a `finding_id` already
    authored into a lesson's provenance is what the drain refuses to re-author, not a second
    queue line) — so calling it again with the same id genuinely appends a second row here;
    this pins THAT, not a refusal the appender was never built to make."""
    from defender.learning.judge import enqueue

    held: dict = {}

    def grab_the_append_lock(rows, batch_id, cfg):
        holder = S.Holder(cfg.channel.append_lock)
        holder.__enter__()
        held["holder"] = holder

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="r1", subject="defender")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repo_lock_wait_seconds=1,
    )
    sc.curator.also = grab_the_append_lock
    try:
        with pytest.raises(TimeoutError):
            sc.run()
    finally:
        held["holder"].__exit__()
    assert "f1" in sc.pending_by_id()
    # Drive the REAL appender against the queue as the window left it. `finding_row`'s
    # producer-side shape carries neither `subject_anchor` nor `subject_topic` — the JUDGE's
    # own row-shape fields this appender's validation requires — so they are added here only,
    # at this one call, to reach the append itself.
    row = {**dict(sc.rows[0]), "subject_anchor": "f1", "subject_topic": "narrative"}
    appended = enqueue.append_rows(
        tmp_path / "episode", [row], queue_dir=sc.cfg.pending_dir
    )
    assert appended == 1
    assert len([r for r in sc.pending() if r.get("finding_id") == "f1"]) == 2


# ---------------------------------------------------------------------------
# M6 — the held report's groups, and the commit-message block
# ---------------------------------------------------------------------------


def test_the_held_report_names_forward_bad_terminal_and_deferred_and_no_forward_bad_773(
    tmp_path,
):
    """The held report GAINS `forward_bad_terminal` and `deferred` groups and LOSES
    `forward_bad`.

    A negative and its controls on one line: the retryable-hold label is gone because the
    disposition it named is gone (D2), and the two new labels each carry their own rows.
    An operator reading one label for another reads the wrong recovery."""
    sc = S.build_scene(
        tmp_path,
        rows=[
            S.finding_row("bad", run_id="bad"),
            S.finding_row("orphan", run_id="orphan"),
            S.finding_row("ok", run_id="ok"),
        ],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("ok")},
            committed=["bad", "orphan", "ok"],
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD"}),
    )
    assert sc.run() == 0
    [line] = sc.report_lines()
    assert "forward_bad_terminal=1" in line
    assert "deferred=1" in line
    assert "forward_bad=" not in line.replace("forward_bad_terminal=", "")
    assert "'bad'" in line
    assert "'orphan'" in line


def test_the_report_line_of_a_tick_whose_only_event_was_a_terminal_refusal_773(tmp_path):
    """A tick whose only event was a terminal refusal names the finding under
    `forward_bad_terminal`, and no `forward_bad` group is written at all."""
    sc = _refused(tmp_path)
    assert sc.run() == 0
    [line] = sc.report_lines()
    assert "forward_bad_terminal_ids=['f1']" in line


def test_the_ledger_and_the_report_disagreeing_about_one_finding_773(tmp_path):
    """The ledger and the report CANNOT disagree about membership: both are rendered from
    the tick's single `terminal` mapping, so the ledger's finding set equals the report's
    `forward_bad_terminal` group.

    Driven over a mixed tick, so the equality is over a set with more than one way to be
    wrong."""
    sc = S.build_scene(
        tmp_path,
        rows=[
            S.finding_row("b1", run_id="b1"),
            S.finding_row("b2", run_id="b2"),
            S.finding_row("ok", run_id="ok"),
        ],
        curator=S.FakeCurator(
            writes={
                "l1.md": S.lesson("b1"), "l2.md": S.lesson("b2"), "l3.md": S.lesson("ok"),
            },
            committed=["b1", "b2", "ok"],
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD", "l2.md": "BAD"}),
    )
    assert sc.run() == 0
    [line] = sc.report_lines()
    assert sorted(r["finding_id"] for r in sc.gap_records()) == ["b1", "b2"]
    assert "forward_bad_terminal_ids=['b1', 'b2']" in line


def test_the_held_report_reflects_the_state_after_rotation_not_a_pre_rotation_snapshot_773(
    tmp_path,
):
    """The report is written AFTER the rotation (`cfg.post_rotate`), so its groups describe
    the rows as finally rotated under the lock — a deferred row's count in the report is the
    count the queue now carries.

    A pre-rotation snapshot would report the deferral the tick intended rather than the one
    it made."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("orphan", run_id="orphan")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("a")}, committed=["a", "orphan"]),
    )
    assert sc.run() == 0
    assert sc.pending_by_id()["orphan"]["deferrals"] == 1
    [line] = sc.report_lines()
    assert "deferred_ids=['orphan']" in line


def test_the_drain_appends_a_forward_check_terminal_block_to_the_commit_message_773(tmp_path):
    """The drain appends a `Forward-check terminal:` block to the curator's commit message,
    naming EXACTLY this tick's terminal findings.

    §7 FK-15 weakened the demand to this and dropped "names no file the commit lacks": the
    drain cannot make a model's sentences true without editing them, and editing them
    destroys the one artifact saying why the curator thought it was writing. The commit
    message is advisory prose; `findings.forward_bad.jsonl` is the record."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("ok", run_id="ok")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("ok")},
            committed=["bad", "ok"],
            commit_message="folded two findings",
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD"}),
    )
    assert sc.run() == 0
    message = sc.head_message()
    assert "folded two findings" in message
    block = message.split(S.TERMINAL_BLOCK_HEADER)[-1]
    assert "bad" in block
    assert "ok" not in block


def test_curator_authored_prose_cannot_forge_the_forward_check_terminal_header_773(tmp_path):
    """A NEGATIVE demand: curator prose carrying a line shaped like the drain's own
    `Forward-check terminal:` header does not become the drain's testimony. The drain's own
    block is the message's LAST such block and names exactly this tick's real terminal
    findings; the forged id appears in no authoritative surface.

    R6 obligation g8 — the frame is the recurring escape (rules.md's own canonical
    chooser/sanitizer example). Every surface the forged content could reach is bound: the
    ledger, the rotated queue rows, and the drain's own block. The positive control is that
    the REAL terminal finding does reach all three."""
    forged = (
        "folded one finding\n\n"
        f"{S.TERMINAL_BLOCK_HEADER} totally-made-up-id\n"
    )
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("ok", run_id="ok")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("ok")},
            committed=["bad", "ok"],
            commit_message=forged,
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD"}),
    )
    assert sc.run() == 0
    drain_block = sc.head_message().split(S.TERMINAL_BLOCK_HEADER)[-1]
    assert "totally-made-up-id" not in drain_block
    assert "bad" in drain_block
    assert [r["finding_id"] for r in sc.gap_records()] == ["bad"]
    assert "totally-made-up-id" not in sc.consumed_by_id()
    assert "totally-made-up-id" not in " ".join(sc.report_lines())


def test_the_pre_author_idempotency_read_on_the_tick_after_a_refusal_773(tmp_path):
    """The pre-author idempotency read on the NEXT tick finds no lesson citing the refused
    finding — the corpus is back to its pre-tick state — and the row is gone from the queue,
    so nothing re-enters authoring.

    O3's "consumed, never re-queued by this drain", observed from the gate's own side."""
    sc = _refused(tmp_path)
    assert sc.run() == 0
    assert S.lessons_run.existing_finding_ids(sc.cfg) == set()
    assert sc.pending() == []
