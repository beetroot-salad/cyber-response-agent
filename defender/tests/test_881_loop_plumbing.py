"""#881 — two pieces of the author drain's plumbing that lost a row in silence.

O3 — **every row the pre-author gate holds leaves a written trace in the findings held
report.** The report exists so an operator can see what the drain declined to author, and it
was handed only the forward-check bucket's holds: `DrainOutcome.held` is filled from the
AUTHOR_RESULT buckets, i.e. rows the agent returned a verdict on. The gate's holds — BOTH
arms, `no_ground_truth(...)` and `no_family_ground_truth(...)` — never reached the agent, are
permanent because the facts they wait on have no writer any more, and reached the queue and
nothing else. So the rows that will be there forever were the ones nothing said anything
about.

O4 — **a non-`RETIRE_SET` fault anywhere in a tick leaves exactly one stuck record naming the
fault class.** The gate and the authoring region were wrapped; the unkeyable-row retirement,
which runs before both, was not — so a fault anywhere in it escaped `run_batch` leaving
neither a graveyard entry nor a stuck record. The demand is a guard round the STEP, so the
tests below fault it at two different seams with two different classes: a `TimeoutError` from
its rotation's own bounded wait under a genuinely contended append lock, and an
`OSError(ENOSPC)` from the graveyard append that precedes it (#1135: a folder planted there is now a `StateRefused`, which records nothing by design). Its stuck records must also
fold by ROW, which for a keyless row means by its content — an empty id list, or any key
coarser than the row, reads two unrelated poison rows as one problem getting worse.

O2's wake-gate accounting lives in `tests/test_orchestrate_thresholds.py` and is not repeated
here. O1 — the fence-then-prose regression — was BACKED OUT of this change and has no test
anywhere: `learning/core/validate.py` is byte-identical to the branch base, the judge keeps
today's behaviour (a reply that OPENS with a fence and closes with a sentence costs one draw),
and what a reply carrying several fenced blocks means is left to its own issue. Do not read the
files the design named for it as coverage; they hold none.

Project idioms, because CI ratchets them: fakes enter through `dataclasses.replace` on the
config, never `monkeypatch.setattr`; every fault is a real one met at a real seam — a
contended `flock`, an obstructed path — never an injected exception; and every negative case
is paired with its control on the same address.
"""
from __future__ import annotations

import errno
import json
import os
import re
from collections.abc import Callable
from pathlib import Path

import pytest

import _drain719 as h
from defender.learning.core.state import FINDINGS, LearningState
from _drain719 import drain  # noqa: F401 — the target; the shim keeps collection alive


def _ids_in(line: str, label: str) -> str:
    """The contents of one `<label>=[...]` list on a held-report line.

    A MISSING LABEL FAILS HERE rather than answering `""`. The two assertions this feeds are
    negative — a gate hold must appear in neither `forward_bad_terminal_ids` nor `skipped_ids` — so an
    absent label made them vacuously true: rename the field, drop an empty list, or move the
    line to JSON, and the whole "never merged under one label" demand passes without reading
    anything. `re.escape` for the same reason: a label carrying a regex metacharacter would
    silently match nothing."""
    found = re.search(rf"{re.escape(label)}=\[(.*?)\]", line)
    assert found is not None, (
        f"the held-report line carries no {label}=[...] list, so asserting a row is absent "
        f"from it asserts nothing: {line!r}"
    )
    return found.group(1)


# ---------------------------------------------------------------------------------------
# O3 — a row the pre-author gate holds is named in the held report
# ---------------------------------------------------------------------------------------


def test_881_a_row_the_pre_author_gate_holds_is_named_in_the_findings_held_report(tmp_path):
    """#881/O3, through the real `run_batch` on the real findings channel.

    BOTH ARMS OF THE GATE HOLD, and both must be named. An adversarial finding whose run has
    no resolvable `source_refs.yaml` is held with `no_ground_truth(...)`; a `direction:
    family` row whose `judge_outcome` is not a word the family partition knows is held with
    `no_family_ground_truth(...)`. Both are permanent — the facts they wait on have no writer
    any more — so they sit in the queue on every tick from now on, and a report that names
    one arm and not the other is silent about exactly the rows an operator has to move by
    hand. Naming one reason prefix is not naming the gate's holds.

    THE FIRST TICK IS MIXED — two held rows and one authorable one — because that is the
    shape `_write_held_report_after_rotate` calls itself UNCONDITIONAL for. A report written
    only when the tick committed nothing is invisible on every batch that did any work, which
    is most of them; the batch where a row was declined WHILE its neighbours were authored is
    the one an operator most needs. The agent's captured batch is asserted to be exactly the
    authorable row, so "mixed" is a fact about the tick and not about the seeding.

    THE SECOND TICK HOLDS A DIFFERENT ROW, and the first tick's line must still be there. The
    report is an append-only ledger; a writer that opened it `"w"` would satisfy every
    single-tick assertion above while destroying the record of the tick before — and a
    control that only asserts the file is UNCHANGED cannot see that, because the tick it
    checks never opens the file at all.

    THE THIRD TICK IS THE PAIRED CONTROL, on the same address under the complementary
    condition: it holds nothing, and the report gains nothing. Without it a writer that
    appended a line every tick would pass everything above while making the report
    unreadable — which is the same as not having one.

    Each held id is also asserted NOT to be inside `forward_bad_terminal_ids=[...]` or
    `skipped_ids=[...]`. `DrainOutcome.held` is typed as the AUTHOR_RESULT bucket holds, so
    folding the gate's holds into that bucket would report a row the forward check never saw
    as a forward-check verdict, and a skip is terminal where a hold is forever. What the
    third label IS is the implementation's to choose; that it is neither of those two is the
    demand.
    """
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    legacy = h.row_for("findings", "a/0")
    family = h.row_for("findings", "f/0", direction="family", judge_outcome="not-a-word")
    authorable = h.row_for("findings", "z/0")
    h.write_source_refs(paths, "z")
    h.seed(paths, ch, [legacy, family, authorable])
    agent = h.recording(h.committing("881-o3"))
    cfg = h.cfg_for(paths, "findings", invoke_agent=agent)
    report = paths.state_root / FINDINGS.report

    assert drain.run_batch(cfg=cfg) == 0
    assert [[r["finding_id"] for r in call["rows"]] for call in agent.calls] == [["z/0"]], (
        "the tick did not author exactly the one authorable row, so it is not the mixed "
        "batch this test is about"
    )
    assert {r["finding_id"]: r.get("held_reason") for r in h.pending(paths, ch)} == {
        "a/0": "no_ground_truth(direction='adversarial', disposition=None)",
        "f/0": "no_family_ground_truth(judge_outcome='not-a-word')",
    }, "the tick did not hold the two rows this test is about"

    assert report.is_file(), (
        "the tick held two rows and wrote no held report at all — the gate's holds are the "
        "permanent ones, and they are the ones with no written trace"
    )
    first_tick = report.read_text(encoding="utf-8")
    for held_id, arm in (("a/0", "no_ground_truth"), ("f/0", "no_family_ground_truth")):
        assert held_id in first_tick, (
            f"the row held on the {arm} arm is not named in the report, although the tick "
            f"committed a row alongside it: {first_tick!r}"
        )
        for line in first_tick.splitlines():
            assert held_id not in _ids_in(line, "forward_bad_terminal_ids"), (
                "a pre-author gate hold was reported as a forward-check verdict; the "
                f"forward check never saw this row: {line!r}"
            )
            assert held_id not in _ids_in(line, "skipped_ids"), (
                f"a held row was reported as a skip — a hold is not terminal: {line!r}"
            )

    # A second HOLDING tick: the report is a ledger, so it grows by a line and keeps the one
    # it had. `"w"` instead of `"a"` fails here and nowhere else.
    h.seed(paths, ch, [h.row_for("findings", "b/0")])
    assert drain.run_batch(cfg=cfg) == 0
    second_tick = report.read_text(encoding="utf-8")
    assert "b/0" in second_tick, "the second tick's hold is not named in the report"
    assert first_tick in second_tick, (
        "the second tick's report TRUNCATED the first tick's line rather than appending to "
        f"it; the record of every earlier hold is gone: {second_tick!r}"
    )
    assert len(second_tick.splitlines()) == 2, (
        f"the report is a ledger and must have grown by exactly one line: {second_tick!r}"
    )

    # The paired control: a tick that holds nothing writes nothing.
    h.seed(paths, ch, [h.row_for("findings", "c/0")])
    h.write_source_refs(paths, "c")
    assert drain.run_batch(cfg=cfg) == 0
    assert h.pending(paths, ch) == [], "the row was not authored on the tick that could author it"
    assert report.read_text(encoding="utf-8") == second_tick, (
        "a tick that held nothing appended to the held report anyway; a report that grows "
        "on every tick names nothing"
    )


# ---------------------------------------------------------------------------------------
# O4 — the unkeyable-row retirement is inside the stuck-recording guard
# ---------------------------------------------------------------------------------------


class _StateThatLetsAnAppenderIn(LearningState):
    """The learning state handle, plus one callback fired at the single instant an appender can
    arrive with no race to lose.

    That instant is the end of the retirement's graveyard append. `_retire_unkeyable` calls
    `state.deadletter(...)` and then `state.rotate(...)`, and the call between them sits AFTER
    `_tick` released the append lock (the batch read is over) and BEFORE the rotation asks for
    it again. So nothing holds the lock when the callback runs and the appender can take it
    SYNCHRONOUSLY: `Holder.__enter__` returns only once it OWNS the lock, so when the drain
    resumes the lock is already held. No thread, no interval to guess at, nothing to lose
    under load.

    Nothing about the contention is faked. The appender takes the real `flock` on the real
    lock file with the appender's own blocking discipline (no deadline), and the `TimeoutError`
    under test is raised by the retire rotation's own bounded wait. What the hook decides is
    only WHEN the appender arrives.

    It enters through `dataclasses.replace(cfg, state=...)`, the config seam, not through
    `monkeypatch.setattr`: a handle sharing the real one's descriptor (`over`), with the one
    verb wrapped. The real handle must outlive it."""

    _on_deadletter: Callable[[], None] | None = None
    _fired: bool = False

    @classmethod
    def over(cls, real: LearningState, on_deadletter: Callable[[], None]) -> LearningState:
        self = cls.__new__(cls)
        self.__dict__.update(real.__dict__)
        self._real = real  # keeps the shared descriptor open for as long as this one lives
        self._on_deadletter = on_deadletter
        return self

    def deadletter(self, channel, entries):
        super().deadletter(channel, entries)
        if not self._fired and self._on_deadletter:
            self._fired = True
            self._on_deadletter()


class _StateWhoseDiskIsFull(LearningState):
    """The learning state handle, with one verb answering `ENOSPC` while `full` is set.

    #1135: a folder planted where the graveyard or the held report belongs is now a refusal
    (`StateRefused`), which stops the tick and records NOTHING by design ("a planted entry
    stops the tick, and nothing is recorded after it"). The fault these tests need is an
    ordinary I/O fault outside `RETIRE_SET`, met at the same seam, so it is a full disk on the
    one verb that seam calls. It enters through `dataclasses.replace(cfg, state=...)`, the
    config seam, sharing the real handle's descriptor (the real handle must outlive it), and
    `full = False` is the obstruction removed, for the paired control on the same config."""

    _verb: str = ""
    full: bool = True

    @classmethod
    def over(cls, real: LearningState, verb: str) -> _StateWhoseDiskIsFull:
        self = cls.__new__(cls)
        self.__dict__.update(real.__dict__)
        self._real = real
        self._verb = verb
        return self

    def _maybe_full(self, verb: str) -> None:
        if self.full and verb == self._verb:
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    def deadletter(self, channel, entries):
        self._maybe_full("deadletter")
        super().deadletter(channel, entries)

    def disposition_report(self, channel, text):
        self._maybe_full("disposition_report")
        super().disposition_report(channel, text)


def _tick_meeting_an_appender_at_the_unkeyable_retirement(
    paths, ch, *, lock_wait: int = 1,
) -> BaseException | None:
    """One real `run_batch` whose unkeyable retirement — and only that — meets a held append
    lock. Returns whatever escaped the tick.

    The ordering is exact rather than probable: the appender acquires the lock in the
    foreground, from inside the drain's own call stack, in the window the retirement opens
    between releasing the lock and asking for it again (see
    `_QueueFileThatLetsAnAppenderIn`). By the time the rotation runs the lock is held, so its
    bounded wait is the only thing that can expire. `repo_lock_wait_seconds=lock_wait` is that
    deadline: 1 by default, as in `tests/test_drain719_hardening.py`; 0 (one try, as the drain
    takes it in `tests/test_952_consumption_follows_durability.py`) where the caller's subject
    is what the expiry leaves behind, not the wait.
    """
    appender = h.Holder(paths.state_root / ch.append_lock)

    def _an_appender_arrives() -> None:
        # Synchronous, and it must be: `Holder.__enter__` returns only once the appender
        # OWNS the lock, which is the whole guarantee. Nothing holds it at this point in the
        # tick, so it returns at once.
        appender.__enter__()

    real = LearningState.open(paths)
    cfg = h.cfg_for(
        paths, "findings", state=_StateThatLetsAnAppenderIn.over(real, _an_appender_arrives),
        repo_lock_wait_seconds=lock_wait,
        invoke_agent=h.recording(h.committing("881-o4")),
    )
    tick = h.Background(lambda: drain.run_batch(cfg=cfg))
    try:
        tick._thread.start()
        assert tick.finished_within(30), (
            "the tick never returned — the unkeyable retirement is waiting on the append "
            "lock with no deadline, holding the repo lock while it does"
        )
    finally:
        # CLEANUP ONLY. An assertion here replaces whatever diagnosis the block above was
        # about to raise, and — because it raises BEFORE the release — leaves a real `flock`
        # parked for `Holder`'s 60s wait and the drain worker unjoined, so the next call to
        # this helper on the same channel contends with the last one's corpse. Release
        # first so a tick still waiting on the lock can finish, then join it.
        appender.__exit__()
        tick.__exit__()
    assert appender.acquired is True, (
        "the appender never took the append lock, so the rotation was never contended "
        "and this tick proves nothing"
    )
    assert cfg.invoke_agent.calls == [], (  # type: ignore[attr-defined]
        "the tick reached the author; the fault under test is the one BEFORE the gate"
    )
    return tick.error


def _unkeyable(rid: str, **body) -> dict:
    """A well-formed findings row with its id field removed — the shape `_retire_unkeyable`
    exists for.

    `body` overrides ordinary content fields, which is how two such rows are made to differ
    in their BODY while sharing a `run_id`. Deriving the difference from `rid` instead would
    move `run_id` and `source_run_dir` too, and a fold keyed on the run would then be
    indistinguishable from one keyed on the row."""
    return {
        k: v for k, v in h.row_for("findings", rid, **body).items() if k != "finding_id"
    }


def test_881_a_contended_append_lock_in_the_unkeyable_retirement_leaves_a_stuck_record(
    tmp_path: Path,
):
    """#881/O4: the tick's THIRD fault-bearing region is inside the guard the other two are.

    The reproduction is the real one. An appender arrives in the window the retirement itself
    opens between releasing the append lock and asking for it again — an ordinary append, on
    the real lock, with the appender's own no-deadline discipline — and the retirement's
    rotation then expires against it. `TimeoutError` is
    deliberately outside `RETIRE_SET` (a busy lock is not the batch's fault), so nothing
    retires and the row stays queued; the stuck report is by construction the ONLY external
    trace such a tick can leave.

    Asserted: exactly ONE record, naming `TimeoutError`, with the graveyard holding exactly
    the one entry the retirement had already written before it reached the lock — so the
    fault is recorded once per tick, not once per row and not once per handler on the way
    out.

    THE PAIRED CONTROL is the second half: the same row, retired on an UNCONTENDED tick,
    completes and writes NO further stuck record. An implementation that recorded every
    unkeyable retirement would satisfy the first half and turn the stuck report into a log of
    ordinary bad data, which is the one thing it must not be.
    """
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    rows = [_unkeyable("a/0")]
    h.seed(paths, ch, rows)

    escaped = _tick_meeting_an_appender_at_the_unkeyable_retirement(paths, ch)

    assert isinstance(escaped, TimeoutError), f"the tick ended as {escaped!r}"
    assert str(paths.state_root / ch.append_lock) in str(escaped), (
        f"the timeout was not the append lock's: {escaped}"
    )
    assert h.pending(paths, ch) == rows, "the queue was rewritten by a rotation that never ran"
    assert len(h.graveyard(paths, ch)) == 1, (
        "the graveyard should hold the one row the retirement wrote before the rotation "
        f"expired, not {h.graveyard(paths, ch)}"
    )
    records = h.stuck_records(paths, ch)
    assert len(records) == 1, (
        "a fault the drain cannot retire escaped the tick with no operator signal: the row "
        "is queued, nothing was graveyarded, and the channel is silently wedged"
    )
    assert records[0]["fault_class"] == "TimeoutError", (
        "the record does not name the fault class, so a busy appender is indistinguishable "
        "from a broken one"
    )

    # The control: the same retirement, uncontended, is ordinary work and records nothing.
    # A FAKE AGENT even though this half cannot reach one: with an all-unkeyable batch
    # `to_author` is empty and `_author_and_rotate` short-circuits, so the default config's
    # REAL `invoke_agent` (the curator subagent stage) is unreached only by accident. A gate
    # that starts emitting a row here would turn a unit test into a live model call that
    # hangs to `author_timeout` and fails as a timeout rather than as its own assertion.
    uncontended = h.cfg_for(
        paths, "findings", repo_lock_wait_seconds=1,
        invoke_agent=h.recording(h.committing("881-o4-control")),
    )
    assert drain.run_batch(cfg=uncontended) == 0
    assert h.pending(paths, ch) == [], "the uncontended retirement did not clear the row"
    assert len(h.graveyard(paths, ch)) == 2, "the uncontended retirement did not graveyard the row"
    assert len(h.stuck_records(paths, ch)) == 1, (
        "an ordinary unkeyable retirement wrote a stuck record; the report then names every "
        "bad row rather than every wedged tick"
    )


def test_881_a_fault_before_the_rotation_in_the_unkeyable_retirement_is_recorded_too(
    tmp_path: Path,
):
    """#881/O4 at the retirement's OTHER seams — the demand is a GUARD ROUND THE STEP, not a
    clause round its last line.

    The retirement crosses several seams before it reaches the rotation: it derives the
    graveyard path, appends the retiring rows to it, and logs. A guard wrapped round the
    rotation alone — or one that names only `TimeoutError`, the class the sibling test
    injects — passes that test and leaves every earlier seam exactly as it was: the fault
    escapes `run_batch`, nothing is graveyarded, nothing is recorded, and the channel is
    wedged in silence. That is the shape this suite has shipped before (PR #678: a catch-all
    fault demand discharged at one seam and believed of the whole region).

    The fault is met at a real seam: the graveyard append, on the very file the retirement
    exists to write, answers `ENOSPC` (`_StateWhoseDiskIsFull`; before #1135 it was a folder
    planted at the graveyard path, which the handle now refuses as `StateRefused` and records
    nothing for, by design). `OSError` is not in `RETIRE_SET`, so nothing retires and the row
    stays queued.

    THE PAIRED CONTROL is the second half: with the obstruction removed the same retirement
    completes, graveyards its row and records nothing further — so the guard cannot be
    satisfied by recording every retirement, and the channel is shown to be recoverable
    rather than merely loud.
    """
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    rows = [_unkeyable("a/0")]
    h.seed(paths, ch, rows)
    full = _StateWhoseDiskIsFull.over(LearningState.open(paths), "deadletter")
    cfg = h.cfg_for(
        paths, "findings", repo_lock_wait_seconds=1, state=full,
        invoke_agent=h.recording(h.committing("881-o4-seams")),
    )

    with pytest.raises(OSError, match="No space left"):
        drain.run_batch(cfg=cfg)

    assert cfg.invoke_agent.calls == [], (  # type: ignore[attr-defined]
        "the tick reached the author; the fault under test is the one BEFORE the gate"
    )
    assert h.graveyard(paths, ch) == [], "nothing can have been graveyarded"
    assert h.pending(paths, ch) == rows, "the row must stay queued — `OSError` retires nothing"
    records = h.stuck_records(paths, ch)
    assert len(records) == 1, (
        "a fault the drain cannot retire escaped the tick with no operator signal, because "
        "the guard covers the rotation and not the whole retirement"
    )
    assert records[0]["fault_class"] == "OSError", (
        "the record does not name the fault class, or the guard names only the one class "
        f"the sibling test injects: {records[0]}"
    )
    assert records[0]["row_ids"], (
        "the record names no rows, so the guard was handed the wrong batch — the rows this "
        "tick is stuck on are the unkeyable ones"
    )

    # The paired control: unobstructed, the same retirement is ordinary work.
    full.full = False
    assert drain.run_batch(cfg=cfg) == 0
    assert h.pending(paths, ch) == [], "the retirement did not clear the row once unobstructed"
    assert len(h.graveyard(paths, ch)) == 1, "the retirement did not graveyard the row"
    assert len(h.stuck_records(paths, ch)) == 1, (
        "an ordinary unkeyable retirement wrote a stuck record; the report then names every "
        "bad row rather than every wedged tick"
    )


def test_881_stuck_unkeyable_ticks_fold_by_row_content_and_not_by_an_empty_id_list(
    tmp_path: Path,
):
    """#881/O4's counter: `consecutive_ticks` is what turns "this failed" into "this has been
    stuck for N ticks", and it folds on `(fault_class, row_ids)`.

    A keyless row has no id to contribute. So the two halves below are the same to a dedup key
    built from ids alone, and they must not be: the FIRST is one queue stuck across two ticks
    (fold — the count rises to 2), the SECOND is two unrelated ticks over different bad rows
    (do not fold — two records, each at 1). Folding them would report a channel that ate two
    different poison rows as one problem that has been going on for a while; splitting the
    first would reset the count on every tick and never let a stuck queue look stuck.

    THE TWO DIFFERENT ROWS SHARE A `run_id` AND DIFFER ONLY IN THEIR BODY. A row's other
    fields are the obvious place to reach for a stand-in id, and `run_id` is the nearest to
    hand — but one run yields many findings, so a key built on it folds two unrelated poison
    rows from the same run into one rising count: the exact misreading this test exists to
    prevent, wearing a different name. Only the row's own content tells them apart.

    Written as one test over two repos because neither half is an oracle alone — the pair is
    what discriminates a content fingerprint from an empty id list, or from any key coarser
    than the row.
    """
    same = h.make_paths(tmp_path / "same")
    same_ch = h.channel_of("findings")
    h.seed(same, same_ch, [_unkeyable("a/0")])
    for tick in (1, 2):
        escaped = _tick_meeting_an_appender_at_the_unkeyable_retirement(same, same_ch,
                                                                        lock_wait=0)
        assert isinstance(escaped, TimeoutError), f"tick {tick} ended as {escaped!r}"
    records = h.stuck_records(same, same_ch)
    assert [r["fault_class"] for r in records] == ["TimeoutError", "TimeoutError"]
    assert [r["consecutive_ticks"] for r in records] == [1, 2], (
        "the same unkeyable row stuck across two ticks did not fold, so a queue that has "
        f"been wedged for two ticks reads as two unrelated one-off faults: {records}"
    )

    different = h.make_paths(tmp_path / "different")
    diff_ch = h.channel_of("findings")
    poison = [
        _unkeyable("a/0", subject="the holding system was never re-queried"),
        _unkeyable("a/1", subject="the lead was closed on a stale enrichment"),
    ]
    assert {json.dumps(row.get("run_id")) for row in poison} == {'"a"'}, (
        "the two poison rows must share a run so that a run-keyed fold is distinguishable "
        "from a content-keyed one"
    )
    for row in poison:
        h.seed(different, diff_ch, [row])
        escaped = _tick_meeting_an_appender_at_the_unkeyable_retirement(different, diff_ch,
                                                                        lock_wait=0)
        assert isinstance(escaped, TimeoutError), f"{row['subject']!r} ended as {escaped!r}"
    records = h.stuck_records(different, diff_ch)
    assert [r["consecutive_ticks"] for r in records] == [1, 1], (
        "two ticks over DIFFERENT unkeyable rows from the SAME run folded into one rising "
        "count; a keyless row contributes no id, so neither an ids-only key nor one built "
        f"on the row's run can tell them apart — only its content can: {records}"
    )
    for record in records:
        assert record["row_ids"], (
            "a keyless row left the stuck record naming nothing at all, so the report "
            f"cannot say WHICH rows the channel is stuck on: {record}"
        )
    assert records[0]["row_ids"] != records[1]["row_ids"], (
        "two different bad rows are named identically in the stuck report"
    )


# ---------------------------------------------------------------------------------------
# O2's other half, in the drain — a tick does not return early on a queue it cannot parse
# ---------------------------------------------------------------------------------------


def test_881_a_queue_of_only_unreadable_lines_is_cleared_by_the_tick_it_wakes(tmp_path: Path):
    """#881/O2 at the drain end: `_tick` must NOT return on an empty batch while unreadable
    lines remain.

    The two halves of this contract live in two modules and only one of them was pinned.
    `core/drains._pending_queue_counts` counts an unreadable line as work — so the wake gate
    fires for a queue of nothing but junk — and the tick it wakes is the only thing that can
    clear it, because a line the tolerant reader could not turn into a row has no id, cannot
    be matched, and cannot be graveyarded. A tick that returned early on `not batch` would
    leave the junk counted and uncleared: the gate re-firing on the same bytes every pass,
    fetching, minting a worktree and starting a box to read them again, forever. That is
    #881/O2's own defect wearing the other mask, and restoring the early return is the
    obvious cleanup for anyone who reads "run a whole tick for no rows" as waste.

    THE PAIRED CONTROL is a genuinely empty queue on the same address: it returns without
    reaching the author, so "falls through" is a fact about the junk and not about `_tick`
    having stopped short-circuiting at all.

    The agent is asserted UNREACHED on both halves. There are no rows to author either way,
    and a fall-through that started handing the curator an empty batch would spend a real
    model call on nothing.
    """
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    (paths.state_root / ch.queue).parent.mkdir(parents=True, exist_ok=True)
    (paths.state_root / ch.queue).write_text('{not json at all\n[1,2]\nnull\n', encoding="utf-8")
    cfg = h.cfg_for(paths, "findings", invoke_agent=h.recording(h.committing("881-o2-junk")))

    assert drain.run_batch(cfg=cfg) == 0
    assert (paths.state_root / ch.queue).read_text(encoding="utf-8") == "", (
        "the tick returned on the empty batch and left the unreadable lines queued; the wake "
        "gate counts them as work, so it will fire on the same bytes on every pass forever"
    )
    assert cfg.invoke_agent.calls == [], (  # type: ignore[attr-defined]
        "the tick handed the curator a batch with no rows in it"
    )

    # The control: an empty queue is not the same as an unreadable one.
    empty = h.cfg_for(paths, "findings", invoke_agent=h.recording(h.committing("881-o2-empty")))
    assert drain.run_batch(cfg=empty) == 0
    assert empty.invoke_agent.calls == [], (  # type: ignore[attr-defined]
        "an empty queue reached the author"
    )


def test_881_unreadable_lines_beside_a_real_row_do_not_take_it_with_them(tmp_path: Path):
    """The mixed queue: the rotation that drops the junk rewrites the file from the rows it
    CAN read, so a well-formed row sharing the queue with a torn line must survive it.

    Without this the sibling above is satisfied by a tick that simply truncates the queue,
    which would delete every queued finding the moment one appender tore a line."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    keep = h.row_for("findings", "a/0")
    (paths.state_root / ch.queue).parent.mkdir(parents=True, exist_ok=True)
    (paths.state_root / ch.queue).write_text(json.dumps(keep) + "\n{torn\n", encoding="utf-8")
    cfg = h.cfg_for(paths, "findings", invoke_agent=h.recording(h.committing("881-o2-mixed")))

    assert drain.run_batch(cfg=cfg) == 0
    survivors = h.pending(paths, ch)
    assert [r["finding_id"] for r in survivors] == ["a/0"], (
        "the rotation that dropped the unreadable line took the readable row with it"
    )


def test_881_a_tick_whose_gate_held_the_whole_batch_names_those_rows_when_it_sticks(
    tmp_path: Path,
):
    """#881/O4's guard has to NAME the rows the phase in flight is stuck on, and the phase
    the wide guard covers last is not the authoring one.

    `_author_and_rotate` runs the closing rotation and the held-report write after the agent
    region, and on a tick the gate held whole there is no agent region at all — the rows in
    flight are the gate's holds, which that rotation is what writes back. Labelling the whole
    call with `to_author` names `[]` for exactly that tick: none of the stuck rows reported,
    and — because `_record_stuck` folds on `(fault_class, row_ids)` and an empty list is a
    foldable key — every such tick on every queue merging into one rising `consecutive_ticks`.
    An operator paging on "stuck for N ticks" would read one problem where there are several,
    and could not say which rows any of them is about.

    The fault is met at a real seam: the held report's append answers `ENOSPC`
    (`_StateWhoseDiskIsFull`; before #1135 it was a folder planted at the report's path, which
    the handle now refuses as `StateRefused` and records nothing for, by design) — `OSError` is
    not in `RETIRE_SET`, so nothing retires. It fires only because the gate held something, which is the same
    condition that empties `to_author`, so the two halves cannot be separated by the fixture.

    THE PAIRED CONTROL is the same tick unobstructed: it holds the same rows, writes its
    report, and records nothing — so the guard cannot be satisfied by naming rows on every
    tick that holds anything.
    """
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    held = [h.row_for("findings", f"a/{i}") for i in range(3)]
    h.seed(paths, ch, held)
    full = _StateWhoseDiskIsFull.over(LearningState.open(paths), "disposition_report")
    cfg = h.cfg_for(paths, "findings", state=full,
                    invoke_agent=h.recording(h.committing("881-o4-rotate")))
    held_report = paths.state_root / FINDINGS.report

    with pytest.raises(OSError, match="No space left"):
        drain.run_batch(cfg=cfg)

    assert cfg.invoke_agent.calls == [], (  # type: ignore[attr-defined]
        "the gate admitted a row, so this is not the held-whole tick the test is about"
    )
    records = h.stuck_records(paths, ch)
    assert len(records) == 1, f"the fault left no stuck record: {records}"
    assert sorted(records[0]["row_ids"]) == ["a/0", "a/1", "a/2"], (
        "the stuck record names none of the rows the tick is stuck on — the guard was "
        f"handed the authoring leg's empty batch instead of the rows in flight: {records[0]}"
    )

    # The control: unobstructed, the same tick holds the same rows and records nothing more.
    full.full = False
    assert drain.run_batch(cfg=cfg) == 0
    assert len(h.stuck_records(paths, ch)) == 1, (
        "an ordinary holding tick wrote a stuck record; the report then names every tick "
        "that declined a row rather than every wedged one"
    )
    assert held_report.is_file(), "the held report was not written once unobstructed"
