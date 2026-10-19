"""#881 — two pieces of the author drain's plumbing that lost a row in silence."""
from __future__ import annotations

import errno
import json
import os
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from defender.tests.support.learning.curation import _drain719 as h
from defender.learning.core.state import FINDINGS, LearningState
from defender.tests.support.learning.curation._drain719 import drain  # noqa: F401 — the target; the shim keeps collection alive


def _ids_in(line: str, label: str) -> str:
    """The contents of one `<label>=[...]` list on a held-report line.

    A MISSING LABEL FAILS HERE rather than answering `""`. The two assertions this feeds are
    negative — a gate hold must appear in neither `deferred_ids` nor `skipped_ids` — so an
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


def test_881_a_row_the_pre_author_gate_holds_is_named_in_the_findings_held_report(tmp_path):
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    legacy = h.row_for("findings", "a/0", direction="adversarial")
    family = h.row_for("findings", "f/0", direction="family", judge_outcome="not-a-word")
    authorable = h.row_for("findings", "z/0")
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
        "a/0": "retired_direction('adversarial')",
        "f/0": "retired_name(judge_outcome)",
    }, "the tick did not hold the two rows this test is about"

    assert report.is_file(), (
        "the tick held two rows and wrote no held report at all — the gate's holds are the "
        "permanent ones, and they are the ones with no written trace"
    )
    first_tick = report.read_text(encoding="utf-8")
    for held_id, arm in (("a/0", "retired_direction"), ("f/0", "retired_name")):
        assert held_id in first_tick, (
            f"the row held on the {arm} arm is not named in the report, although the tick "
            f"committed a row alongside it: {first_tick!r}"
        )
        for line in first_tick.splitlines():
            assert held_id not in _ids_in(line, "deferred_ids"), (
                "a pre-author gate hold was reported as a deferral; the curator never saw "
                f"this row: {line!r}"
            )
            assert held_id not in _ids_in(line, "skipped_ids"), (
                f"a held row was reported as a skip — a hold is not terminal: {line!r}"
            )

    # A second HOLDING tick: the report is a ledger, so it grows by a line and keeps the one
    # it had. `"w"` instead of `"a"` fails here and nowhere else.
    h.seed(paths, ch, [h.row_for("findings", "b/0", direction="adversarial")])
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
    assert drain.run_batch(cfg=cfg) == 0
    assert h.pending(paths, ch) == [], "the row was not authored on the tick that could author it"
    assert report.read_text(encoding="utf-8") == second_tick, (
        "a tick that held nothing appended to the held report anyway; a report that grows "
        "on every tick names nothing"
    )


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
    deadline: 1 by default, as in `tests/learning/curation/test_drain719_hardening.py`; 0 (one try, as the drain
    takes it in `tests/learning/core/test_952_consumption_follows_durability.py`) where the caller's subject
    is what the expiry leaves behind, not the wait.
    """
    appender = h.Holder(paths.state_root / ch.append_lock)

    def _an_appender_arrives() -> None:
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


def test_881_a_queue_of_only_unreadable_lines_is_cleared_by_the_tick_it_wakes(tmp_path: Path):
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
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    keep = h.row_for("findings", "a/0", direction="adversarial")  # held, so it stays queued
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
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    held = [h.row_for("findings", f"a/{i}", direction="adversarial") for i in range(3)]
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
