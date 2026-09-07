"""#881 — two pieces of the author drain's plumbing that lose a row in silence.

O3 — **every row the gate holds leaves a written trace in the findings held report.** The
report exists precisely so an operator can see what the drain declined to author, and it is
handed only the forward-check bucket's holds (`author/drain.py:395-403` fills
`DrainOutcome.held` from the AUTHOR_RESULT buckets). The PRE-AUTHOR gate's holds —
`no_ground_truth(...)` and `no_family_ground_truth(...)`, the ones that stay queued forever
because the fact they are waiting on has no writer any more — reach the queue and nothing else.

O4 — **a non-`RETIRE_SET` fault anywhere in a tick leaves exactly one stuck record naming the
fault class.** Two of the tick's three fault-bearing regions are wrapped
(`author/drain.py:292-296` for the gate, `:314-317` for authoring); the unkeyable-row
retirement at `:287` runs before both, so a `TimeoutError` out of its rotation escapes
`run_batch` with an empty stuck report. Retirement is not reachable for it either
(`TimeoutError` is not in `RETIRE_SET`), so there is no graveyard trace of the tick and no
stuck trace of it: the operator's only signal that the channel is wedged is that nothing
happens.

RED against `main` @ `b740b9ec`, which is what a spec written before its implementation looks
like. The two obligations whose homes the design names elsewhere — O1's fence-then-prose
regression (`tests/learning/test_loop.py`, `tests/test_921_judge_call.py`) and O2's wake-gate
accounting (`tests/test_orchestrate_thresholds.py`) — are not repeated here.

Project idioms, because CI ratchets them: fakes enter through `dataclasses.replace` on the
config, never `monkeypatch.setattr`; the fault under O4 is a REAL contended `flock`, not an
injected exception; every negative case is paired with its control on the same address.
"""
from __future__ import annotations

import dataclasses
import re
import threading
import time
from pathlib import Path

import _drain719 as h
from _drain719 import drain  # noqa: F401 — the target; the shim keeps collection alive

#: How long a summoned appender is given to reach its blocking `flock` call while the drain
#: holds the queue open. It is a grace period over a gap of microseconds — thread start plus
#: one `open()` — and it is spent while the drain is STOPPED inside its own batch read, so it
#: races nothing. Losing it would leave the tick to complete normally, which fails the test
#: loudly rather than greening it.
_APPENDER_REACHES_THE_LOCK = 0.3


def _held_report(paths) -> Path:
    """The lessons direction's operator report, spelled as `build_author_config` spells it."""
    return paths.pending_dir / "findings.held_report.log"


def _ids_in(line: str, label: str) -> str:
    """The contents of one `<label>=[...]` list on a held-report line, or `""` if absent."""
    found = re.search(rf"{label}=\[(.*?)\]", line)
    return found.group(1) if found else ""


# ---------------------------------------------------------------------------------------
# O3 — a row the pre-author gate holds is named in the held report
# ---------------------------------------------------------------------------------------


def test_881_a_row_the_pre_author_gate_holds_is_named_in_the_findings_held_report(tmp_path):
    """#881/O3, through the real `run_batch` on the real findings channel.

    An adversarial finding whose run has no resolvable `source_refs.yaml` is HELD by
    `_gate_findings` with `held_reason=no_ground_truth(...)`. It is a permanent hold — the
    writer of that file went with the #922 cutover — so it will sit in the queue on every
    tick from now on. The tick must say so once, in the one place an operator reads.

    THE PAIRED CONTROL IS THE SECOND HALF, on the same address under the complementary
    condition: the same row, once its ground truth exists, is authored and committed, and the
    report gains NOTHING. Without it a writer that appended a line every tick would pass the
    first half while making the report unreadable — which is the same as not having one.

    The id is also asserted NOT to be inside `forward_bad_ids=[...]` or `skipped_ids=[...]`.
    `DrainOutcome.held` is typed as the AUTHOR_RESULT bucket holds and the report already
    distinguishes its reasons by prefix, so folding the gate's holds into that bucket would
    report a row the forward check never saw as a forward-check verdict. What the label IS is
    the implementation's to choose; that it is not one of those two is the demand.
    """
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    row = h.row_for("findings", "a/0")
    h.seed(ch, [row])
    agent = h.recording(h.committing("881-o3"))
    cfg = h.cfg_for(paths, "findings", invoke_agent=agent)

    assert drain.run_batch(cfg=cfg) == 0
    assert agent.calls == [], "the held row was handed to the author anyway"
    assert [r.get("held_reason") for r in h.pending(ch)] == [
        "no_ground_truth(direction='adversarial', disposition=None)"
    ], "the tick did not hold the row this test is about"

    report = _held_report(paths)
    assert report.is_file(), (
        "the tick held a row and wrote no held report at all — the gate's holds are the "
        "permanent ones, and they are the ones with no written trace"
    )
    text = report.read_text(encoding="utf-8")
    assert "a/0" in text, f"the held row is not named in the report: {text!r}"
    for line in text.splitlines():
        assert "a/0" not in _ids_in(line, "forward_bad_ids"), (
            "a pre-author gate hold was reported as a forward-check verdict; the forward "
            f"check never saw this row: {line!r}"
        )
        assert "a/0" not in _ids_in(line, "skipped_ids"), (
            f"a held row was reported as a skip — a hold is not terminal: {line!r}"
        )

    # The control: the same row, now with ground truth, is authored — and holds nothing.
    before = text
    h.write_source_refs(paths, "a")
    assert drain.run_batch(cfg=cfg) == 0
    assert h.pending(ch) == [], "the row was not authored on the tick that could author it"
    assert report.read_text(encoding="utf-8") == before, (
        "a tick that held nothing appended to the held report anyway; a report that grows "
        "on every tick names nothing"
    )


# ---------------------------------------------------------------------------------------
# O4 — the unkeyable-row retirement is inside the stuck-recording guard
# ---------------------------------------------------------------------------------------


class _QueueFileThatLetsAnAppenderIn:
    """The queue file, plus one callback fired when the drain reads its batch.

    Delegates every path operation to the real `Path` and adds exactly one behaviour: the
    drain's batch read — the step that holds the channel's append lock — returns only after
    `on_read` has run. That is the seam this scenario needs and the code has no other: the
    unkeyable retirement runs BEFORE `cfg.gate` and `cfg.invoke_agent`, so the
    `commit_fn`-shaped hook `tests/test_drain719_hardening.py` uses to let an appender in
    mid-tick lands too late.

    Nothing about the contention is faked. The appender takes the real `flock` on the real
    lock path with the appender's own blocking discipline (`persist.queue_lock`, no
    deadline), and the `TimeoutError` under test is raised by the retire rotation's own
    bounded wait. What the hook decides is only WHEN the appender arrives — the same thing
    the hardening suite's `commit_then_appender_takes_the_lock` decides.

    It enters through `dataclasses.replace(cfg.channel, file=...)`, the config seam, not
    through `monkeypatch.setattr`."""

    def __init__(self, real: Path, on_read) -> None:
        self._real = real
        self._on_read = on_read
        self._fired = False

    def read_text(self, *args, **kwargs) -> str:
        text = self._real.read_text(*args, **kwargs)
        if not self._fired:
            self._fired = True
            self._on_read()
        return text

    def __fspath__(self) -> str:
        return str(self._real)

    def __str__(self) -> str:
        return str(self._real)

    def __getattr__(self, name):
        # Everything else — `is_file`, `parent`, `with_suffix` (which is how the graveyard
        # and stuck-report paths are derived) — is the real path's, and answers with real
        # `Path` objects.
        return getattr(object.__getattribute__(self, "_real"), name)


def _tick_meeting_an_appender_at_the_unkeyable_retirement(paths, ch) -> BaseException | None:
    """One real `run_batch` whose unkeyable retirement — and only that — meets a held append
    lock. Returns whatever escaped the tick.

    The ordering is the whole trick and it is deterministic: the appender is summoned while
    the drain is inside its batch read, so it queues as a KERNEL waiter behind the lock the
    drain is holding. `_flock.take` blocks outright with no deadline for an appender and
    polls under one for the drain, so on release the waiting appender takes the lock and the
    retire rotation's bounded wait is the one that expires. `repo_lock_wait_seconds=1` is the
    deadline, as in `tests/test_drain719_hardening.py`.
    """
    appender = h.Holder(ch.append_lock)

    def _an_appender_arrives() -> None:
        # `Holder.__enter__` blocks until it OWNS the lock, and the drain is holding it right
        # now — so it is started on its own thread and only given time to get as far as
        # asking. It acquires the moment the drain's read releases.
        threading.Thread(target=appender.__enter__, daemon=True).start()
        time.sleep(_APPENDER_REACHES_THE_LOCK)

    watched = dataclasses.replace(
        ch, file=_QueueFileThatLetsAnAppenderIn(ch.file, _an_appender_arrives)
    )
    cfg = h.cfg_for(
        paths, "findings", channel=watched, repo_lock_wait_seconds=1,
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
    assert cfg.invoke_agent.calls == [], (  # type: ignore[attr-defined]
        "the tick reached the author; the fault under test is the one BEFORE the gate"
    )
    return tick.error


def _unkeyable(rid: str) -> dict:
    """A well-formed findings row with its id field removed — the shape `_retire_unkeyable`
    exists for. `run_id` still differs per row, which is what gives two such rows different
    content without giving either one an id."""
    return {k: v for k, v in h.row_for("findings", rid).items() if k != "finding_id"}


def test_881_a_contended_append_lock_in_the_unkeyable_retirement_leaves_a_stuck_record(
    tmp_path: Path,
):
    """#881/O4: the tick's THIRD fault-bearing region is inside the guard the other two are.

    The reproduction is the real one. An appender arrives while the drain has the queue open
    — an ordinary append, on the real lock, with the appender's own no-deadline discipline —
    and the unkeyable retirement's rotation then expires against it. `TimeoutError` is
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
    ch = h.channel_of(paths, "findings")
    rows = [_unkeyable("a/0")]
    h.seed(ch, rows)

    escaped = _tick_meeting_an_appender_at_the_unkeyable_retirement(paths, ch)

    assert isinstance(escaped, TimeoutError), f"the tick ended as {escaped!r}"
    assert str(ch.append_lock) in str(escaped), (
        f"the timeout was not the append lock's: {escaped}"
    )
    assert h.pending(ch) == rows, "the queue was rewritten by a rotation that never ran"
    assert len(h.graveyard(ch)) == 1, (
        "the graveyard should hold the one row the retirement wrote before the rotation "
        f"expired, not {h.graveyard(ch)}"
    )
    records = h.stuck_records(ch)
    assert len(records) == 1, (
        "a fault the drain cannot retire escaped the tick with no operator signal: the row "
        "is queued, nothing was graveyarded, and the channel is silently wedged"
    )
    assert records[0]["fault_class"] == "TimeoutError", (
        "the record does not name the fault class, so a busy appender is indistinguishable "
        "from a broken one"
    )

    # The control: the same retirement, uncontended, is ordinary work and records nothing.
    uncontended = h.cfg_for(paths, "findings", repo_lock_wait_seconds=1)
    assert drain.run_batch(cfg=uncontended) == 0
    assert h.pending(ch) == [], "the uncontended retirement did not clear the row"
    assert len(h.graveyard(ch)) == 2, "the uncontended retirement did not graveyard the row"
    assert len(h.stuck_records(ch)) == 1, (
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

    Written as one test over two repos because neither half is an oracle alone — the pair is
    what discriminates a content fingerprint from an empty id list.
    """
    same = h.make_paths(tmp_path / "same")
    same_ch = h.channel_of(same, "findings")
    h.seed(same_ch, [_unkeyable("a/0")])
    for tick in (1, 2):
        escaped = _tick_meeting_an_appender_at_the_unkeyable_retirement(same, same_ch)
        assert isinstance(escaped, TimeoutError), f"tick {tick} ended as {escaped!r}"
    records = h.stuck_records(same_ch)
    assert [r["fault_class"] for r in records] == ["TimeoutError", "TimeoutError"]
    assert [r["consecutive_ticks"] for r in records] == [1, 2], (
        "the same unkeyable row stuck across two ticks did not fold, so a queue that has "
        f"been wedged for two ticks reads as two unrelated one-off faults: {records}"
    )

    different = h.make_paths(tmp_path / "different")
    diff_ch = h.channel_of(different, "findings")
    for rid in ("b/0", "c/0"):
        h.seed(diff_ch, [_unkeyable(rid)])
        escaped = _tick_meeting_an_appender_at_the_unkeyable_retirement(different, diff_ch)
        assert isinstance(escaped, TimeoutError), f"{rid} ended as {escaped!r}"
    records = h.stuck_records(diff_ch)
    assert [r["consecutive_ticks"] for r in records] == [1, 1], (
        "two ticks over DIFFERENT unkeyable rows folded into one rising count; a keyless "
        f"row contributes no id, so an ids-only key cannot tell them apart: {records}"
    )
    for record in records:
        assert record["row_ids"], (
            "a keyless row left the stuck record naming nothing at all, so the report "
            f"cannot say WHICH rows the channel is stuck on: {record}"
        )
    assert records[0]["row_ids"] != records[1]["row_ids"], (
        "two different bad rows are named identically in the stuck report"
    )
