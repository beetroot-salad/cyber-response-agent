"""#1025 O7 — the episode's stage timing record, written at the source.

One record at the episode root, `episodes/<id>/timing.jsonl`, appended by the launcher AFTER
each step completes: one row `{step, started_at, ended_at}` per step, in launch order —
`questioner`, `staging`, `review`, `runs`, `verify`, `judge`. The launcher (`cli._run_episode`,
and `cli._release_and_grade` for the judge's clock) is the only frame that sees every step
boundary, so it is the one writer; written after the step and never before, an aborted episode
leaves exactly the steps that ran, and a row the record refuses is printed and absent, never a
failure of the step it clocks. The timestamps are a clock's (`_clock.now_iso`), not file
mtimes — O4's named failing is a wall time reconstructed from timestamps on disk.

`learning/branch/steps.py` owns the step sequence (`Step`, `STEPS`) — the ONE declaration the
launcher's step frames, the record's writer and the page all read. `learning/branch/timing.py`
owns the row's shape (`record_step`) and the tolerant reader (`read_stage_timings`). All are
imported PER TEST through `T.mod`, so a module that does not exist yet is one failure per test
rather than a collection error.

THE CLOCK IS WHOLE-SECOND AND A FAKED EPISODE TAKES WELL UNDER ONE, so every row of a launch
usually carries one string, and a timestamp assertion that only compares rows to each other
holds for a writer that stamps a constant. Every launcher assertion about time here is therefore
BRACKETED by a real `now_iso()` taken before and after the launch, and one scenario holds a
seam open across a second boundary so `started_at < ended_at` is actually observable.
"""
from __future__ import annotations

import contextlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender._clock import now_iso, parse_iso_utc
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T

#: The six steps, in the order the launcher runs them — the names a reader of the record keys on.
EXPECTED_STEPS = ["questioner", "staging", "review", "runs", "verify", "judge"]


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Every configured root points inside `tmp_path` — the launcher's, the sibling runs base's
    and the learning state root the judge's enqueue appends to — so an episode this file drives
    lands in this test's own tree and never in the checkout's."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _cli():
    return T.mod("learning.branch.cli")


def _timing():
    return T.mod("learning.branch.timing")


def _steps_mod():
    return T.mod("learning.branch.steps")


def _steps(episode_dir) -> list[str]:
    """The step names on the record, in the order the READER returns them."""
    return [row["step"] for row in _timing().read_stage_timings(episode_dir)]


def _raw_rows(episode_dir) -> list[dict]:
    """The record's rows in FILE order, read without the reader — so an order assertion cannot
    be satisfied by a reader that sorts what a writer wrote out of order."""
    path = Path(episode_dir) / _timing().TIMING_NAME
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()  # noqa: E501 # lint-jsonl-io: ok — the raw file-order oracle: the reader under test IS `read_jsonl_rows`, which must not be its own oracle
            if line.strip()]


def _clocked(rows: list[dict], *, before: str, after: str) -> list[tuple[Any, Any]]:
    """Every row's `(started_at, ended_at)` as aware datetimes, each pair inside the real
    clock's `[before, after]` bracket, in order, and starting no earlier than the previous row
    ended — the launch's own wall time, not a constant, and not a value from any clock but
    the one bracketing it.

    THE NO-OVERLAP CHAIN IS CHECKED HERE, on every launch, and not only on the sub-second
    accepted one: there every stamp is the same whole second and the chain is vacuous, so a
    writer whose `started_at` is the LAUNCH's start rather than the step's own passed it —
    and passed the one launch that straddles a second boundary, which never asked. Asked on
    that launch, `verify` starting at the launch's first second while `runs` ended in the
    next is the overlap it exists to catch.
    """
    lo, hi = parse_iso_utc(before), parse_iso_utc(after)
    out = []
    previous_end = None
    for row in rows:
        started, ended = parse_iso_utc(row["started_at"]), parse_iso_utc(row["ended_at"])
        assert started is not None, f"{row['step']}: started_at={row['started_at']!r}"
        assert ended is not None, f"{row['step']}: ended_at={row['ended_at']!r}"
        assert lo <= started, f"{row['step']} started before the launch did"
        assert started <= ended, f"{row['step']} ended before it started"
        assert ended <= hi, f"{row['step']} ended after the launch returned"
        if previous_end is not None:
            assert started >= previous_end, f"{row['step']} started before its predecessor ended"
        previous_end = ended
        out.append((started, ended))
    return out


@dataclass
class Launch:
    rc: int
    spawn: Any
    judge: Any
    episode_dir: Path
    #: The real clock either side of `cli.main` — the bracket every recorded moment lies in.
    before: str
    after: str


def _launch(tmp_path, *, judge=None, spawn=None, capture=(), **seams) -> Launch:
    """Drive ONE whole episode through the real launcher, every fake entering by its seam.

    `capture` lands rows in the SOURCE run's queries table before the launch — the only way to
    give the review something to replay, since the launcher primes the episode from the source.
    """
    base, src = T.runs_base(tmp_path)
    for row in capture:
        T.capture_call(src, **row)
    episode_dir = _cli().episode_dir_for(T.EPISODE_ID)
    if spawn is None:
        spawn = J.FakeSibling(episode_dir)
    if judge is None:
        judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    seams.setdefault("door", T.FakeDoor())
    seams.setdefault("questioner",
                     T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c")))
    seams.setdefault("adapters", T.FakeAdapters())
    seams.setdefault("invoke", T.FakeAgent(*["same"] * 24))
    seams.setdefault("preflight", T.no_preflight)
    before = now_iso()
    rc = _cli().main([str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
                     spawn=spawn, judge=judge, **seams)
    return Launch(rc, spawn, judge, episode_dir, before, now_iso())


def _abort(tmp_path, raises: type[BaseException], **seams) -> tuple[Path, str, str]:
    """A launch expected to leave through `raises`; returns the episode dir and the clock
    bracket around the launch."""
    before = now_iso()
    with pytest.raises(raises):
        _launch(tmp_path, **seams)
    return _cli().episode_dir_for(T.EPISODE_ID), before, now_iso()


def _rejecting_seams() -> dict:
    """The seams under which the review REJECTS the family before any sibling starts.

    The recipe `test_947_contradicting_world_is_rejected_before_any_sibling_starts` executes:
    the source captured one identity answer naming `web-1`, world B patches that entity, and
    the blind comparator answers `contradiction` — one contradicting world ends the episode.
    """
    patched = T.world_doc("b", ov=T.overlay(
        patches={"identity": {"web-1": {"owner": "platform"}}}))
    return {
        "capture": [{"system": "identity", "verb": "get-user",
                     "payload": {"hits": [{"host": "web-1", "owner": "soc"}]}}],
        "questioner": T.FakeAgent(T.family_doc(worlds=[T.base_world(), patched]), patched),
        "invoke": T.FakeAgent(*["contradiction"] * 24),
    }


class _Interrupting:
    """A seam standing in for the operator's interrupt landing INSIDE the step that calls it.

    It records what the timing record held at the moment it was called — the observation from
    inside a later step that tells a row written at the boundary from one buffered and flushed
    on the way out — then raises.

    `KeyboardInterrupt` and not an `Exception`, because every boundary holds the latter:
    `start_family` files one arm's `Exception` as a non-zero exit and the family goes on to be
    archived, `_release_and_grade` holds whatever the judge raises, and the review's fault arms
    record a failed replay rather than aborting. An interrupt is the one thing that really ends
    a step mid-way at all six boundaries.
    """

    def __init__(self, episode_dir: Path) -> None:
        self.episode_dir = Path(episode_dir)
        self.calls = 0
        self.seen: list[list[str]] = []

    def __call__(self, *args: Any, **kw: Any) -> Any:
        self.calls += 1
        self.seen.append(_steps(self.episode_dir))
        raise KeyboardInterrupt


class _WatchingSibling(J.FakeSibling):
    """`FakeSibling` that also records what the timing record held when the sibling was spawned
    (from inside the `runs` step) and holds the step open across a real second boundary,
    stamping the clock while inside it."""

    def __init__(self, episode_dir: Path, *, hold: float = 0.0) -> None:
        super().__init__(episode_dir)
        self.hold = hold
        self.seen: list[list[str]] = []
        self.stamps: list[str] = []

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None,
                 **kw: Any) -> int:
        self.seen.append(_steps(self.episode_dir))
        if self.hold:
            time.sleep(self.hold)
        self.stamps.append(now_iso())
        return super().__call__(argv, env=env, **kw)


class _PlantingSibling(J.FakeSibling):
    """`FakeSibling` that leaves a symlink where the archive will copy world B's report — the
    real fault the archive's own screen refuses, so `verify_family` raises mid-step."""

    def __init__(self, episode_dir: Path, *, outside: Path) -> None:
        super().__init__(episode_dir)
        self.outside = outside

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None,
                 **kw: Any) -> int:
        rc = super().__call__(argv, env=env, **kw)
        world = self.episode_dir / "worlds" / "b"
        world.mkdir(parents=True, exist_ok=True)
        # N arms, released from one barrier, race to plant ONE link; the loser's
        # `FileExistsError` would otherwise leave `start_family` as a second, unintended fault
        # ("world b was never started") in a scenario whose only fault is the planted alias.
        with contextlib.suppress(FileExistsError):
            (world / "report.md").symlink_to(self.outside)
        return rc


# ---------------------------------------------------------------------------------------
# the record itself — `learning/branch/timing.py`
# ---------------------------------------------------------------------------------------


def test_1025_a_step_row_round_trips_through_the_record(tmp_path):
    """`record_step` appends one JSON row `{step, started_at, ended_at}` to `timing.jsonl` at
    the episode root and returns it; `read_stage_timings` hands back exactly what was written,
    in file order, and every timestamp parses through `parse_iso_utc`.

    The timestamps handed in are DISTINCT LITERALS and come back verbatim: a writer that
    stamps its own clock and ignores its arguments returns something else.

    Fails when the row's shape drifts (a key renamed, added or dropped), when the record lands
    under any other name, when a timestamp is not the one handed in, or when a reader and
    writer disagree about the row.
    """
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()
    assert timing.TIMING_NAME == "timing.jsonl"
    assert list(_steps_mod().STEPS) == EXPECTED_STEPS
    assert [s.value for s in _steps_mod().Step] == EXPECTED_STEPS, (
        "the enum's member order is not launch order, or STEPS is not derived from it")

    first = timing.record_step(episode_dir, "questioner",
                               started_at="2026-01-01T00:00:00+00:00",
                               ended_at="2026-01-01T00:00:05+00:00")
    second = timing.record_step(episode_dir, "staging",
                                started_at="2026-01-01T00:00:07+00:00",
                                ended_at="2026-01-01T00:01:30+00:00")

    assert first == {"step": "questioner", "started_at": "2026-01-01T00:00:00+00:00",
                     "ended_at": "2026-01-01T00:00:05+00:00"}
    assert second == {"step": "staging", "started_at": "2026-01-01T00:00:07+00:00",
                      "ended_at": "2026-01-01T00:01:30+00:00"}
    record = episode_dir / timing.TIMING_NAME
    assert record.is_file(), "the record is not at the episode root under TIMING_NAME"
    assert record.read_text(encoding="utf-8") == (
        json.dumps(first) + "\n" + json.dumps(second) + "\n"), (
        "the file does not hold one JSON row per recorded step, verbatim")
    assert timing.read_stage_timings(episode_dir) == [first, second]
    for row in (first, second):
        for key in ("started_at", "ended_at"):
            assert parse_iso_utc(row[key]) is not None, f"{key}={row[key]!r} is not a timestamp"


def test_1025_the_reader_returns_file_order_not_step_order(tmp_path):
    """The reader returns rows in FILE order — it does not sort them into `STEPS` order.

    A reader that sorts by step would make a launcher that writes `verify` before `runs`
    indistinguishable from one that writes at each boundary, which is the one property the
    record exists to show. Recorded `staging` then `questioner`, the reader answers
    `[staging, questioner]`.
    """
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()
    later = timing.record_step(episode_dir, "staging",
                               started_at="2026-01-01T00:00:07+00:00",
                               ended_at="2026-01-01T00:01:30+00:00")
    earlier = timing.record_step(episode_dir, "questioner",
                                 started_at="2026-01-01T00:00:00+00:00",
                                 ended_at="2026-01-01T00:00:05+00:00")

    assert timing.read_stage_timings(episode_dir) == [later, earlier], (
        "the reader reordered the rows")
    assert _raw_rows(episode_dir) == [later, earlier], "the writer reordered the rows"


def test_1025_an_absent_record_reads_as_no_rows(tmp_path):
    """An episode with no `timing.jsonl` reads as `[]` — an aborted-before-any-step episode is
    a legitimate state, not an error — and reading does not bring the file into existence.

    Positive control in the same test: once one step is recorded, the reader returns it.
    """
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()

    assert timing.read_stage_timings(episode_dir) == []
    assert not (episode_dir / timing.TIMING_NAME).exists(), "reading created the record"

    row = timing.record_step(episode_dir, "questioner", started_at=now_iso(), ended_at=now_iso())
    assert timing.read_stage_timings(episode_dir) == [row], "the control failed"


def test_1025_a_torn_line_is_skipped_and_the_good_rows_still_read(tmp_path):
    """A line the reader cannot parse — here a REAL torn write, half a JSON object and NO
    newline, what a process that died mid-append actually leaves — is skipped, and the rows
    on either side of it are still returned in order. The record is written after each step
    by a process that can be killed at any moment; a reader that raises on one torn line loses
    every step that did complete.

    The row written AFTER the fragment is the one that exercises the writer: appended straight
    onto a tail with no newline, it and the fragment become one unreadable line and the
    completed step is lost with the torn one. The writer closes the fragment's line first and
    leaves the fragment's own bytes exactly as they were.
    """
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()
    before = timing.record_step(episode_dir, "questioner",
                                started_at=now_iso(), ended_at=now_iso())
    record = episode_dir / timing.TIMING_NAME
    torn = json.dumps({"step": "staging", "started_at": now_iso(), "ended_at": now_iso()})
    fragment = torn[: len(torn) // 2]
    with record.open("a", encoding="utf-8") as fh:
        fh.write(fragment)
    after = timing.record_step(episode_dir, "review", started_at=now_iso(), ended_at=now_iso())

    assert timing.read_stage_timings(episode_dir) == [before, after], (
        "a torn line either raised or was returned as a row, or the row appended after it "
        "was lost with it")
    assert record.read_text(encoding="utf-8") == (
        json.dumps(before) + "\n" + fragment + "\n" + json.dumps(after) + "\n"), (
        "the fragment's bytes were changed, or the row after it was not put on its own line")


def test_1025_an_unknown_step_is_refused_and_nothing_is_written(tmp_path):
    """A step name outside `STEPS` is refused with a `ValueError` naming it, and the refusal
    writes nothing: an absent record stays absent, and an existing record's bytes are
    unchanged. The step names are what every reader of the record keys on, so a misspelt step
    is an unreadable row.

    Positive control: a name in `STEPS` is written.
    """
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()
    record = episode_dir / timing.TIMING_NAME

    with pytest.raises(ValueError, match="questionner"):
        timing.record_step(episode_dir, "questionner", started_at=now_iso(), ended_at=now_iso())
    assert not record.exists(), "a refused step brought the record into existence"

    good = timing.record_step(episode_dir, "questioner", started_at=now_iso(), ended_at=now_iso())
    bytes_before = record.read_bytes()
    with pytest.raises(ValueError, match="teardown"):
        timing.record_step(episode_dir, "teardown", started_at=now_iso(), ended_at=now_iso())
    assert record.read_bytes() == bytes_before, "a refused step still wrote to the record"
    assert timing.read_stage_timings(episode_dir) == [good], "the control failed"


def test_1025_an_aliased_or_non_plain_record_is_refused_not_written_through(tmp_path):
    """The record is appended through `_io.write_guarded`: an entry planted at
    `episodes/<id>/timing.jsonl` that is not a plain single-linked regular file is REFUSED
    rather than written through, and the file it aliases keeps its bytes.

    Three plants, each its own episode dir. A symlink and a HARD LINK (`st_nlink > 1`, which
    `O_NOFOLLOW` alone never stops) both raise the seam's own alias refusal — `OSError` carrying
    `write_guarded_alias is True`, which only `_io._mark_alias` sets, so a hand-rolled
    `is_symlink()` check in front of a bare `os.open` cannot satisfy this. A DIRECTORY at the
    name is refused by the same seam with the mark set `False`.

    Positive control: the same row lands at a plain path.
    """
    timing = _timing()
    outside = tmp_path / "outside.jsonl"
    outside.write_text("untouched\n", encoding="utf-8")
    original_links = os.stat(outside).st_nlink

    symlinked = tmp_path / "symlinked-episode"
    symlinked.mkdir()
    (symlinked / timing.TIMING_NAME).symlink_to(outside)
    with pytest.raises(OSError, match="aliased") as refusal:
        timing.record_step(symlinked, "questioner", started_at=now_iso(), ended_at=now_iso())
    assert refusal.value.write_guarded_alias is True, (
        "the symlink was refused by something other than the guarded write seam")
    assert (symlinked / timing.TIMING_NAME).is_symlink(), "the planted link was replaced"

    hardlinked = tmp_path / "hardlinked-episode"
    hardlinked.mkdir()
    os.link(outside, hardlinked / timing.TIMING_NAME)
    assert os.stat(outside).st_nlink == original_links + 1, "the control failed: no hard link"
    with pytest.raises(OSError, match="aliased") as refusal:
        timing.record_step(hardlinked, "questioner", started_at=now_iso(), ended_at=now_iso())
    assert refusal.value.write_guarded_alias is True, (
        "the hard link was not refused as an alias — a symlink check alone lets it through")

    squatted = tmp_path / "squatted-episode"
    squatted.mkdir()
    (squatted / timing.TIMING_NAME).mkdir()
    with pytest.raises(OSError, match="aliased") as refusal:
        timing.record_step(squatted, "questioner", started_at=now_iso(), ended_at=now_iso())
    assert refusal.value.write_guarded_alias is False, (
        "a directory at the record's name was not refused by the guarded write seam")

    assert outside.read_text(encoding="utf-8") == "untouched\n", (
        "the record was written THROUGH a planted entry")

    plain = tmp_path / "plain-episode"
    plain.mkdir()
    row = timing.record_step(plain, "questioner", started_at=now_iso(), ended_at=now_iso())
    assert timing.read_stage_timings(plain) == [row], "the control failed"


def test_1025_the_reader_does_not_follow_a_link_the_writer_refuses(tmp_path):
    """`read_stage_timings` takes the same `lstat` posture as the writer and as every other
    reader of the episode tree: a symlink planted at `episodes/<id>/timing.jsonl` reads as NO
    record — never as the rows of whatever it points at — and so does a directory squatting
    the name. The target holds a real, parseable row, so an answer of `[]` is the reader
    refusing the entry rather than finding nothing to parse.

    Positive control: the same row, at a plain path, is read.
    """
    timing = _timing()
    planted = tmp_path / "planted.jsonl"
    stray = {"step": "judge", "started_at": "2020-01-01T00:00:00+00:00",
             "ended_at": "2020-01-01T09:00:00+00:00"}
    planted.write_text(json.dumps(stray) + "\n", encoding="utf-8")

    symlinked = tmp_path / "symlinked-episode"
    symlinked.mkdir()
    (symlinked / timing.TIMING_NAME).symlink_to(planted)
    assert timing.read_stage_timings(symlinked) == [], (
        "the reader followed a planted link and returned another file's rows as this "
        "episode's clock")
    assert (symlinked / timing.TIMING_NAME).is_symlink(), "the planted link was replaced"

    squatted = tmp_path / "squatted-episode"
    squatted.mkdir()
    (squatted / timing.TIMING_NAME).mkdir()
    assert timing.read_stage_timings(squatted) == [], "a directory at the name read as rows"

    plain = tmp_path / "plain-episode"
    plain.mkdir()
    (plain / timing.TIMING_NAME).write_text(json.dumps(stray) + "\n", encoding="utf-8")
    assert timing.read_stage_timings(plain) == [stray], "the control failed"


# ---------------------------------------------------------------------------------------
# the launcher writes it — one row per completed step, through `cli.main`
# ---------------------------------------------------------------------------------------


def test_1025_an_accepted_episode_leaves_all_six_steps_in_launch_order(tmp_path):
    """A clean accepted episode leaves six rows in `STEPS` order — in the FILE, not merely as
    the reader returns them — each row's moments inside the real clock's bracket around the
    launch, `started_at <= ended_at`, and each step starting no earlier than the previous one
    ended. The rows are on disk from inside a LATER step: the sibling spawned during `runs`
    already sees `questioner`, `staging`, `review`, and the judge called during `judge` sees
    the five before it — a record buffered and flushed on the way out shows them nothing.

    Fails when a step is not recorded, when the file's rows are out of order, when a timestamp
    is not one `parse_iso_utc` accepts or lies outside the launch, when two steps' intervals
    overlap, or when the rows are not on disk until the launcher exits.
    """
    episode_dir = _cli().episode_dir_for(T.EPISODE_ID)
    sibling = _WatchingSibling(episode_dir)
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    seen_by_judge: list[list[str]] = []

    def watching_judge(prompt, **kw):
        seen_by_judge.append(_steps(episode_dir))
        return judge(prompt, **kw)

    launch = _launch(tmp_path, spawn=sibling, judge=watching_judge)
    assert launch.rc == 0, "the control failed: the accepted episode did not launch cleanly"
    assert T.review_doc(launch.episode_dir)["episode"]["outcome"] == "accepted", (
        "the control failed")

    rows = _raw_rows(launch.episode_dir)
    assert [row["step"] for row in rows] == EXPECTED_STEPS
    assert _steps(launch.episode_dir) == EXPECTED_STEPS
    assert list(_steps_mod().STEPS) == EXPECTED_STEPS

    _clocked(rows, before=launch.before, after=launch.after)

    assert sibling.seen, "the control failed: no sibling was spawned"
    assert all(seen == ["questioner", "staging", "review"] for seen in sibling.seen), (
        f"a sibling spawned during `runs` saw {sibling.seen} on the record — the rows are "
        "not on disk at the boundary")
    assert seen_by_judge, "the control failed: the judge was never called"
    assert seen_by_judge[0] == ["questioner", "staging", "review", "runs", "verify"], (
        f"the judge saw {seen_by_judge[0]} on the record — the rows are not on disk at the "
        "boundary")


def test_1025_the_runs_row_spans_the_time_the_siblings_were_actually_running(tmp_path):
    """`started_at` and `ended_at` are the boundary's own moments, not one stamp taken when the
    row is written: a sibling held open across a real second boundary stamps the clock while
    it runs, and the `runs` row has `started_at < stamp <= ended_at` — strictly, so a row whose
    two moments are one write-time stamp cannot satisfy it.

    The one scenario in this file that spends real wall time (about a second), because it is
    the only way a whole-second clock can tell the two apart.
    """
    episode_dir = _cli().episode_dir_for(T.EPISODE_ID)
    sibling = _WatchingSibling(episode_dir, hold=1.1)
    launch = _launch(tmp_path, spawn=sibling)
    assert launch.rc == 0, "the control failed: the accepted episode did not launch cleanly"
    assert sibling.stamps, "the control failed: no sibling was spawned"

    rows = _raw_rows(launch.episode_dir)
    # `_clocked`'s chain is what makes THIS launch tell a step's own start from the launch's:
    # `verify` must start no earlier than `runs` ended, which is one second later than a
    # `started_at` frozen at the launch's first moment.
    _clocked(rows, before=launch.before, after=launch.after)
    runs = next(row for row in rows if row["step"] == "runs")
    started, ended = parse_iso_utc(runs["started_at"]), parse_iso_utc(runs["ended_at"])
    for stamp in sibling.stamps:
        inside = parse_iso_utc(stamp)
        assert started < inside, "`runs` started after a sibling it started was already running"
        assert inside <= ended, "`runs` ended before a sibling it started had returned"
    assert started < ended, "the `runs` row does not span the second the siblings ran across"
    verify = next(row for row in rows if row["step"] == "verify")
    assert parse_iso_utc(verify["started_at"]) >= ended, (
        "`verify` started before `runs` ended — a `started_at` that is not the step's own")


def test_1025_a_rejected_episode_stops_the_record_at_the_review(tmp_path, monkeypatch):
    """An episode the review REJECTS leaves exactly `questioner`, `staging`, `review` — the
    launcher returns 1 before any sibling starts, so no `runs`, `verify` or `judge` row exists
    — and those three rows lie inside the launch's own clock bracket.

    Positive control under its own episodes root: the accepted episode does carry those three
    later rows, so the negative cannot pass on a launcher that never records them.
    """
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-accepted"))
    accepted = _launch(tmp_path)
    assert accepted.rc == 0, "the control failed: the accepted episode did not launch cleanly"

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-rejected"))
    rejected = _launch(tmp_path, **_rejecting_seams())
    assert rejected.rc == 1, "the rejecting drive did not reach the rejected exit"
    assert T.review_doc(rejected.episode_dir)["episode"]["decision"] == "rejected", (
        "the rejecting drive did not reject")
    assert rejected.spawn.launches == [], "a sibling started for a rejected episode"

    rows = _raw_rows(rejected.episode_dir)
    assert [row["step"] for row in rows] == ["questioner", "staging", "review"]
    _clocked(rows, before=rejected.before, after=rejected.after)
    assert _steps(accepted.episode_dir)[3:] == ["runs", "verify", "judge"], "the control failed"


def test_1025_an_aborted_episode_keeps_the_completed_steps_and_not_the_one_that_raised(
        tmp_path, monkeypatch):
    """An episode that aborts MID-STEP leaves the rows for the steps that completed and no row
    for the step that raised — at EVERY one of the six boundaries, the record is written after
    the step, never before. Each arm runs under its own episodes root, and each interrupting
    seam reports what the record held when it was called, so a row written before its step, or
    a record flushed only on the way out, is caught from inside the step as well as after it.

    The seam that ends each step, and the rows it must leave:
    `questioner` interrupted → `[]` (and the seam itself saw an empty record);
    the comparator (`invoke`) interrupted mid-review → `[questioner, staging]`;
    the process seam interrupted during `runs` → `[questioner, staging, review]`;
    the archive refusing a planted alias during `verify` → the four before it;
    the judge seam interrupted → the five before it, no `judge`.
    Plus one `Exception`-class real fault: the staging door dying on its first staging write
    (`raise_after=2`: the preflight probe and the sweep take the first two connections) →
    `[questioner]`. Every arm but the judge's leaves through `LauncherRefused`; the judge's
    interrupt lands after the cluster is handed back, which `_launch` re-raises unchanged.
    """
    cli = _cli()

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-questioner"))
    questioner = _Interrupting(cli.episode_dir_for(T.EPISODE_ID))
    ep, _before, _after = _abort(tmp_path, cli.LauncherRefused, questioner=questioner)
    assert questioner.calls > 0, "the control failed: the questioner seam was never reached"
    assert questioner.seen == [[]], f"the questioner saw {questioner.seen} before it ran"
    assert _raw_rows(ep) == [], "a step that raised was recorded"

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-review"))
    comparator = _Interrupting(cli.episode_dir_for(T.EPISODE_ID))
    seams = _rejecting_seams()
    seams["invoke"] = comparator
    ep, before, after = _abort(tmp_path, cli.LauncherRefused, **seams)
    assert comparator.calls > 0, "the control failed: the comparator seam was never reached"
    assert comparator.seen == [["questioner", "staging"]], (
        f"the comparator saw {comparator.seen} mid-review")
    assert [row["step"] for row in _raw_rows(ep)] == ["questioner", "staging"]
    _clocked(_raw_rows(ep), before=before, after=after)

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-runs"))
    family = _Interrupting(cli.episode_dir_for(T.EPISODE_ID))
    ep, before, after = _abort(tmp_path, cli.LauncherRefused, spawn=family)
    assert family.calls > 0, "the control failed: the process seam was never reached"
    assert all(seen == ["questioner", "staging", "review"] for seen in family.seen), (
        f"a sibling saw {family.seen} on the record when spawned")
    assert [row["step"] for row in _raw_rows(ep)] == ["questioner", "staging", "review"], (
        "the record does not stop at the last step that completed")
    _clocked(_raw_rows(ep), before=before, after=after)

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-verify"))
    outside = tmp_path / "outside-verify.md"
    outside.write_text("untouched\n", encoding="utf-8")
    planting = _PlantingSibling(cli.episode_dir_for(T.EPISODE_ID), outside=outside)
    ep, before, after = _abort(tmp_path, cli.LauncherRefused, spawn=planting)
    assert planting.launches, "the control failed: no sibling was spawned"
    assert outside.read_text(encoding="utf-8") == "untouched\n", (
        "the control failed: the archive wrote through the planted alias")
    assert [row["step"] for row in _raw_rows(ep)] == ["questioner", "staging", "review", "runs"], (
        "a `verify` that raised was recorded, or a step before it was not")
    _clocked(_raw_rows(ep), before=before, after=after)

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-judge"))
    judge = _Interrupting(cli.episode_dir_for(T.EPISODE_ID))
    ep, before, after = _abort(tmp_path, KeyboardInterrupt, judge=judge)
    assert judge.calls > 0, "the control failed: the judge seam was never reached"
    assert judge.seen == [["questioner", "staging", "review", "runs", "verify"]], (
        f"the judge saw {judge.seen} when called")
    assert [row["step"] for row in _raw_rows(ep)] == EXPECTED_STEPS[:5], (
        "a `judge` that raised was recorded")
    _clocked(_raw_rows(ep), before=before, after=after)

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-staging"))
    dying_door = T.FakeDoor(fault=T.Fault(raise_after=2))
    author = T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c"))
    ep, before, after = _abort(tmp_path, cli.LauncherRefused, door=dying_door, questioner=author)
    assert author.calls > 0, "the control failed: the questioner step never ran"
    assert any(call.op == "create_index" for call in dying_door.calls), (
        "the control failed: the door died before staging began")
    assert [row["step"] for row in _raw_rows(ep)] == ["questioner"], (
        "a step that raised was recorded, or the one before it was not")
    _clocked(_raw_rows(ep), before=before, after=after)


def test_1025_a_failed_judge_still_leaves_the_judge_row(tmp_path, monkeypatch, capsys):
    """A judge failure is non-fatal to the episode — `_release_and_grade` holds it and the
    launcher returns — so the boundary is crossed and the `judge` row is on the record with the
    five before it, inside the launch's clock bracket.

    Two failures, each under its own episodes root. The grade itself fails: the learning state
    root the enqueue appends to is a regular FILE, so the family grade cannot land and
    `grade_episode` raises into `_release_and_grade`'s catch (control: the launcher reports
    "the judge pass failed" and writes no `judge.yaml`). The seam fails: the judge's model call
    raises on every draw, which the grade holds per draw (control: the seam was reached).
    """
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-grade-failed"))
    blocker = tmp_path / "learning-state-as-a-file"
    blocker.write_text("not a directory\n", encoding="utf-8")
    monkeypatch.setenv(J.STATE_DIR_ENV, str(blocker))
    launch = _launch(tmp_path)
    assert launch.rc == 0, "a failed grade ended the episode instead of being held"
    assert launch.judge.calls > 0, "the control failed: the judge seam was never reached"
    assert "the judge pass failed" in capsys.readouterr().err, (
        "the control failed: the grade did not fail")
    assert not (launch.episode_dir / "judge.yaml").exists(), (
        "the control failed: a family grade was written")
    rows = _raw_rows(launch.episode_dir)
    assert [row["step"] for row in rows] == EXPECTED_STEPS, "a held judge failure lost a row"
    _clocked(rows, before=launch.before, after=launch.after)

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-seam-failed"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))
    launch = _launch(tmp_path, judge=J.FakeJudge(fault=J.Fault(raise_after=0)))
    assert launch.rc == 0, "a raising judge seam ended the episode"
    assert launch.judge.calls > 0, "the control failed: the judge seam was never reached"
    rows = _raw_rows(launch.episode_dir)
    assert [row["step"] for row in rows] == EXPECTED_STEPS, "a raising judge seam lost a row"
    _clocked(rows, before=launch.before, after=launch.after)


class _StickyDoor(T.FakeDoor):
    """`FakeDoor` whose deletes are accepted and do nothing — every staged name is "still
    present after delete", so teardown reports a failure for each and raises."""

    def delete(self, name: str) -> None:
        self._gate("delete", name, {})


def test_1025_a_held_teardown_failure_still_leaves_the_judge_row(tmp_path):
    """A teardown that cannot verify a staged name gone is HELD by `_release_and_grade`, the
    grade runs to completion, and only then is the failure raised. The judge step therefore
    completed — `judge.yaml` certifies it — and its row is on the record with the five before
    it, even though the launch itself leaves through the held refusal.

    Drawn around the whole of `_release_and_grade`, the `judge` clock saw that deferred
    re-raise as the judge step raising and wrote nothing: a graded episode whose record said
    the judge never finished. The clock is drawn around the grade alone.

    Controls: the judge seam was reached, `judge.yaml` exists, and the launch leaves through
    `LauncherRefused` naming the teardown.
    """
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    with pytest.raises(_cli().LauncherRefused, match="teardown did not verify"):
        _launch(tmp_path, door=_StickyDoor(), judge=judge)
    episode_dir = _cli().episode_dir_for(T.EPISODE_ID)
    assert judge.calls > 0, "the control failed: the judge seam was never reached"
    assert (episode_dir / "judge.yaml").exists(), "the control failed: the grade did not land"
    rows = _raw_rows(episode_dir)
    assert [row["step"] for row in rows] == EXPECTED_STEPS, (
        "a judge step that ran to completion has no row because the held teardown failure "
        "was raised through its clock")


def test_1025_a_record_that_cannot_be_written_does_not_end_the_episode(tmp_path, capsys):
    """A timing row the record cannot take — here a DIRECTORY squatting `timing.jsonl` before
    the launch, so every append is refused by the guarded seam — is printed and absent, and
    the episode is otherwise untouched: it runs to completion, every world is archived, the
    judge is called and grades, and the launch returns 0. The record is observability; an
    append that could refuse used to end the episode from inside whichever step had just
    finished — after `runs`, as "no sibling started" with the family never archived; after
    the judge, as a bare `OSError` out of `main` for a fully graded episode.

    Six refusals, one per step, each named on stderr; the reader answers no rows for the
    squatted name rather than raising.
    """
    episode_dir = _cli().episode_dir_for(T.EPISODE_ID)
    episode_dir.mkdir(parents=True)
    (episode_dir / _timing().TIMING_NAME).mkdir()

    launch = _launch(tmp_path)
    assert launch.rc == 0, "a refused timing append ended the episode"
    assert T.review_doc(launch.episode_dir)["episode"]["outcome"] == "accepted", (
        "the family was not archived after the refused append")
    assert launch.judge.calls > 0, "the judge was never reached after the refused append"
    assert (launch.episode_dir / "judge.yaml").exists(), "the grade did not land"
    err = capsys.readouterr().err
    for step in EXPECTED_STEPS:
        assert f"the {step} row could not be written" in err, (
            f"the refused {step} row was not reported")
    assert _steps(launch.episode_dir) == [], "a squatted record read as rows"
