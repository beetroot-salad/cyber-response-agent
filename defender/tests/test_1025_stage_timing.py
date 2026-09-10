"""#1025 O7 — the episode's stage timing record, written at the source.

One record at the episode root, `episodes/<id>/timing.jsonl`, appended by the launcher AFTER
each step completes: one row `{step, started_at, ended_at}` per step, in launch order —
`questioner`, `staging`, `review`, `runs`, `verify`, `judge`. The launcher (`cli._run_episode`)
is the only frame that sees every step boundary, so it is the one writer; written after the
step and never before, an aborted episode leaves exactly the steps that ran. The timestamps are
a clock's (`_clock.now_iso`), not file mtimes — O4's named failing is a wall time reconstructed
from timestamps on disk.

`learning/branch/timing.py` owns the row's shape (`record_step`) and the tolerant reader
(`read_stage_timings`). Both are imported PER TEST through `T.mod`, so a module that does not
exist yet is one failure per test rather than a collection error.
"""
from __future__ import annotations

import json

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


def _steps(episode_dir) -> list[str]:
    """The step names on the record, in file order."""
    return [row["step"] for row in _timing().read_stage_timings(episode_dir)]


def _launch(tmp_path, *, judge=None, spawn=None, capture=(), **seams):
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
    rc = _cli().main([str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
                     spawn=spawn, judge=judge, **seams)
    return rc, spawn, judge, episode_dir


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


# ---------------------------------------------------------------------------------------
# the record itself — `learning/branch/timing.py`
# ---------------------------------------------------------------------------------------


def test_1025_a_step_row_round_trips_through_the_record(tmp_path):
    """`record_step` appends one JSON row `{step, started_at, ended_at}` to `timing.jsonl` at
    the episode root and returns it; `read_stage_timings` hands back exactly what was written,
    in file order, and every timestamp parses through `parse_iso_utc`.

    Fails when the row's shape drifts (a key renamed, added or dropped), when the record lands
    under any other name, or when a reader and writer disagree about the row.
    """
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()
    assert timing.TIMING_NAME == "timing.jsonl"
    assert list(timing.STEPS) == EXPECTED_STEPS

    first_start, first_end = now_iso(), now_iso()
    first = timing.record_step(episode_dir, "questioner",
                               started_at=first_start, ended_at=first_end)
    second_start, second_end = now_iso(), now_iso()
    second = timing.record_step(episode_dir, "staging",
                                started_at=second_start, ended_at=second_end)

    assert first == {"step": "questioner", "started_at": first_start, "ended_at": first_end}
    assert second == {"step": "staging", "started_at": second_start, "ended_at": second_end}
    record = episode_dir / timing.TIMING_NAME
    assert record.is_file(), "the record is not at the episode root under TIMING_NAME"
    lines = record.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in lines] == [first, second], (
        "the file does not hold one JSON row per recorded step")
    assert timing.read_stage_timings(episode_dir) == [first, second]
    for row in (first, second):
        for key in ("started_at", "ended_at"):
            assert parse_iso_utc(row[key]) is not None, f"{key}={row[key]!r} is not a timestamp"


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
    """A line the reader cannot parse — here a REAL torn write, half a JSON object left by a
    process that died mid-append — is skipped, and the rows on either side of it are still
    returned in order. The record is written after each step by a process that can be killed
    at any moment; a reader that raises on one torn line loses every step that did complete.
    """
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()
    before = timing.record_step(episode_dir, "questioner",
                                started_at=now_iso(), ended_at=now_iso())
    record = episode_dir / timing.TIMING_NAME
    torn = json.dumps({"step": "staging", "started_at": now_iso(), "ended_at": now_iso()})
    with record.open("a", encoding="utf-8") as fh:
        fh.write(torn[: len(torn) // 2] + "\n")
    after = timing.record_step(episode_dir, "review", started_at=now_iso(), ended_at=now_iso())

    assert timing.read_stage_timings(episode_dir) == [before, after], (
        "a torn line either raised or was returned as a row")


def test_1025_an_unknown_step_is_refused_and_nothing_is_written(tmp_path):
    """A step name outside `STEPS` is refused with a `ValueError` naming it, and the refusal
    writes nothing:
    an absent record stays absent, and an existing record's bytes are unchanged. The step names
    are what every reader of the record keys on, so a misspelt step is an unreadable row.

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


def test_1025_a_symlink_planted_at_the_record_is_refused_not_written_through(tmp_path):
    """The record is appended through the guarded write seam: a symlink planted at
    `episodes/<id>/timing.jsonl` is REFUSED — `_io`'s own aliased-entry `OSError` — rather
    than followed, and the file it points at keeps its bytes. A bare `open(..., "a")` writes
    through the link.

    Positive control: the same row lands at a plain path.
    """
    timing = _timing()
    outside = tmp_path / "outside.jsonl"
    outside.write_text("untouched\n", encoding="utf-8")
    aliased = tmp_path / "aliased-episode"
    aliased.mkdir()
    (aliased / timing.TIMING_NAME).symlink_to(outside)

    with pytest.raises(OSError, match="aliased"):
        timing.record_step(aliased, "questioner", started_at=now_iso(), ended_at=now_iso())
    assert outside.read_text(encoding="utf-8") == "untouched\n", (
        "the record was written THROUGH the planted symlink")
    assert (aliased / timing.TIMING_NAME).is_symlink(), "the planted link was replaced"

    plain = tmp_path / "plain-episode"
    plain.mkdir()
    row = timing.record_step(plain, "questioner", started_at=now_iso(), ended_at=now_iso())
    assert timing.read_stage_timings(plain) == [row], "the control failed"


# ---------------------------------------------------------------------------------------
# the launcher writes it — one row per completed step, through `cli.main`
# ---------------------------------------------------------------------------------------


def test_1025_an_accepted_episode_leaves_all_six_steps_in_launch_order(tmp_path):
    """A clean accepted episode leaves six rows in `STEPS` order, each with a parseable
    `started_at <= ended_at`, and each step starting no earlier than the previous one ended —
    the outer clock over the whole episode, read from the record and not reconstructed.

    Fails when a step is not recorded, when the rows are out of order, when a timestamp is not
    one `parse_iso_utc` accepts, or when two steps' intervals overlap.
    """
    rc, _spawn, _judge, ep = _launch(tmp_path)
    assert rc == 0, "the control failed: the accepted episode did not launch cleanly"
    assert T.review_doc(ep)["episode"]["outcome"] == "accepted", "the control failed"

    rows = _timing().read_stage_timings(ep)
    assert [row["step"] for row in rows] == EXPECTED_STEPS
    assert list(_timing().STEPS) == EXPECTED_STEPS

    previous_end = None
    for row in rows:
        started, ended = parse_iso_utc(row["started_at"]), parse_iso_utc(row["ended_at"])
        assert started is not None, f"{row['step']}: started_at={row['started_at']!r}"
        assert ended is not None, f"{row['step']}: ended_at={row['ended_at']!r}"
        assert started <= ended, f"{row['step']} ended before it started"
        if previous_end is not None:
            assert started >= previous_end, f"{row['step']} started before its predecessor ended"
        previous_end = ended


def test_1025_a_rejected_episode_stops_the_record_at_the_review(tmp_path, monkeypatch):
    """An episode the review REJECTS leaves exactly `questioner`, `staging`, `review` — the
    launcher returns 1 before any sibling starts, so no `runs`, `verify` or `judge` row exists.

    Positive control under its own episodes root: the accepted episode does carry those three
    later rows, so the negative cannot pass on a launcher that never records them.
    """
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-accepted"))
    rc, _spawn, _judge, accepted = _launch(tmp_path)
    assert rc == 0, "the control failed: the accepted episode did not launch cleanly"

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-rejected"))
    rc, spawn, _judge, rejected = _launch(tmp_path, **_rejecting_seams())
    assert rc == 1, "the rejecting drive did not reach the rejected exit"
    assert T.review_doc(rejected)["episode"]["decision"] == "rejected", (
        "the rejecting drive did not reject")
    assert spawn.launches == [], "a sibling started for a rejected episode"

    assert _steps(rejected) == ["questioner", "staging", "review"]
    assert _steps(accepted)[3:] == ["runs", "verify", "judge"], "the control failed"


class _InterruptedFamily:
    """`spawn=` standing in for the operator's interrupt landing while the siblings run.

    Not an `Exception`: `start_family` files one arm's `Exception` as a non-zero exit and the
    family goes on to be archived, which is a COMPLETED `runs` step. A `KeyboardInterrupt` is
    the one thing that really ends the step mid-way — it leaves through `_launch`'s abort arm.
    """

    def __init__(self) -> None:
        self.launches = 0

    def __call__(self, argv, *, env=None, **kw):
        self.launches += 1
        raise KeyboardInterrupt


def test_1025_an_aborted_episode_keeps_the_completed_steps_and_not_the_one_that_raised(
        tmp_path, monkeypatch):
    """An episode that aborts MID-STEP leaves the rows for the steps that completed and no row
    for the step that raised — the record is written after the step, never before.

    Two boundaries, each under its own episodes root. The process seam interrupts the family
    during `runs`: `questioner`, `staging`, `review` are on the record and `runs` is not. The
    staging door dies on its first staging write (`raise_after=2`: the preflight probe and the
    sweep take the first two connections): `questioner` is on the record and `staging` is not.
    Both leave through `LauncherRefused`, which is the abort arm's exit.
    """
    cli = _cli()

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-runs-aborted"))
    interrupted = _InterruptedFamily()
    with pytest.raises(cli.LauncherRefused):
        _launch(tmp_path, spawn=interrupted)
    assert interrupted.launches > 0, "the control failed: the process seam was never reached"
    assert _steps(cli.episode_dir_for(T.EPISODE_ID)) == ["questioner", "staging", "review"], (
        "the record does not stop at the last step that completed")

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-staging-aborted"))
    dying_door = T.FakeDoor(fault=T.Fault(raise_after=2))
    questioner = T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c"))
    with pytest.raises(cli.LauncherRefused):
        _launch(tmp_path, door=dying_door, questioner=questioner)
    assert questioner.calls > 0, "the control failed: the questioner step never ran"
    assert any(call.op == "create_index" for call in dying_door.calls), (
        "the control failed: the door died before staging began")
    assert _steps(cli.episode_dir_for(T.EPISODE_ID)) == ["questioner"], (
        "a step that raised was recorded, or the one before it was not")


def test_1025_a_failed_judge_still_leaves_the_judge_row(tmp_path, monkeypatch, capsys):
    """A judge failure is non-fatal to the episode — `_release_and_grade` holds it and the
    launcher returns — so the boundary is crossed and the `judge` row is on the record with the
    five before it.

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
    rc, _spawn, judge, ep = _launch(tmp_path)
    assert rc in (0, 1), "a failed grade ended the episode instead of being held"
    assert judge.calls > 0, "the control failed: the judge seam was never reached"
    assert "the judge pass failed" in capsys.readouterr().err, (
        "the control failed: the grade did not fail")
    assert not (ep / "judge.yaml").exists(), "the control failed: a family grade was written"
    assert _steps(ep) == EXPECTED_STEPS, "a held judge failure lost the judge row"

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-seam-failed"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))
    raising = J.FakeJudge(fault=J.Fault(raise_after=0))
    rc, _spawn, judge, ep = _launch(tmp_path, judge=raising)
    assert rc in (0, 1), "a raising judge seam ended the episode"
    assert judge.calls > 0, "the control failed: the judge seam was never reached"
    assert _steps(ep) == EXPECTED_STEPS, "a raising judge seam lost the judge row"
