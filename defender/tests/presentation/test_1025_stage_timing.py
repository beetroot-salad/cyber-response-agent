"""#1025 O7 — the episode's stage timing record, written at the source."""
from __future__ import annotations

import contextlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.episodes._episode_handle import Episode
from defender.episodes._episode_paths import LAYOUT, EpisodePaths

from defender._clock import now_iso, parse_iso_utc
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135
from defender.tests.learning.oracle.live_contracts import _spec1224 as S

#: The five steps, in the order the launcher runs them — the names a reader of the record keys on.
EXPECTED_STEPS = ["questioner", "preflight", "runs", "verify", "judge"]


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Every configured root points inside `tmp_path` — the launcher's, the sibling runs base's
    and the learning state root the judge's enqueue appends to — so an episode this file drives
    lands in this test's own tree and never in the checkout's."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    # #1187 (O9): the episodes variable is read by nothing; every launch's episode is
    # `<data root>/<T>/episodes/<uuid>` (`_NextEpisode`). The per-arm settings below are inert.
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _cli():
    return T.mod("learning.branch.cli")


def _tenant_paths():
    """#1078: the tenant `T.runs_base` (or `d9_tenant`) already created."""
    return T.current_tenant()


def _episodes_now() -> set[Path]:
    """Every episode under any tenant of this test's data root — `<data root>/<T>/episodes/*`,
    where #1187 (Layout A, O9) puts every launch's episode."""
    return set(Path(os.environ["DEFENDER_DATA_ROOT"]).glob("*/episodes/*"))


class _NextEpisode:
    """The episode the NEXT launch makes. #1187: the launcher mints the episode's id (a fresh
    uuid4), so no test can compose its folder in advance; this is the one folder that appears
    under `<data root>/<T>/episodes/` after it was made — resolved when it is asked for (a seam
    called mid-launch asks after the launcher made it)."""

    def __init__(self) -> None:
        self.before = _episodes_now()

    @property
    def dir(self) -> Path:
        made = sorted(_episodes_now() - self.before)
        assert len(made) == 1, f"expected the launch's one new episode under <T>/episodes: {made}"
        return made[0]


def _timing():
    return T.mod("learning.branch.timing")


def _steps_mod():
    return T.mod("learning.branch.steps")


def _read(episode_dir) -> list[dict] | None:
    """`read_stage_timings` over the episode dir's bound reader — the reader takes the bound
    primitive, never a root it could format (#1049 D-V2), so the bind is made here."""
    return _timing().read_stage_timings(T.mod("_io").bind(episode_dir))


def _steps(episode_dir) -> list[str]:
    """The step names on the record, in the order the READER returns them."""
    return [row["step"] for row in _read(episode_dir) or []]


def _raw_rows(episode_dir) -> list[dict]:
    """The record's entries in DOCUMENT order, read without the reader — so an order assertion
    cannot be satisfied by a reader that sorts what a writer wrote out of order — and parsed
    strictly: a document that is not whole is a failure here, not a skipped line."""
    path = EpisodePaths(episode_dir).timing
    if not path.is_file():
        return []
    return json.loads(path.read_text(encoding="utf-8"))["steps"]


def _open(episode_dir: Path) -> Episode:
    """Open (and deliberately never close) an `Episode` handle for a `StageClock` under test."""
    return Episode.open(episode_dir).__enter__()


def _clock(episode_dir):
    return _timing().StageClock(_open(episode_dir))


def _clocked(rows: list[dict], *, before: str, after: str) -> list[tuple[Any, Any]]:
    """Every row's `(started_at, ended_at)` as aware datetimes, each pair inside the real clock's
    `[before, after]` bracket, in order, and starting no earlier than the previous row ended ."""
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


#: The one answer every captured call recorded and the live estate gives, so an oracle serving
#: it unchanged calibrates every world (no drift, no change to a pre-branch call).
_BASE = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
                   "ts": "2026-07-28T15:00:00Z"}]}


def _calls() -> list:
    """The source run's three captured calls, one per fixture system, all answered `_BASE`."""
    return [S.Call("idp", "query", S.query_params("user:alice"), _BASE),
            S.Call("edr", "query", S.query_params("host:db-1"), _BASE),
            S.Call("siem-x", "lookup", {"entity": "svc-1225"}, _BASE)]


def _launch(tmp_path, *, judge=None, spawn=None, calls=None, oracle=None, verifier=None,
            **seams) -> Launch:
    """Drive ONE whole episode through the real launcher over `_spec1224`'s fixture tenant, every
    fake entering by its seam."""
    est = S.estate(tmp_path)
    _base, src = S.source_run(tmp_path, est, calls=_calls() if calls is None else calls)
    nxt = _NextEpisode()
    if spawn is None:
        spawn = J.FakeSibling()
    if judge is None:
        judge = J.FakeJudge(
            default=J.as_reply_text(J.reply_doc(findings=[], bucket="none", systems=[])),
            family_default=J.as_reply_text(J.family_reply()))
    oracle = oracle if oracle is not None else S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM))  # lint-default: ok — a test builder's fresh per-call double, never a shared instance
    verifier = verifier if verifier is not None else S.passing_verifier()  # lint-default: ok — a test builder's fresh per-call double, never a shared instance
    seams.setdefault("questioner", S.questioner_for())
    seams.setdefault("preflight", S.no_preflight)
    seams.setdefault("live_tree", T.source_capture())
    seams.setdefault("roster", est.roster())
    before = now_iso()
    # #1105 PR 2 (declared change 1): the tenant and the source run by id.
    rc = _cli().main(["--tenant", src.parent.parent.name, src.name, str(T.BRANCH_MESSAGE_ID),
                      *T.retired_continuation_argv()],
                     spawn=spawn, judge=judge, oracle=oracle.model, verifier=verifier.model,
                     **seams)
    return Launch(rc, spawn, judge, nxt.dir, before, now_iso())


def _abort(tmp_path, raises: type[BaseException], **seams) -> tuple[Path, str, str]:
    """A launch expected to leave through `raises`; returns the episode dir and the clock
    bracket around the launch."""
    before = now_iso()
    nxt = _NextEpisode()
    with pytest.raises(raises):
        _launch(tmp_path, **seams)
    return nxt.dir, before, now_iso()


def _outcome(episode_dir: Path) -> dict:
    """Pre-flight's outcome record, through its production reader."""
    with T.mod("_io").bind(episode_dir) as bound:
        return T.mod("learning.branch.outcome").read_outcome(bound)


def _refusing_seams() -> dict:
    """The seams under which pre-flight REFUSES the family before any sibling starts: no world
    carries a fact, so there is nothing to calibrate (M05=A `refused`)."""
    bare = S.family_v2(worlds=[S.control_world("a"), S.world_v2("b", facts=[]),
                               S.world_v2("c", role="C", facts=[])])
    return {"questioner": S.questioner_for(bare)}


class _Interrupting:
    """A seam standing in for the operator's interrupt landing INSIDE the step that calls it."""

    def __init__(self, episode: _NextEpisode) -> None:
        self.episode = episode
        self.calls = 0
        self.seen: list[list[str]] = []

    def __call__(self, *args: Any, **kw: Any) -> Any:
        self.calls += 1
        self.seen.append(_steps(self.episode.dir))
        raise KeyboardInterrupt


class _WatchingSibling(J.FakeSibling):
    """`FakeSibling` that also records what the timing record held when the sibling was spawned
    (from inside the `runs` step) and holds the step open across a real second boundary,
    stamping the clock while inside it."""

    def __init__(self, *, hold: float = 0.0) -> None:
        super().__init__()
        self.hold = hold
        self.seen: list[list[str]] = []
        self.stamps: list[str] = []

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None,
                 **kw: Any) -> int:
        # #1187: the episode this child runs in, from its own `--tenant` and `--episode`.
        self.seen.append(_steps(self.episode_of(list(argv))))
        if self.hold:
            time.sleep(self.hold)
        self.stamps.append(now_iso())
        return super().__call__(argv, env=env, **kw)


class _PlantingSibling(J.FakeSibling):
    """`FakeSibling` that leaves a symlink to an outside directory where the episode's
    `worlds/` belongs — a real fault the episode handle's own screen refuses before the
    archive writes anything, so `verify_family` raises mid-step."""

    def __init__(self, *, outside: Path) -> None:
        super().__init__()
        self.outside = outside

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None,
                 **kw: Any) -> int:
        rc = super().__call__(argv, env=env, **kw)
        ep = self.episode_of(list(argv))
        with contextlib.suppress(FileExistsError):
            (ep / "worlds").symlink_to(self.outside, target_is_directory=True)
        return rc


def test_1025_a_step_row_round_trips_through_the_record(tmp_path):
    """`StageClock.record` adds one entry `{step, started_at, ended_at}` to `timing.json` at the
    episode root and returns it."""
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()
    # The name is the OWNER's now (#1077 D7) — `timing.py` held a re-binding of it.
    assert str(LAYOUT.timing) == "timing.json"
    assert not hasattr(timing, "TIMING_NAME"), "timing.py still re-binds the name"
    assert list(_steps_mod().STEPS) == EXPECTED_STEPS
    assert [s.value for s in _steps_mod().Step] == EXPECTED_STEPS, (
        "the enum's member order is not launch order, or STEPS is not derived from it")

    clock = timing.StageClock(_open(episode_dir))
    first = clock.record("questioner", started_at="2026-01-01T00:00:00+00:00",
                         ended_at="2026-01-01T00:00:05+00:00")
    second = clock.record("preflight", started_at="2026-01-01T00:00:07+00:00",
                          ended_at="2026-01-01T00:01:30+00:00")

    assert first == {"step": "questioner", "started_at": "2026-01-01T00:00:00+00:00",
                     "ended_at": "2026-01-01T00:00:05+00:00"}
    assert second == {"step": "preflight", "started_at": "2026-01-01T00:00:07+00:00",
                      "ended_at": "2026-01-01T00:01:30+00:00"}
    record = EpisodePaths(episode_dir).timing
    assert record.is_file(), "the record is not at the episode root under the owner's name"
    assert record.read_text(encoding="utf-8") == (
        json.dumps({"steps": [first, second]}, indent=2, sort_keys=True) + "\n"), (
        "the file is not the one whole document holding every entry, verbatim")
    assert _read(episode_dir) == [first, second]
    for row in (first, second):
        for key in ("started_at", "ended_at"):
            assert parse_iso_utc(row[key]) is not None, f"{key}={row[key]!r} is not a timestamp"


def test_1025_every_write_replaces_the_whole_document_and_never_the_open_file(tmp_path):
    """Each `record` swaps a NEW whole document into place."""
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()
    record = EpisodePaths(episode_dir).timing
    clock = timing.StageClock(_open(episode_dir))
    first = clock.record("questioner", started_at=now_iso(), ended_at=now_iso())
    before_text = record.read_text(encoding="utf-8")
    before_inode = os.stat(record).st_ino

    with record.open("r", encoding="utf-8") as held_open:
        second = clock.record("preflight", started_at=now_iso(), ended_at=now_iso())
        assert held_open.read() == before_text, (
            "a handle opened before the write saw the new bytes — the existing file was written "
            "in place rather than replaced")
    assert os.stat(record).st_ino != before_inode, "the write reused the existing file"
    assert json.loads(record.read_text(encoding="utf-8")) == {"steps": [first, second]}
    assert _read(episode_dir) == [first, second]


def test_1025_a_document_that_is_not_the_record_raises_rather_than_reading_as_no_steps(tmp_path):
    """A file at the record's name that is not the record ."""
    good = {"step": "questioner", "started_at": "2026-01-01T00:00:00+00:00",
            "ended_at": "2026-01-01T00:00:05+00:00"}
    foreign = [
        "{not json\n",
        json.dumps([good]) + "\n",
        json.dumps({"rows": [good]}) + "\n",
        json.dumps({"steps": {"questioner": good}}) + "\n",
        json.dumps({"steps": [{"step": "questioner", "started_at": good["started_at"]}]}) + "\n",
        json.dumps({"steps": [{**good, "duration_ms": 5}]}) + "\n",
        json.dumps({"steps": [{**good, "ended_at": None}]}) + "\n",
        json.dumps({"steps": [{**good, "step": "teardown"}]}) + "\n",
        json.dumps({"steps": [{**good, "started_at": "not a moment"}]}) + "\n",
        json.dumps(good) + "\n" + json.dumps(good) + "\n",
        "[" * 100_000 + "]" * 100_000,
    ]
    for n, text in enumerate(foreign):
        episode_dir = tmp_path / f"episode-{n}"
        episode_dir.mkdir()
        EpisodePaths(episode_dir).timing.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError, match=str(LAYOUT.timing)):
            _read(episode_dir)

    plain = tmp_path / "plain-episode"
    plain.mkdir()
    EpisodePaths(plain).timing.write_text(json.dumps({"steps": [good]}), encoding="utf-8")
    assert _read(plain) == [good], "the control failed"


def test_1025_an_unknown_step_is_refused_and_nothing_is_written(tmp_path):
    """A step name outside `STEPS` is refused with a `ValueError` naming it, and the refusal writes
    nothing."""
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()
    record = EpisodePaths(episode_dir).timing
    clock = timing.StageClock(_open(episode_dir))

    with pytest.raises(ValueError, match="questionner"):
        clock.record("questionner", started_at=now_iso(), ended_at=now_iso())
    assert not record.exists(), "a refused step brought the record into existence"

    good = clock.record("questioner", started_at=now_iso(), ended_at=now_iso())
    bytes_before = record.read_bytes()
    with pytest.raises(ValueError, match="teardown"):
        clock.record("teardown", started_at=now_iso(), ended_at=now_iso())
    assert record.read_bytes() == bytes_before, "a refused step still wrote to the record"
    assert _read(episode_dir) == [good], "the control failed"


def test_1025_an_aliased_or_non_plain_record_is_refused_not_written_through(tmp_path):
    """The record is written through `_io.write_guarded`."""
    outside = tmp_path / "outside.json"
    outside.write_text("untouched\n", encoding="utf-8")
    original_links = os.stat(outside).st_nlink

    symlinked = tmp_path / "symlinked-episode"
    symlinked.mkdir()
    EpisodePaths(symlinked).timing.symlink_to(outside)
    with pytest.raises(OSError, match="aliased") as refusal:
        _clock(symlinked).record("questioner", started_at=now_iso(), ended_at=now_iso())
    assert refusal.value.write_guarded_alias is True, (
        "the symlink was refused by something other than the guarded write seam")
    assert EpisodePaths(symlinked).timing.is_symlink(), "the planted link was replaced"

    hardlinked = tmp_path / "hardlinked-episode"
    hardlinked.mkdir()
    os.link(outside, EpisodePaths(hardlinked).timing)
    assert os.stat(outside).st_nlink == original_links + 1, "the control failed: no hard link"
    with pytest.raises(OSError, match="aliased") as refusal:
        _clock(hardlinked).record("questioner", started_at=now_iso(), ended_at=now_iso())
    assert refusal.value.write_guarded_alias is True, (
        "the hard link was not refused as an alias — a symlink check alone lets it through")

    squatted = tmp_path / "squatted-episode"
    squatted.mkdir()
    EpisodePaths(squatted).timing.mkdir()
    with pytest.raises(OSError, match="aliased") as refusal:
        _clock(squatted).record("questioner", started_at=now_iso(), ended_at=now_iso())
    assert refusal.value.write_guarded_alias is False, (
        "a directory at the record's name was not refused by the guarded write seam")

    assert outside.read_text(encoding="utf-8") == "untouched\n", (
        "the record was written THROUGH a planted entry")

    plain = tmp_path / "plain-episode"
    plain.mkdir()
    row = _clock(plain).record("questioner", started_at=now_iso(), ended_at=now_iso())
    assert _read(plain) == [row], "the control failed"


def test_1025_the_reader_refuses_what_it_cannot_read_and_only_absence_is_empty(tmp_path):
    """`read_stage_timings` reads through `_io.read_guarded`, the posture of every other reader of
    the episode tree, and splits ABSENT from REFUSED the way the judge's readers do."""
    planted = tmp_path / "planted.json"
    stray = {"step": "judge", "started_at": "2020-01-01T00:00:00+00:00",
             "ended_at": "2020-01-01T09:00:00+00:00"}
    planted.write_text(json.dumps({"steps": [stray]}) + "\n", encoding="utf-8")

    symlinked = tmp_path / "symlinked-episode"
    symlinked.mkdir()
    EpisodePaths(symlinked).timing.symlink_to(planted)
    with pytest.raises(ValueError, match=str(LAYOUT.timing)):
        _read(symlinked)
    assert EpisodePaths(symlinked).timing.is_symlink(), "the planted link was replaced"

    squatted = tmp_path / "squatted-episode"
    squatted.mkdir()
    EpisodePaths(squatted).timing.mkdir()
    with pytest.raises(ValueError, match=str(LAYOUT.timing)):
        _read(squatted)

    binary = tmp_path / "binary-episode"
    binary.mkdir()
    EpisodePaths(binary).timing.write_bytes(b"\xff\xfe not text")
    with pytest.raises(ValueError, match=str(LAYOUT.timing)):
        _read(binary)

    plain = tmp_path / "plain-episode"
    plain.mkdir()
    EpisodePaths(plain).timing.write_text(json.dumps({"steps": [stray]}) + "\n",
                                            encoding="utf-8")
    assert _read(plain) == [stray], "the control failed"


def test_1025_a_step_the_disk_refused_once_is_still_on_the_next_document(tmp_path):
    """A step the clock saw finish stays on the clock even when the disk refused THAT write."""
    timing = _timing()
    episode_dir = tmp_path / "episode"
    episode_dir.mkdir()
    record = EpisodePaths(episode_dir).timing
    clock = timing.StageClock(_open(episode_dir))
    clock.record("questioner", started_at=now_iso(), ended_at=now_iso())

    good = record.read_bytes()
    record.unlink()
    record.mkdir()
    with pytest.raises(OSError, match="aliased"):
        clock.record("preflight", started_at=now_iso(), ended_at=now_iso())
    record.rmdir()
    record.write_bytes(good)

    clock.record("runs", started_at=now_iso(), ended_at=now_iso())
    assert _steps(episode_dir) == ["questioner", "preflight", "runs"], (
        "the step whose own write was refused is missing from the document written after it")


def test_1025_an_accepted_episode_leaves_every_step_in_launch_order(tmp_path):
    """A clean accepted episode leaves five rows in `STEPS` order — in the FILE, not merely as
    the reader returns them — each row's moments inside the real clock's bracket around the
    launch, `started_at <= ended_at`, and each step starting no earlier than the previous one
    ended. The rows are on disk from inside a LATER step: the sibling spawned during `runs`
    already sees `questioner`, `preflight`, and the judge called during `judge` sees the four
    before it — a record buffered and flushed on the way out shows them nothing."""
    nxt = _NextEpisode()
    sibling = _WatchingSibling()
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    seen_by_judge: list[list[str]] = []

    def watching_judge(prompt, **kw):
        seen_by_judge.append(_steps(nxt.dir))
        return judge(prompt, **kw)

    launch = _launch(tmp_path, spawn=sibling, judge=watching_judge)
    assert launch.rc == 0, "the control failed: the accepted episode did not launch cleanly"
    assert _outcome(launch.episode_dir)["outcome"] == "accepted", "the control failed"

    rows = _raw_rows(launch.episode_dir)
    assert [row["step"] for row in rows] == EXPECTED_STEPS
    assert _steps(launch.episode_dir) == EXPECTED_STEPS
    assert list(_steps_mod().STEPS) == EXPECTED_STEPS

    _clocked(rows, before=launch.before, after=launch.after)

    assert sibling.seen, "the control failed: no sibling was spawned"
    assert all(seen == ["questioner", "preflight"] for seen in sibling.seen), (
        f"a sibling spawned during `runs` saw {sibling.seen} on the record — the rows are "
        "not on disk at the boundary")
    assert seen_by_judge, "the control failed: the judge was never called"
    assert seen_by_judge[0] == ["questioner", "preflight", "runs", "verify"], (
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
    sibling = _WatchingSibling(hold=1.1)
    launch = _launch(tmp_path, spawn=sibling)
    assert launch.rc == 0, "the control failed: the accepted episode did not launch cleanly"
    assert sibling.stamps, "the control failed: no sibling was spawned"

    rows = _raw_rows(launch.episode_dir)
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


def test_1025_an_aborted_episode_keeps_the_completed_steps_and_not_the_one_that_raised(
        tmp_path, monkeypatch):
    """An episode that aborts MID-STEP leaves the rows for the steps that completed and no row for
    the step that raised ."""
    cli = _cli()

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-questioner"))
    questioner = _Interrupting(_NextEpisode())
    ep, _before, _after = _abort(tmp_path, cli.LauncherRefused, questioner=questioner)
    assert questioner.calls > 0, "the control failed: the questioner seam was never reached"
    assert questioner.seen == [[]], f"the questioner saw {questioner.seen} before it ran"
    assert _raw_rows(ep) == [], "a step that raised was recorded"

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-preflight"))
    oracle_seam = _Interrupting(_NextEpisode())
    ep, before, after = _abort(tmp_path, cli.LauncherRefused,
                               oracle=S.oracle(then=S.Move(None, raises=oracle_seam)))
    assert oracle_seam.calls > 0, "the control failed: pre-flight's oracle was never reached"
    assert all(seen == ["questioner"] for seen in oracle_seam.seen), (
        f"the oracle saw {oracle_seam.seen} mid-pre-flight")
    assert [row["step"] for row in _raw_rows(ep)] == ["questioner"]
    _clocked(_raw_rows(ep), before=before, after=after)

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-runs"))
    family = _Interrupting(_NextEpisode())
    ep, before, after = _abort(tmp_path, KeyboardInterrupt, spawn=family)
    assert family.calls > 0, "the control failed: the process seam was never reached"
    assert all(seen == ["questioner", "preflight"] for seen in family.seen), (
        f"a sibling saw {family.seen} on the record when spawned")
    assert [row["step"] for row in _raw_rows(ep)] == ["questioner", "preflight"], (
        "the record does not stop at the last step that completed")
    _clocked(_raw_rows(ep), before=before, after=after)

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-verify"))
    outside = tmp_path / "outside-verify"
    outside.mkdir()
    planting = _PlantingSibling(outside=outside)
    ep, before, after = _abort(tmp_path, OSError, spawn=planting)
    assert planting.launches, "the control failed: no sibling was spawned"
    assert list(outside.iterdir()) == [], (
        "the control failed: the archive wrote through the planted alias")
    assert [row["step"] for row in _raw_rows(ep)] == ["questioner", "preflight", "runs"], (
        "a `verify` that raised was recorded, or a step before it was not")
    _clocked(_raw_rows(ep), before=before, after=after)

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-judge"))
    judge = _Interrupting(_NextEpisode())
    ep, before, after = _abort(tmp_path, KeyboardInterrupt, judge=judge)
    assert judge.calls > 0, "the control failed: the judge seam was never reached"
    assert judge.seen == [["questioner", "preflight", "runs", "verify"]], (
        f"the judge saw {judge.seen} when called")
    assert [row["step"] for row in _raw_rows(ep)] == EXPECTED_STEPS[:4], (
        "a `judge` that raised was recorded")
    _clocked(_raw_rows(ep), before=before, after=after)


def test_1025_a_record_that_cannot_be_written_does_not_end_the_episode(tmp_path, capsys):
    """A timing entry the record cannot take ."""
    author = S.questioner_for()
    squatted: list[Path] = []
    nxt = _NextEpisode()

    def squatting_author(prompt, **kw):
        if not squatted:
            episode_dir = nxt.dir
            EpisodePaths(episode_dir).timing.mkdir()
            squatted.append(episode_dir)
        return author(prompt, **kw)

    launch = _launch(tmp_path, questioner=squatting_author)
    assert squatted == [launch.episode_dir], "the control failed: the squat was not planted"
    assert launch.rc == 0, "a refused timing write ended the episode"
    assert _outcome(launch.episode_dir)["outcome"] == "accepted", (
        "the family was not calibrated after the refused write")
    for label in ("a", "b", "c"):
        assert (launch.episode_dir / "worlds" / T.world_id(launch.episode_dir, label) / "report.md").is_file(), (
            f"world {label} was not archived after the refused write")
    assert launch.judge.calls > 0, "the judge was never reached after the refused write"
    assert (launch.episode_dir / "judge.yaml").exists(), "the grade did not land"
    err = capsys.readouterr().err
    for step in EXPECTED_STEPS:
        assert f"the {step} entry could not be written" in err, (
            f"the refused {step} row was not reported")
    with pytest.raises(ValueError, match=str(LAYOUT.timing)):
        _steps(launch.episode_dir)
