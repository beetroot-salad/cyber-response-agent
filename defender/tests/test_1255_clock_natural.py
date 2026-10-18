"""#1255 slice D — on a NATURAL run, every time the model can see is a reading of the run clock.

Design rev 4, "Time": the run clock is owned by the host and, on a natural run, reads its
source (production: wall time). "Every time the model can see comes from it: timestamps written
to readable files, … times in prompts and tool output, budget and timeout messages." Dossier
seam: `driver.run_investigation(clock=…)` is the run's single source of wall time. Rev 5 C4
bounds what it governs: "model-visible times and the budget's wall-clock limb"; the real-time
safety bounds (the bash exec timeout, the review stage's wait, lead-0's timeout) "are not
model-visible times and stay on real time", and an adapter called outside any run stamps wall
time (`test_947_clock`).

Census of what the model can see today that carries a time (base 4b3628ed), and where each
comes from — each row is a channel below or a named exclusion:

  * `lessons_loaded.jsonl` `ts` (run root, in MAIN's and gather's read scope) — `now_iso()`,
    the wall clock (`runtime/tools/_deps.py` `_record_lesson_load`).            -> N1, N6
  * `policy_denials.jsonl` `ts` (run root, in read scope) — `now_iso()`
    (`runtime/observe.py` `log_policy_denial`).                                  -> N2, N6
  * a host-state payload's `captured_at` (the tool result and its `gather_raw` payload) —
    the wall clock on a natural run, `ctx.as_of` on an arm
    (`scripts/adapters/host_state_adapter.py` `_captured_at`).                   -> N3, N6
  * the budget's wall-clock limb, which decides whether the model is shown the budget refusal
    (and names `wall-clock` in it) — `max(wall delta, monotonic delta)` from `RunState`'s own
    origins (`hooks/budget_enforcer.py` `_elapsed`).                             -> N4, N5
  * the arm-only `now:` line (`runtime/driver/_prompts.py` `_branch_clock`) — slice A's
    (no injected opening); not repeated here.
  * the SQL engine's `now()` and python's time inside the box — `test_1255_clock_box.py`.
  * host-only, outside O1's surface: `circuit_breaker` `tripped_at` (RunState), the wire log's
    `ts`, `observe.write_trace`'s `wall_ms`, a fold frontier's message timestamp (part
    timestamps are never sent to the provider). Not asserted.
  * real-time safety bounds — `bash_exec`'s timeout, the review gate's `wait_for`, lead-0's
    `asyncio.timeout`: excluded by C4 (they stay on real time). Not asserted.

Every scenario drives the REAL driver loop, tools, gate, query tool and budget hooks; the only
injected values are the models (`Clocked` doubles that advance the clock by the seconds the
step "took"), the clock source, and where named a verb registry. Expected instants are the
test's own sums over its own script. The clock starts in 2031 (`SOURCE_START`), so a wall-clock
stamp cannot coincide with one.

Every test here is RED until `run_investigation` accepts `clock=` (class a) — N4's
`inside-the-limit` case included, though it is the pass-control of its pair (with the keyword
withheld it passes today; it is there to show the channel carries the call's output). Each was
also driven with the `clock=` keyword withheld (a scratch toggle, not committed) to show its
machinery reaches the assertion on today's code; every other case's assertion rejected today's
behaviour there (class c).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import time
from pathlib import Path

import pytest

from defender.tests import _1255_clock as C
from defender.tests.e2e._replay_harness import GOLDEN_AB3, materialize

pytestmark = pytest.mark.e2e

START = C.SOURCE_START
L1, L2, L3 = C.LESSONS


@pytest.fixture
def enforced(monkeypatch):
    """The enforcing posture, set the way production sets it."""
    monkeypatch.setenv(C.FLAG, "true")


def _run_dir(tmp_path: Path, name: str = "run") -> Path:
    return materialize(tmp_path, GOLDEN_AB3, run_id=name)


# ---------------------------------------------------------------------------------------
# N1 — the lessons log: a file the model can read, stamped by the run clock
# ---------------------------------------------------------------------------------------


def test_n1_a_natural_runs_lessons_log_is_stamped_with_the_run_clocks_readings(tmp_path):
    """O4 / P5 (time): each `lessons_loaded.jsonl` row MAIN's read leaves carries the run
    clock's reading at that read — the injected source's own time, not the wall clock.

    Script: MAIN reads L1 after 10 s of work and L2 after a further 50 s, then stops. Expected
    instants are `START+10` and `START+60`. Positive control on the same channel: both rows
    exist (an empty log satisfies no equality)."""
    clock = C.FakeClock(START)
    run_dir = _run_dir(tmp_path)
    main = C.script(clock, (10, C.read_lesson(L1)), (50, C.read_lesson(L2)), (5, C.DONE))

    C.drive_clocked(run_dir, clock=clock, main=main)

    assert C.lesson_reads(run_dir, L1), (f"the reads left no lessons-log rows, so nothing below is observed: "
        f"{C.lesson_rows(run_dir)}")
    assert C.lesson_reads(run_dir, L2), (f"the reads left no lessons-log rows, so nothing below is observed: "
        f"{C.lesson_rows(run_dir)}")
    assert C.lesson_reads(run_dir, L1) == [C.at(START, 10)], (
        "L1's row is not stamped with the run clock's reading at the read (START+10s) — "
        f"rows: {C.lesson_rows(run_dir)}")
    assert C.lesson_reads(run_dir, L2) == [C.at(START, 60)], (
        "L2's row is not stamped with the run clock's reading at the read (START+60s)")


def test_n6_a_source_stepping_back_never_makes_a_visible_time_run_backwards(tmp_path):
    """O4: every time the model can see "never runs earlier than the history's last
    timestamp". The source steps BACK an hour between two reads (a wall clock corrected by
    NTP does this); the second row must not name an instant before the first, which the model
    already holds.

    Positive control: N1 — the same channel follows the source forward."""
    clock = C.FakeClock(START)
    run_dir = _run_dir(tmp_path)
    main = C.script(clock, (10, C.read_lesson(L1)), (-3600, C.read_lesson(L2)), (0, C.DONE))

    C.drive_clocked(run_dir, clock=clock, main=main)

    first, second = C.lesson_reads(run_dir, L1), C.lesson_reads(run_dir, L2)
    assert first == [C.at(START, 10)], f"the first read is not the run clock's reading: {first}"
    assert len(second) == 1, f"the second read left no row: {second}"
    assert second[0] is not None, f"the second read left no row: {second}"
    assert second[0] >= first[0], (
        f"a visible time ran backwards: the model already holds {first[0]} and was then shown "
        f"{second[0]}")


# ---------------------------------------------------------------------------------------
# N2 — the denial log: written by the gather lead's query tool
# ---------------------------------------------------------------------------------------


def test_n2_a_natural_runs_denial_log_is_stamped_with_the_run_clocks_readings(tmp_path):
    """O4 / P5 (time): each `policy_denials.jsonl` row carries the run clock's reading at the
    denied call. A gather lead calls a verb its grant withholds twice: after 10 s (MAIN's
    dispatch) + 20 s, and again 30 s later. Expected: `START+30`, `START+60`.

    The registry is #632's scoped fake (grant: `elastic.query` only), so `elastic.esql` is
    denied by the real grant decision; nothing about the denial is faked. Positive control:
    two rows exist, each naming the denied verb."""
    from defender.tests._verb_authorization_632 import ScopedFakeVerbs, grant_of, recording_table
    from defender.tests.e2e._replay_harness import VerbRecorder

    clock = C.FakeClock(START)
    run_dir = _run_dir(tmp_path)
    verbs = ScopedFakeVerbs(recording_table(VerbRecorder(), {"elastic": ("query", "esql")}),
                            grant_of("gather", (("elastic", "query"),)))
    main = C.script(clock, (10, C.gather_turn("l-001", "elastic")), (0, C.DONE))
    gather = C.script(clock, (20, C.query("elastic", "esql")), (30, C.query("elastic", "esql")),
                      (0, C.H.Turn(text="Summary: measured the lead.")))

    C.drive_clocked(run_dir, clock=clock, main=main, gather=gather, verbs=verbs)

    rows = [r for r in C.denial_rows(run_dir) if r.get("verb") == "esql"]
    assert len(rows) == 2, f"two denied calls, two denial rows; got {C.denial_rows(run_dir)}"
    assert [C.instant(r.get("ts")) for r in rows] == [C.at(START, 30), C.at(START, 60)], (
        "the denial rows are not stamped with the run clock's readings at the denied calls "
        f"(START+30s, START+60s): {rows}")


# ---------------------------------------------------------------------------------------
# N3 — a capture stamp in a tool result: host-state's `captured_at`
# ---------------------------------------------------------------------------------------

#: The six stamping verbs and their arguments, as `test_947_clock.STAMPING_VERBS` names them.
STAMPING_VERBS = [
    ("container-inspect", {"container_id": "abc123def456"}),
    ("proc-tree", {"host": "web-1"}),
    ("passwd", {"host": "web-1"}),
    ("authorized-keys", {"host": "web-1"}),
    ("fim-checksum", {"host": "web-1", "path": "/etc/hosts"}),
    ("package-list", {"host": "web-1"}),
]


def test_n3_every_host_state_capture_on_a_natural_run_is_stamped_with_the_run_clock(
        tmp_path, monkeypatch):
    """Time, "capture stamps use the run clock": each of host-state's six stamping verbs,
    served through the REAL production registry and the REAL adapter body, carries
    `captured_at` == the run clock's reading at its call (`Z` seconds), in the payload the model
    is handed (the persisted `gather_raw` payload the query row names).

    Seven seconds of lead work before each call, so the six expected stamps are all different
    (`START+10+7k`). The transport is a `docker` planted on the run's own PATH (the env the
    query tool builds its context from), as `test_947_clock` drives the adapters; it answers
    every shape and records nothing the assertion reads. Today: the wall clock."""
    from defender import _clock
    from defender._io import read_jsonl_rows
    from defender.tests.test_947_clock import DOCKER_LOG, fake_docker

    monkeypatch.setenv("PATH", f"{fake_docker(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("DOCKER_CALL_LOG", str(tmp_path / DOCKER_LOG))
    clock = C.FakeClock(START)
    run_dir = _run_dir(tmp_path)
    main = C.script(clock, (10, C.gather_turn("l-001", "host-state")), (0, C.DONE))
    gather = C.script(clock, *[(7, C.query("host-state", verb, params))
                               for verb, params in STAMPING_VERBS],
                      (0, C.H.Turn(text="Summary: captured.")))

    C.drive_clocked(run_dir, clock=clock, main=main, gather=gather)

    rows = [r for r in read_jsonl_rows(run_dir / "executed_queries.jsonl")
            if r.get("lead_id") == "l-001"]
    assert [r["verb"] for r in rows] == [v for v, _ in STAMPING_VERBS], (
        f"the six captures did not all run through the query tool: {rows}")
    stamps = []
    for row in rows:
        assert row["exit_code"] == 0, f"a capture failed: {row}"
        assert row["payload_path"], f"a capture failed: {row}"
        payload = json.loads((run_dir / row["payload_path"]).read_text(encoding="utf-8"))
        stamps.append(payload.get("captured_at"))
    expected = [_clock.z_seconds(C.at(START, 10 + 7 * (k + 1))) for k in range(6)]
    assert stamps == expected, (
        "a host-state capture is not stamped with the run clock's reading at its call — "
        f"expected {expected}, got {stamps}")


# ---------------------------------------------------------------------------------------
# N6 over every channel — no visible time runs backwards, within a channel or across them
# ---------------------------------------------------------------------------------------


def _channel_stamps(run_dir: Path, channel: str) -> list[dt.datetime | None]:
    """The stamps a channel left, in call order: the denials log's `ts` for the denied
    `elastic.esql` calls, or each host-state capture's `captured_at` in the payload the query
    row names."""
    if channel == "denials":
        return [C.instant(r.get("ts")) for r in C.denial_rows(run_dir) if r.get("verb") == "esql"]
    from defender._io import read_jsonl_rows

    stamps: list[dt.datetime | None] = []
    for row in read_jsonl_rows(run_dir / "executed_queries.jsonl"):
        if row.get("lead_id") != "l-001":
            continue
        assert row.get("exit_code") == 0, f"a capture failed: {row}"
        assert row.get("payload_path"), f"a capture failed: {row}"
        payload = json.loads((run_dir / row["payload_path"]).read_text(encoding="utf-8"))
        stamps.append(C.instant(payload.get("captured_at")))
    return stamps


@pytest.mark.parametrize("channel", ["denials", "capture"])
def test_n6_a_step_back_never_makes_a_denial_or_capture_stamp_run_backwards(
        tmp_path, monkeypatch, channel):
    """O4 over EVERY channel, not just the lessons log: "every time the model can see agrees
    with every other one and never runs earlier than the history's last timestamp". MAIN reads
    L1 after 10 s (a lessons-log row: the run clock's START+10, as N1), then dispatches a lead.
    The source then steps BACK an hour before the lead's first call, forward 20 s before its
    second, and back an hour again before its third. Each call leaves a stamp the model can
    read — a denials-log row (`elastic.esql` withheld by the grant, N2's registry) or a
    host-state capture's `captured_at` (the real adapter through the real registry, N3's
    transport) — and the sequence lessons row, then the channel's three stamps, never decreases.

    The violations it rejects (contract-repair finding F-D1, the handoff's own deferred
    "writer-only clamp" mutant): only the lessons writer absorbs a step back while the denial or
    capture writer reads the source raw (the first channel stamp an hour before the lessons
    row); or each writer clamps against its own last stamp only (the first channel stamp, the
    writer's first, still behind the lessons row the model already holds).

    Positive controls: the lessons row is START+10 (the channel follows the clock), and each
    channel left three stamps. Exact readings after a step back are not asserted (O4 asks
    order, and C10's "absorbed" is stated for elapsed time)."""
    clock = C.FakeClock(START)
    run_dir = _run_dir(tmp_path)
    kw: dict = {}
    if channel == "denials":
        from defender.tests._verb_authorization_632 import (
            ScopedFakeVerbs,
            grant_of,
            recording_table,
        )
        from defender.tests.e2e._replay_harness import VerbRecorder

        kw["verbs"] = ScopedFakeVerbs(
            recording_table(VerbRecorder(), {"elastic": ("query", "esql")}),
            grant_of("gather", (("elastic", "query"),)))
        system = "elastic"
        calls = [C.query("elastic", "esql")] * 3
    else:
        from defender.tests.test_947_clock import DOCKER_LOG, fake_docker

        monkeypatch.setenv("PATH", f"{fake_docker(tmp_path)}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("DOCKER_CALL_LOG", str(tmp_path / DOCKER_LOG))
        system = "host-state"
        calls = [C.query("host-state", verb, params) for verb, params in STAMPING_VERBS[:3]]
    main = C.script(clock, (10, C.read_lesson(L1)), (0, C.gather_turn("l-001", system)),
                    (0, C.DONE))
    gather = C.script(clock, (-3600, calls[0]), (20, calls[1]), (-3600, calls[2]),
                      (0, C.H.Turn(text="Summary: measured the lead.")))

    C.drive_clocked(run_dir, clock=clock, main=main, gather=gather, **kw)

    lesson = C.lesson_reads(run_dir, L1)
    assert lesson == [C.at(START, 10)], (
        f"positive control: the lessons row is not the run clock's reading (START+10): {lesson}")
    stamps = _channel_stamps(run_dir, channel)
    assert len(stamps) == 3, f"the lead's three {channel} calls left {len(stamps)} stamps"
    assert None not in stamps, f"a {channel} stamp does not read as a time: {stamps}"
    seen = [*lesson, *stamps]
    assert seen == sorted(seen), (
        f"a visible time ran backwards across the lessons log and the {channel} channel: the "
        f"model was shown, in order, {[s.isoformat() for s in seen]}")


# ---------------------------------------------------------------------------------------
# N4 / N5 — the budget's wall-clock limb is measured on the run clock
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(("advance", "refused"), [(601, True), (599, False)],
                         ids=["past-the-limit", "inside-the-limit"])
def test_n4_the_wall_clock_limb_measures_the_run_clock(tmp_path, enforced, advance, refused):
    """Time, "budget and timeout messages": the budget's wall-clock limb reads elapsed time off
    the run clock. With a 600 s limit, a MAIN turn that took `advance` seconds of run-clock time
    before its second `bash` call is refused — the model is shown the budget refusal naming the
    `wall-clock` limb — exactly when the run clock has passed the limit. Real time is a few
    hundred milliseconds either way.

    The two cases are each other's control on the same channel: at 599 s the same call runs and
    its output reaches the model. Today the limb reads the wall/monotonic clocks, so 601 s of
    run-clock time refuses nothing."""
    clock = C.FakeClock(START)
    run_dir = _run_dir(tmp_path)
    main = C.script(clock, (0, C.bash("echo first")), (advance, C.bash("echo second-call-ran")),
                    (0, C.DONE))

    C.drive_clocked(run_dir, clock=clock, main=main,
                    limits=C.caps(wall_clock_timeout=600, grace_seconds=600, max_tool_calls=50))

    assert len(main.seen) >= 3, f"the run stopped before its second call was answered: {main.seen}"
    shown = main.seen[2]
    if refused:
        assert C.refusal_stem() in shown, (f"{advance} s of run-clock time past a 600 s limit refused nothing — the wall-clock "
            "limb does not read the run clock")
        assert "wall-clock" in shown, (f"{advance} s of run-clock time past a 600 s limit refused nothing — the wall-clock "
            "limb does not read the run clock")
        assert "second-call-ran" not in shown, "the refused call ran anyway"
    else:
        assert C.refusal_stem() not in shown, (
            f"{advance} s of run-clock time is inside a 600 s limit and was refused")
        assert "second-call-ran" in shown, "the call inside the limit did not run"


#: The elapsed seconds the budget reports with each metered call (`check_budgets`'s
#: `wall_clock at <n>s/<cap>s`, logged after every executed call) — the one place the number
#: the limb measures is written. The model is shown the limb by name, never the number.
_MEASURED = re.compile(r"wall_clock at (\d+)s/")


def _measured_elapsed(caplog: pytest.LogCaptureFixture) -> list[int]:
    return [int(n) for r in caplog.records for n in _MEASURED.findall(r.getMessage())]


@pytest.mark.parametrize("case", ["after-limit", "before-limit"])
def test_the_wall_clock_limb_never_shrinks_when_the_source_steps_back(
        tmp_path, enforced, caplog, case):
    """C10 (O4): the run clock never runs backwards, so the elapsed time the budget measures
    never decreases — "a step back in the underlying source neither lifts a limit already
    reached nor extends one not yet reached". A 600 s limit; the source steps back an hour.

    * after-limit: `bash` at +0 runs; `bash` after +601 s is refused (wall-clock); the source
      then steps back 3600 s and the next `bash` is STILL refused — the limit is not lifted. A
      metered tail call (`read_file`, never refused at the cap) after the step-back has the
      budget report elapsed >= 601.
    * before-limit: `bash` after +500 s runs; the source steps back 3600 s and `bash` runs
      (500 s, inside the limit — the step-back tripped nothing either); after +200 s more,
      `bash` is refused: elapsed is 500 + 200 = 700 >= 600, not 200 - 3600 + 500 — the
      step-back did not extend the limit.

    Each case's control is on the same channel: the call before the trip runs and its output
    reaches the model. Across the run, every elapsed the budget reports is >= the one before.
    Today the limb reads the wall/monotonic clocks, so no case is refused (class c once
    `clock=` lands)."""
    caplog.set_level(logging.WARNING)
    clock = C.FakeClock(START)
    run_dir = _run_dir(tmp_path)
    if case == "after-limit":
        steps = [(0, C.bash("echo first-call-ran")), (601, C.bash("echo second-call-ran")),
                 (-3600, C.bash("echo third-call-ran")), (0, C.read_lesson(L1)), (0, C.DONE)]
    else:
        steps = [(500, C.bash("echo first-call-ran")), (-3600, C.bash("echo second-call-ran")),
                 (200, C.bash("echo third-call-ran")), (0, C.DONE)]
    main = C.script(clock, *steps)

    C.drive_clocked(run_dir, clock=clock, main=main,
                    limits=C.caps(wall_clock_timeout=600, grace_seconds=600, max_tool_calls=50))

    def refused(i: int, marker: str) -> bool:
        assert len(main.seen) > i, f"the run stopped before request {i}: {main.seen}"
        shown = main.seen[i]
        hit = C.refusal_stem() in shown and "wall-clock" in shown
        assert hit != (marker in shown), f"request {i} shows both or neither: {shown[-400:]}"
        return hit

    assert not refused(1, "first-call-ran"), "the first call, inside the limit, was refused"
    measured = _measured_elapsed(caplog)
    if case == "after-limit":
        assert refused(2, "second-call-ran"), (
            "601 s of run-clock time past a 600 s limit refused nothing — the control failed")
        assert refused(3, "third-call-ran"), (
            "the source stepping back an hour lifted a wall-clock limit already reached")
        assert C.lesson_reads(run_dir, L1), (
            "the metered tail call after the step-back did not run (no lessons-log row)")
        assert measured, (f"after the step-back the budget measures {measured} — less than the 601 s it had "
            "already counted")
        assert measured[-1] >= 601, (f"after the step-back the budget measures {measured} — less than the 601 s it had "
            "already counted")
    else:
        assert not refused(2, "second-call-ran"), (
            "the step-back itself tripped the limit at 500 s of a 600 s limit")
        assert refused(3, "third-call-ran"), (
            "500 s, a step back, then 200 s more is 700 s of a 600 s limit, and nothing was "
            "refused — the step-back extended the limit")
        assert len(measured) >= 2, f"the budget reported no elapsed for the two calls that ran: {measured}"
        assert measured[0] >= 500, f"the budget reported no elapsed for the two calls that ran: {measured}"
    assert measured == sorted(measured), f"the elapsed the budget measures decreased: {measured}"


def test_n5_real_time_the_run_clock_did_not_count_trips_no_limit(tmp_path, enforced):
    """C4: the run clock governs "the budget's wall-clock limb". A run whose source does NOT
    move is never past a 1 s limit, however long the host really takes: MAIN sleeps 1.5 s of
    REAL time before its second `bash` call and is not refused. (The real-time safety bounds C4
    keeps on real time are timeouts of one command or one stage, not this limb.)

    Positive control: N4 — the same limb on the same channel refuses when the run clock passes
    the limit. Today the limb takes the larger of the wall and monotonic deltas, so the real
    1.5 s refuses the call."""
    clock = C.FakeClock(START)
    run_dir = _run_dir(tmp_path)

    def slow(_text: str) -> C.H.Turn:
        time.sleep(1.5)
        return C.bash("echo second-call-ran")

    main = C.script(clock, (0, C.bash("echo first")), (0, slow), (0, C.DONE))

    C.drive_clocked(run_dir, clock=clock, main=main,
                    limits=C.caps(wall_clock_timeout=1, grace_seconds=600, max_tool_calls=50))

    assert len(main.seen) >= 3, f"the run stopped before its second call was answered: {main.seen}"
    assert C.refusal_stem() not in main.seen[2], (
        "real time the run clock never counted tripped the wall-clock limb — elapsed is not "
        "measured on the run clock alone")
    assert "second-call-ran" in main.seen[2], "the second call did not run"
