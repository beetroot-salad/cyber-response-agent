"""Natural-run timestamps and budget elapsed time follow one monotonic run clock."""
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


@pytest.mark.parametrize("advance", [50, -3600], ids=["forward", "step-back"])
def test_lessons_follow_the_run_clock(tmp_path, advance):
    clock = C.FakeClock(START)
    run_dir = _run_dir(tmp_path)
    main = C.script(clock, (10, C.read_lesson(L1)), (advance, C.read_lesson(L2)), (0, C.DONE))

    C.drive_clocked(run_dir, clock=clock, main=main)

    first, second = C.lesson_reads(run_dir, L1), C.lesson_reads(run_dir, L2)
    assert first == [C.at(START, 10)], first
    assert len(second) == 1, second
    assert second[0] is not None, second
    if advance > 0:
        assert second == [C.at(START, 60)], second
    else:
        assert second[0] >= first[0], f"lesson time went backwards: {first} -> {second}"


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


def _channel_stamps(run_dir: Path, channel: str) -> list[dt.datetime | None]:
    """Read denial timestamps or persisted host-state capture timestamps in call order."""
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


@pytest.mark.parametrize(("channel", "steps"), [
    pytest.param("denials", (20, 30), id="denials-forward"),
    pytest.param("denials", (-3600, 20, -3600), id="denials-step-back"),
    pytest.param("capture", (-3600, 20, -3600), id="captures-step-back"),
])
def test_channel_stamps_follow_the_run_clock(tmp_path, monkeypatch, channel, steps):
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
        calls = [C.query("elastic", "esql")] * len(steps)
    else:
        from defender.tests.test_947_clock import DOCKER_LOG, fake_docker

        monkeypatch.setenv("PATH", f"{fake_docker(tmp_path)}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("DOCKER_CALL_LOG", str(tmp_path / DOCKER_LOG))
        system = "host-state"
        calls = [C.query("host-state", verb, params) for verb, params in STAMPING_VERBS[:3]]
    main = C.script(clock, (10, C.read_lesson(L1)), (0, C.gather_turn("l-001", system)),
                    (0, C.DONE))
    gather = C.script(clock, *zip(steps, calls, strict=True),
                      (0, C.H.Turn(text="Summary: measured the lead.")))

    C.drive_clocked(run_dir, clock=clock, main=main, gather=gather, **kw)

    lesson = C.lesson_reads(run_dir, L1)
    assert lesson == [C.at(START, 10)], (
        f"positive control: the lessons row is not the run clock's reading (START+10): {lesson}")
    stamps = _channel_stamps(run_dir, channel)
    assert len(stamps) == len(steps), f"{len(steps)} {channel} calls left {len(stamps)} stamps"
    if steps == (20, 30):
        assert stamps == [C.at(START, 30), C.at(START, 60)], stamps
    assert None not in stamps, f"a {channel} stamp does not read as a time: {stamps}"
    seen = [*lesson, *stamps]
    assert seen == sorted(seen), (
        f"a visible time ran backwards across the lessons log and the {channel} channel: the "
        f"model was shown, in order, {[s.isoformat() for s in seen]}")


@pytest.mark.parametrize(("advance", "refused"), [(601, True), (599, False)],
                         ids=["past-the-limit", "inside-the-limit"])
def test_n4_the_wall_clock_limb_measures_the_run_clock(tmp_path, enforced, advance, refused):
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


_MEASURED = re.compile(r"wall_clock at (\d+)s/")


def _measured_elapsed(caplog: pytest.LogCaptureFixture) -> list[int]:
    return [int(n) for r in caplog.records for n in _MEASURED.findall(r.getMessage())]


@pytest.mark.parametrize("case", ["after-limit", "before-limit"])
def test_the_wall_clock_limb_never_shrinks_when_the_source_steps_back(
        tmp_path, enforced, caplog, case):
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
