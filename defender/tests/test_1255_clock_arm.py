"""Forked runs continue the source clock and elapsed budget."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

from defender import _clock
from defender._io import read_jsonl_rows
from defender.tests import _1255_clock as C
from defender.tests import _triplet_947 as T
from defender.tests.live_oracle_1224 import _spec1224 as S

pytestmark = pytest.mark.e2e

START = C.SOURCE_START
L1, L2, L3 = C.LESSONS
R = C.BRANCH_READING


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The configured episodes root, the learning state inside `tmp_path`, and production's unboxed mode (the box start finds no daemon and the operator opt-out takes it)."""
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")


def launch_arm(tmp_path: Path, tenant_id: str, source: Path, *steps: C.Step,  # noqa: PLR0913 — the arm's seams, one keyword each
               clock: C.FakeClock, limits: dict | None = None, gather: Any = None,
               oracle: Any = None, verifier: Any = None) -> tuple[C.Launched, C.Clocked]:
    """Launch a recorded source at its L2 read, with scripted clocked main and gather models."""
    branch = C.branch_response(source, tool="read_file", arg_suffix=f"/{L2}.md")
    ep = C.control_episode(tmp_path, source, branch)
    main = C.Clocked(clock, steps)
    out = C.run_main(C.arm_argv(tenant_id, ep.name, "a"), clock=clock, main=main, gather=gather,
                     limits=limits, oracle=oracle, verifier=verifier)
    return out, main


def _launched(out: C.Launched) -> None:
    """The arm ran its investigation (it was not refused at launch or at store setup)."""
    assert out.exit == 0, f"the arm did not run: exit={out.exit} refusal={out.refusal} summary={out.summary}"
    assert out.summary is not None, f"the arm did not run: exit={out.exit} refusal={out.refusal} summary={out.summary}"
    assert out.summary.get("truncated_by") != "store", (
        "the arm ended at store setup — today `branch.validate` refuses a branch point at a "
        f"response whose calls are unanswered (D1 flips it): {out.summary}")


def test_a1_an_arms_visible_times_start_at_the_sources_reading_at_the_branch_point(tmp_path):
    tenant_id, source = C.record_source(tmp_path)
    arm_clock = C.FakeClock(C.ARM_START)
    out, main = launch_arm(tmp_path, tenant_id, source,
                           (20, C.read_lesson(L3)), (5, C.DONE), clock=arm_clock)

    _launched(out)
    arm_dir = out.run_dir
    assert C.lesson_reads(arm_dir, L1) == [C.FIRST_READ_READING], (
        "the arm's lessons log does not hold the source's pre-cut L1 read at its own time "
        f"({C.FIRST_READ_READING}): {C.lesson_rows(arm_dir)}")
    assert C.lesson_reads(arm_dir, L2) == [R], (
        "the arm's lessons log does not hold exactly one L2 read, the re-run dangling call "
        f"stamped with the source's reading at the branch point ({R}): {C.lesson_rows(arm_dir)}")
    assert C.lesson_reads(arm_dir, L3) == [C.at(R, 20)], (
        "the arm's next visible time is not the branch point's reading plus the arm's own 20 s "
        f"({C.at(R, 20)}): {C.lesson_rows(arm_dir)}")
    stamps = [C.instant(r.get("ts")) for r in C.lesson_rows(arm_dir)]
    assert all(s is not None for s in stamps), f"a row carries no readable time: {stamps}"
    assert stamps == sorted(stamps), (
        f"a visible time in the arm runs earlier than one its history already holds: {stamps}")
    assert all(s < C.ARM_START for s in stamps), (
        f"the arm shows its own clock source's absolute time: {stamps}")


@pytest.mark.parametrize(("arm_seconds", "arm_timeout", "refused"),
                         [(300, 900, True), (200, 900, False), (300, 3600, True)],
                         ids=["past-the-sources-limit", "inside-the-sources-limit",
                              "configured-longer-still-the-sources-limit"])
def test_a2_an_arm_reaches_the_wall_clock_limit_where_its_source_would_have(
        tmp_path, monkeypatch, arm_seconds, arm_timeout, refused):
    monkeypatch.setenv(C.FLAG, "true")
    limits = C.caps(wall_clock_timeout=900, grace_seconds=600, max_tool_calls=50)
    arm_limits = C.caps(wall_clock_timeout=arm_timeout, grace_seconds=600, max_tool_calls=50)
    tenant_id, source = C.record_source(tmp_path, limits=limits)
    out, main = launch_arm(tmp_path, tenant_id, source,
                           (arm_seconds, C.bash("echo arm-call-ran")), (0, C.DONE),
                           clock=C.FakeClock(C.ARM_START), limits=arm_limits)

    _launched(out)
    assert len(main.seen) >= 2, f"the arm stopped before its bash call was answered: {main.seen}"
    shown = main.seen[1]
    if refused:
        assert C.refusal_stem() in shown, (f"610 s at the fork + {arm_seconds} s in the arm passes a 900 s limit and nothing "
            "was refused — the arm's clock or its budget origin restarted at the fork")
        assert "wall-clock" in shown, (f"610 s at the fork + {arm_seconds} s in the arm passes a 900 s limit and nothing "
            "was refused — the arm's clock or its budget origin restarted at the fork")
        assert "arm-call-ran" not in shown, "the refused call ran anyway"
    else:
        assert C.refusal_stem() not in shown, (
            f"610 s + {arm_seconds} s is inside a 900 s limit and the arm was refused")
        assert "arm-call-ran" in shown, "the call inside the limit did not run"


DENIED = ("ticket", "get-ticket")


def _summary(text: str = "Summary: measured the lead.") -> Any:
    return C.H.Turn(text=text)


def test_a3_an_arms_denial_log_continues_from_the_sources_reading_at_the_branch_point(tmp_path):
    tenant_id, source = C.record_source(tmp_path)
    arm_clock = C.FakeClock(C.ARM_START)
    system, verb = DENIED
    gather = C.script(arm_clock, (10, C.query(system, verb, {"key": "T-1"})), (0, _summary()))
    out, _main = launch_arm(tmp_path, tenant_id, source,
                            (20, C.gather_turn("l-002", system)), (0, C.DONE),
                            clock=arm_clock, gather=gather)

    _launched(out)
    rows = [r for r in C.denial_rows(out.run_dir) if r.get("verb") == verb]
    assert len(rows) == 1, (
        f"one denied call in the arm, one denial row; got {C.denial_rows(out.run_dir)}")
    assert [C.instant(r.get("ts")) for r in rows] == [C.at(R, 30)], (
        "the arm's denial row is not stamped with the branch point's reading plus the arm's own "
        f"30 s ({C.at(R, 30)}): {rows}")


def _new_host_state_question(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                             ) -> tuple[C.Launched, S.ScriptedModel, Path]:
    """Launch an arm whose host-state question needs a new oracle answer."""
    from defender.tests.test_947_clock import DOCKER_LOG, fake_docker

    monkeypatch.setenv(S.KNOB_RATE, "1e6")
    tenant_id, source = C.record_source(tmp_path)
    time.sleep(1.1)
    monkeypatch.setenv("PATH", f"{fake_docker(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("DOCKER_CALL_LOG", str(tmp_path / DOCKER_LOG))
    base_handle = S.sym("learning.branch.estate.oracle", "BASE_HANDLE")
    oracle = S.oracle(then=S.submit(base_handle, S.EMPTY_CLAIM))
    arm_clock = C.FakeClock(C.ARM_START)
    gather = C.script(arm_clock, (10, C.query("host-state", "proc-tree", {"host": "web-1"})),
                      (0, _summary("Summary: captured the process tree.")))
    out, _main = launch_arm(tmp_path, tenant_id, source,
                            (20, C.gather_turn("l-002", "host-state")), (0, C.DONE),
                            clock=arm_clock, gather=gather, oracle=oracle.model,
                            verifier=S.passing_verifier().model)
    _launched(out)
    return out, oracle, source


def test_a4_an_arms_host_state_capture_is_stamped_with_its_run_clock(tmp_path, monkeypatch):
    out, oracle, _source = _new_host_state_question(tmp_path, monkeypatch)

    rows = [r for r in read_jsonl_rows(out.run_dir / "executed_queries.jsonl")
            if r.get("lead_id") == "l-002" and r.get("verb") == "proc-tree"]
    assert len(rows) == 1, f"the arm's host-state question was not served to its lead: {rows}"
    assert rows[0].get("exit_code") == 0, f"the arm's host-state question was not served to its lead: {rows}"
    assert rows[0].get("payload_path"), f"the arm's host-state question was not served to its lead: {rows}"
    assert oracle.submissions() == 1, (
        f"the control world's new question took {oracle.submissions()} oracle turns (D3: one)")
    payload = json.loads((out.run_dir / rows[0]["payload_path"]).read_text(encoding="utf-8"))
    assert payload.get("captured_at") == _clock.z_seconds(C.at(R, 30)), (
        "the arm's host-state capture is not stamped with its run clock's reading at the call "
        f"({_clock.z_seconds(C.at(R, 30))}): {payload.get('captured_at')!r}")


def test_a5_the_oracle_is_handed_the_snapshots_run_clock_reading_as_the_fork_time(
        tmp_path, monkeypatch):
    out, oracle, source = _new_host_state_question(tmp_path, monkeypatch)

    assert oracle.requests >= 1, "the control world's oracle was never consulted (D3)"
    shown = oracle.all_seen()
    assert C.mentions(shown, R), (
        f"the oracle was not handed the snapshot's run-clock reading {R} as the fork time")
    framework_times = C.source_message_times(source)
    assert framework_times, "the source's messages carry no timestamps; the check below is empty"
    leaked = [t for t in framework_times if C.mentions(shown, t)]
    assert not leaked, (
        "the oracle was handed a fork time taken from the source's message timestamps (the "
        f"wall clock) rather than the run clock: {leaked}")
