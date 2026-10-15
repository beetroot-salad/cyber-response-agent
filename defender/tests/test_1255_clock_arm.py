"""#1255 slice D — an arm's run clock starts at its source's reading at the branch point.

Design rev 4, "Time" and "Fork snapshot": the run clock is host-owned; "on an arm it starts at
the source's reading in the fork snapshot" (the snapshot is taken when the branch response
arrives, before any of its tool calls run), and from there advances by what the arm's own clock
source advances while the arm does work. O4: "Time must be consistent, not equal. Every time the
model can see agrees with every other one and never runs earlier than the history's last
timestamp." D2: "an arm hits its limits where the source would have, not with a fresh budget" —
for the wall-clock limit, that is the source's elapsed time at the fork plus the arm's own.

Composition (dossier, FIXED): the source is a natural `run.main([alert, --tenant T])` run and the
arm is `run.main([--tenant T, --episode E, --world a])`, both through
`lifecycle=partial(run._run_investigation_lifecycle, investigate=partial(run._drive_investigation,
investigate=<driver call with clock=>), …)`. The episode is the control world, laid out as the
sibling suites lay one out, its derived half the launcher's own derivation (`_1255_clock`).

The scenario, in source-clock seconds from `SOURCE_START`:
  * source (`_1255_clock.record_source`): MAIN dispatches one lead at +5 (one elastic query
    reaching the system, so the source is branchable), reads L1 at +10; its next response (at
    +610) calls `read_file(L2)` — the branch point B (D1: a tool-calling MAIN response); then it
    stops at +615.
  * arm: its own clock source starts at `ARM_START` (2040, nowhere near the source's). It
    resumes at B with no new message (D1), so `read_file(L2)` runs again first, before any arm
    model request; the arm's first model request then takes 20 s and reads L3.
Expected, the test's own sums: the arm's L2 read at `R = SOURCE_START+610`, its L3 read at
`R+20`. One equality rejects every wrong origin at once: reading the arm's own source gives
2040; starting at a fork time taken from the framework's message timestamps gives the wall
clock's day; starting fresh gives the arm's launch wall time.

Rev 5 C4: "the fork time handed to the oracle and the arm's cut-off (`as_of`) are the
snapshot's run-clock reading" — on this faked clock, `R`, never a framework message's wall
timestamp. A3–A5 carry the arm's time onto the channels beyond the lessons log: the denials
log, a host-state capture served through the control world's oracle path (D3, D6), and the
fork time the oracle is handed.

RED until (a) `run_investigation` accepts `clock=`, (b) slice A's branch point (a tool-calling
response is admitted; today `branch.validate` refuses it, and the arm ends at store setup) and
fork snapshot exist; A4/A5 also await slice C's D3 (the control world's new question takes an
oracle turn). Those assertion groups are named in each test.
"""
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
#: The source clock's reading when the branch response arrived: 10 s, then 600 s of MAIN work.
R = C.BRANCH_READING


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The configured episodes root, the learning state inside `tmp_path`, and production's
    unboxed mode (the box start finds no daemon and the operator opt-out takes it)."""
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")


def launch_arm(tmp_path: Path, tenant_id: str, source: Path, *steps: C.Step,  # noqa: PLR0913 — the arm's seams, one keyword each
               clock: C.FakeClock, limits: dict | None = None, gather: Any = None,
               oracle: Any = None, verifier: Any = None) -> tuple[C.Launched, C.Clocked]:
    """Fork the control world at B (the response that called `read_file(L2)`) and run the arm
    through `run.main --episode`, its MAIN scripted by `steps` over the arm's own `clock`
    (`gather`, `oracle`, `verifier`: the arm's gather double and the world's oracle-side model
    doubles, `run.main`'s own seams)."""
    branch = C.branch_response(source, tool="read_file", arg_suffix=f"/{L2}.md")
    ep = C.control_episode(tmp_path, source, branch)
    main = C.Clocked(clock, steps)
    out = C.run_main(C.arm_argv(tenant_id, ep.name, "a"), clock=clock, main=main, gather=gather,
                     limits=limits, oracle=oracle, verifier=verifier)
    return out, main


def _launched(out: C.Launched) -> None:
    """The arm ran its investigation (it was not refused at launch or at store setup)."""
    assert out.exit == 0 and out.summary is not None, (
        f"the arm did not run: exit={out.exit} refusal={out.refusal} summary={out.summary}")
    assert out.summary.get("truncated_by") != "store", (
        "the arm ended at store setup — today `branch.validate` refuses a branch point at a "
        f"response whose calls are unanswered (D1 flips it): {out.summary}")


def test_a1_an_arms_visible_times_start_at_the_sources_reading_at_the_branch_point(tmp_path):
    """O4 / Time / P2: the arm's first visible time is `R` — the source's run-clock reading
    when the branch response arrived — and its next is `R` plus the arm's own 20 s; never its
    own source's absolute reading, never earlier than anything the arm's history holds.

    Channel: the arm's lessons log (model-readable). The re-run `read_file(L2)` stamps `R`
    (no arm model request has run yet); the arm's L3 read stamps `R+20`. Exactly ONE L2 row:
    the source's own L2 read ran after the cut and is ALSO stamped `R`, so an arm that copied
    the source's whole log would show two (R1-2). Positive control on the same channel: the
    inherited L1 row (before the cut, `START+10`) is there, so the ordering check below compares
    across the cut. O4's ordering: the whole log the arm can read — the inherited prefix (slice
    A restores it to the cut) followed by the arm's own rows — never runs backwards, and no row
    names a time at or after the arm source's `ARM_START`.

    Awaiting: `clock=` (all), A's branch point (the arm launching at all)."""
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
    """D2 + Time: with a 900 s wall-clock limit, the source had used 610 s of run-clock time at
    the branch point. An arm whose first turn takes `arm_seconds` before a `bash` call is
    refused — shown the budget refusal naming `wall-clock` — exactly when 610 + `arm_seconds`
    passes 900 (300 s: 910, refused; 200 s: 810, runs). Today an arm's budget starts fresh, so
    300 s refuses nothing.

    C3 (limits are inherited: "the arm runs under the source's caps (recorded in the
    snapshot), not caps re-read from the arm's own configuration"): the third case configures
    the ARM with `wall_clock_timeout=3600` (the driver's `limits=` seam, how a run is handed
    its caps) and it is still refused at 910 s — the source's 900 s cap governs.

    The cases are each other's control on the same channel (the second shows the call's own
    output reaching the model). Awaiting: `clock=`, A's branch point and snapshot restore."""
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
        assert C.refusal_stem() in shown and "wall-clock" in shown, (
            f"610 s at the fork + {arm_seconds} s in the arm passes a 900 s limit and nothing "
            "was refused — the arm's clock or its budget origin restarted at the fork")
        assert "arm-call-ran" not in shown, "the refused call ran anyway"
    else:
        assert C.refusal_stem() not in shown, (
            f"610 s + {arm_seconds} s is inside a 900 s limit and the arm was refused")
        assert "arm-call-ran" in shown, "the call inside the limit did not run"


# ---------------------------------------------------------------------------------------
# A3–A5 — the arm's time on the channels beyond the lessons log (R1-5)
# ---------------------------------------------------------------------------------------

#: A pair the fixture tenant's grant withholds from gather (`verb-grants.yaml`: `roles: []`).
DENIED = ("ticket", "get-ticket")


def _summary(text: str = "Summary: measured the lead.") -> Any:
    return C.H.Turn(text=text)


def test_a3_an_arms_denial_log_continues_from_the_sources_reading_at_the_branch_point(tmp_path):
    """O4 / Time / P2, on the denials log: the arm's first model request takes 20 s and
    dispatches a lead whose model takes 10 s before calling a verb its grant withholds
    (`ticket.get-ticket`). The `policy_denials.jsonl` row carries `R+30` — the source's reading
    at the branch point plus the arm's own seconds — not the arm source's 2040 time and not the
    wall clock.

    Positive control on the same channel: exactly one row for the denied verb (the source made
    no denied call, so none is inherited). Awaiting: `clock=`, A's branch point."""
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
    """The arm asks the control world a host-state question the source never asked: its first
    model request takes 20 s and dispatches lead `l-002`, whose model takes 10 s before calling
    `host-state.proc-tree`. The world's base for it is a live read (D6) — the real adapter body
    over a `docker` planted on the run's PATH, as `test_947_clock` drives it — served through
    the control world's oracle path (D3) by a PASS-THROUGH oracle double: it submits the base
    unchanged (`BASE_HANDLE`, the oracle's own "serve the base answer unchanged" spelling) with
    an empty claim, and the verifier passes. Neither double moves the clock. Returns the arm,
    the oracle double and the source run folder."""
    from defender.tests.test_947_clock import DOCKER_LOG, fake_docker

    monkeypatch.setenv(S.KNOB_RATE, "1e6")
    tenant_id, source = C.record_source(tmp_path)
    # Real time, not run-clock time: every wall second the arm can stamp is then later than
    # every second the framework stamped on the source's messages, so A5's negative cannot
    # match a wall time the arm hands the oracle for some other reason.
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
    """Time ("capture stamps use the run clock") on an ARM — slice D's N3 where the control
    world serves: the `proc-tree` capture the arm's lead is handed carries
    `captured_at == R + 30` (`Z` seconds) — the source's reading at the branch point plus the
    arm's own 20 + 10 s. Not the cut-off (`as_of`), not the arm source's 2040, not the wall.

    Positive controls on the same call: the capture is a served row of the lead (exit 0, a
    persisted payload) and it went through the control world's oracle — one submission (D3;
    the pass-through double changes nothing, so the stamp is the base read's own). Awaiting:
    `clock=`, A's branch point, C's D3."""
    out, oracle, _source = _new_host_state_question(tmp_path, monkeypatch)

    rows = [r for r in read_jsonl_rows(out.run_dir / "executed_queries.jsonl")
            if r.get("lead_id") == "l-002" and r.get("verb") == "proc-tree"]
    assert len(rows) == 1 and rows[0].get("exit_code") == 0 and rows[0].get("payload_path"), (
        f"the arm's host-state question was not served to its lead: {rows}")
    assert oracle.submissions() == 1, (
        f"the control world's new question took {oracle.submissions()} oracle turns (D3: one)")
    payload = json.loads((out.run_dir / rows[0]["payload_path"]).read_text(encoding="utf-8"))
    assert payload.get("captured_at") == _clock.z_seconds(C.at(R, 30)), (
        "the arm's host-state capture is not stamped with its run clock's reading at the call "
        f"({_clock.z_seconds(C.at(R, 30))}): {payload.get('captured_at')!r}")


def test_a5_the_oracle_is_handed_the_snapshots_run_clock_reading_as_the_fork_time(
        tmp_path, monkeypatch):
    """C4: "the fork time handed to the oracle … [is] the snapshot's run-clock reading". On this
    faked clock that is `R` (`SOURCE_START+610`): what the control world's oracle is shown
    names `R`, and names none of the timestamps the framework stamped on the source's messages
    (wall times, today's derivation of the branch-point clock). Spelling-free: the whole-second
    date-time is matched, whatever zone suffix follows it.

    Positive controls: the oracle was consulted (D3) and the source does carry framework
    timestamps (so the negative has values to reject). Awaiting: `clock=`, A's branch point,
    C's D3."""
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
