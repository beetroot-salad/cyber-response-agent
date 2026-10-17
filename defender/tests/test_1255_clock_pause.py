"""#1255 slice D — the run clock pauses while the world, not the run, is working.

Design rev 4, "Time": the run clock "advances only while the run does work a natural run would
also do; it pauses during oracle turns and branch rate-limit waits, as today's elapsed-time
accounting already pauses for oracle turns. Every time the model can see comes from it". So an
oracle turn and a rate-limit wait leave NO trace in any time the model can see, and none in
the budget's elapsed measure — while the same seconds spent by the investigator itself count in
full.

Today's code already pauses the BUDGET for an oracle turn (`budget_enforcer.oracle_held`,
#1224 S12-S15, `test_1224_concurrency_and_clock.py` — real sleeps, real elapsed). What is new
here is that the pause is a pause of the ONE clock: the times the model is shown move with it.

Drive shape: the REGISTRY drive #1224's clock tests use — a natural-shaped run through the real
driver whose verb registry is a real `WorldRegistry` (the oracle and verifier doubles injected
through its coined seams, `_spec1224.world_registry`) — plus `clock=`. The oracle double is a
`ScriptedModel` that advances the run clock's SOURCE while it holds the turn (the world took
that long); the limiter's injected `sleep` does the same for a rate-limit wait. The visible
channel is MAIN's lessons-log row after the lead returns; the budget channel is a `bash` call
under a 600 s limit.

Every expected instant is the test's own sum of the INVESTIGATOR's advances. RED until
`run_investigation` accepts `clock=` (class a); see the report for the no-clock scratch runs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender.tests import _1255_clock as C
from defender.tests.e2e._replay_harness import GOLDEN_AB3, materialize
from defender.tests.live_oracle_1224 import _spec1224 as S

pytestmark = pytest.mark.e2e

START = C.SOURCE_START
L1 = C.LESSONS[0]
ALICE = S.query_params("user:alice")
EMPTY: dict = {"rows": []}
#: What the world takes, in run-clock-source seconds: more than the whole 600 s limit, so a
#: clock that counted it would refuse the next call.
WORLD_SECONDS = 900
LIMITS = C.caps(wall_clock_timeout=600, grace_seconds=600, max_tool_calls=50)


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#1224's configured roots (`live_oracle_1224/conftest.py`), and the enforcing posture."""
    monkeypatch.setenv(S.T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv(S.KNOB_RATE, "1e6")
    monkeypatch.setenv(C.FLAG, "true")


class WorldTakesTime(S.ScriptedModel):
    """An oracle double that holds its turn for `seconds` of the run clock's SOURCE time on
    every request (a slow provider): it advances the source, then answers its script."""

    def __init__(self, *moves: Any, clock: C.FakeClock, seconds: float, then: Any = None) -> None:
        super().__init__(*moves, then=then, name="oracle")
        self.clock, self.seconds = clock, seconds

    def __call__(self, messages: list[Any], info: Any) -> Any:
        self.clock.advance(self.seconds)
        return super().__call__(messages, info)


class WaitingLimiter:
    """The rate limiter's two injected primitives: a monotonic reading that moves only when
    the limiter sleeps, and a `sleep` that records the wait and advances the run clock's source
    by `seconds` (the wait took that long in the world)."""

    def __init__(self, clock: C.FakeClock, seconds: float) -> None:
        self.clock, self.seconds = clock, seconds
        self.mono = 0.0
        self.waits: list[float] = []

    def now(self) -> float:
        return self.mono

    def sleep(self, wait: float) -> None:
        self.waits.append(wait)
        self.mono += wait
        self.clock.advance(self.seconds)


def _drive(tmp_path: Path, clock: C.FakeClock, registry: Any, est: Any, *,
           lead_seconds: float = 20, params: dict = ALICE) -> tuple[Path, C.Clocked]:
    """MAIN dispatches one `idp` lead after 10 s; the lead asks `params` after `lead_seconds`;
    MAIN then reads L1 after 5 s and runs one `bash` call. Returns the run dir and MAIN."""
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id="run-1255-pause")
    main = C.script(clock, (10, C.gather_turn("l-001", "idp")), (5, C.read_lesson(L1)),
                    (0, C.bash("echo after-the-lead")), (0, C.DONE))
    gather = C.script(clock, (lead_seconds, C.query("idp", "query", params)),
                      (0, C.H.Turn(text="Summary: measured the lead.")))
    C.drive_clocked(run_dir, clock=clock, main=main, gather=gather, verbs=registry,
                    tenant=est.place(), limits=LIMITS)
    return run_dir, main


def _counterfactual(tmp_path: Path, clock: C.FakeClock, oracle: S.ScriptedModel,
                    **knobs: Any) -> tuple[Any, Any]:
    """World `b` (a fact) of an episode whose recording holds ALICE's answer: ALICE takes an
    oracle turn."""
    est = S.estate(tmp_path)
    ep = S.episode_v2(tmp_path, base_rows=[S.captured("idp", "query", ALICE, EMPTY)])
    return est, S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                                 retry_cap=3, **knobs)


def _bash_refused(main: C.Clocked) -> bool:
    assert len(main.seen) >= 4, f"MAIN stopped before its bash call was answered: {main.seen}"
    return C.refusal_stem() in main.seen[3]


def test_p1_an_oracle_turn_moves_no_visible_time_and_no_elapsed_time(tmp_path):
    """Time: the run clock pauses for an oracle turn. The lead's call holds a 900 s oracle turn;
    afterwards MAIN's lessons-log row reads `START + 10 + 20 + 5` — the investigator's own
    seconds only — and its `bash` call under a 600 s limit is not refused.

    Positive controls on the same run: the oracle took exactly one turn and really advanced the
    source by 900 s (so the source DID move under the run). The complementary case —
    the investigator spending those 900 s itself — is `test_p1_control_…`."""
    clock = C.FakeClock(START)
    oracle = WorldTakesTime(S.submit(EMPTY, S.EMPTY_CLAIM), clock=clock, seconds=WORLD_SECONDS,
                            then=S.submit(EMPTY, S.EMPTY_CLAIM))
    est, reg = _counterfactual(tmp_path, clock, oracle)

    run_dir, main = _drive(tmp_path, clock, reg, est)

    assert oracle.submissions() == 1, f"the lead's call took {oracle.submissions()} oracle turns"
    assert WORLD_SECONDS in clock.advances, "the oracle turn never moved the source"
    assert C.lesson_reads(run_dir, L1) == [C.at(START, 35)], (
        "the time MAIN was shown after the lead includes the oracle turn — expected START+35s "
        f"(investigator seconds only), rows: {C.lesson_rows(run_dir)}")
    assert not _bash_refused(main), "the oracle turn's 900 s counted against a 600 s limit"


def test_p1_control_the_investigators_own_seconds_count_in_full(tmp_path):
    """Positive control for P1 on both channels: the same 900 s spent by the INVESTIGATOR (its
    lead's model took that long before the call) show up in MAIN's lessons-log row
    (`START + 10 + 920 + 5`) and refuse the `bash` call past the 600 s limit, naming the
    wall-clock limb. The oracle here takes no time."""
    clock = C.FakeClock(START)
    oracle = WorldTakesTime(S.submit(EMPTY, S.EMPTY_CLAIM), clock=clock, seconds=0,
                            then=S.submit(EMPTY, S.EMPTY_CLAIM))
    est, reg = _counterfactual(tmp_path, clock, oracle)

    run_dir, main = _drive(tmp_path, clock, reg, est, lead_seconds=20 + WORLD_SECONDS)

    assert C.lesson_reads(run_dir, L1) == [C.at(START, 35 + WORLD_SECONDS)], (
        f"the investigator's own seconds did not reach the visible time: {C.lesson_rows(run_dir)}")
    assert _bash_refused(main) and "wall-clock" in main.seen[3], (
        "935 s of investigator time against a 600 s limit refused nothing")


def test_p2_a_rate_limit_wait_moves_no_visible_time_and_no_elapsed_time(tmp_path):
    """Time: the run clock pauses for a branch rate-limit wait. The oracle explores twice
    through a one-query-a-second limiter whose wait takes 900 s of source time; afterwards
    MAIN's row still reads `START+35` and its `bash` call is not refused.

    Positive control: the limiter really waited (and so really advanced the source). Today
    the only limiter waits on this path sit inside an oracle turn; the assertion is over the
    observable, so it holds wherever an implementation puts a wait."""
    clock = C.FakeClock(START)
    waiting = WaitingLimiter(clock, WORLD_SECONDS)
    limiter = S.sym("learning.branch.estate.limiter", "RateLimiter")(
        1.0, clock=waiting.now, sleep=waiting.sleep)
    oracle = WorldTakesTime(S.run_query("idp", "query", S.query_params("probe-1")),
                            S.run_query("idp", "query", S.query_params("probe-2")),
                            S.submit(EMPTY, S.EMPTY_CLAIM), clock=clock, seconds=0,
                            then=S.submit(EMPTY, S.EMPTY_CLAIM))
    est, reg = _counterfactual(tmp_path, clock, oracle, limiter=limiter)
    est.answer("idp", "query", None, EMPTY)

    run_dir, main = _drive(tmp_path, clock, reg, est)

    assert waiting.waits, "the limiter never waited, so nothing below is about a wait"
    assert C.lesson_reads(run_dir, L1) == [C.at(START, 35)], (
        "the time MAIN was shown includes a rate-limit wait — expected START+35s, rows: "
        f"{C.lesson_rows(run_dir)}")
    assert not _bash_refused(main), "a 900 s rate-limit wait counted against a 600 s limit"


def test_p3_the_control_worlds_oracle_turn_also_moves_no_visible_time(tmp_path):
    """Time + D3: in the CONTROL world a question the source never asked takes an oracle turn
    (D3), and that turn, like every oracle turn, is invisible on the run clock: MAIN's row reads
    `START+35` and the `bash` call is not refused.

    Positive control: the control world's oracle took exactly one turn and advanced the source
    (today the control world passes a live read straight through and takes none — that
    assertion is the one today's code fails; the world-serving half of D3 is slice C's)."""
    clock = C.FakeClock(START)
    oracle = WorldTakesTime(S.submit(EMPTY, S.EMPTY_CLAIM), clock=clock, seconds=WORLD_SECONDS,
                            then=S.submit(EMPTY, S.EMPTY_CLAIM))
    est = S.estate(tmp_path)
    est.answer("idp", "query", None, EMPTY)
    ep = S.episode_v2(tmp_path, base_rows=[S.captured("idp", "query", ALICE, EMPTY)])
    reg = S.world_registry(ep, "a", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=3)
    new_question = S.query_params("user:never-asked")

    run_dir, main = _drive(tmp_path, clock, reg, est, params=new_question)

    assert oracle.submissions() == 1, (
        f"the control world's new question took {oracle.submissions()} oracle turns (D3: one)")
    assert C.lesson_reads(run_dir, L1) == [C.at(START, 35)], (
        f"the control world's oracle turn reached the visible time: {C.lesson_rows(run_dir)}")
    assert not _bash_refused(main), "the control world's oracle turn counted against the limit"
