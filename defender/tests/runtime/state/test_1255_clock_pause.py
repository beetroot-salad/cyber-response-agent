"""Oracle work and rate-limit waits pause the investigator clock."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.runtime.state import _1255_clock as C
from defender.tests.e2e._replay_harness import GOLDEN_AB3, materialize
from defender.tests.learning.oracle.live_contracts import _spec1224 as S

pytestmark = pytest.mark.e2e

START = C.SOURCE_START
L1 = C.LESSONS[0]
ALICE = S.query_params("user:alice")
EMPTY: dict = {"rows": []}
WORLD_SECONDS = 900
LIMITS = C.caps(wall_clock_timeout=600, grace_seconds=600, max_tool_calls=50)


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate configured roots and enable the real unboxed executor."""
    monkeypatch.setenv(S.T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv(S.KNOB_RATE, "1e6")
    monkeypatch.setenv(C.FLAG, "true")


class WorldTakesTime(S.ScriptedModel):
    """Oracle model that advances the source clock to simulate a slow provider."""

    def __init__(self, *moves: Any, clock: C.FakeClock, seconds: float, then: Any = None) -> None:
        super().__init__(*moves, then=then, name="oracle")
        self.clock, self.seconds = clock, seconds

    def __call__(self, messages: list[Any], info: Any) -> Any:
        self.clock.advance(self.seconds)
        return super().__call__(messages, info)


class WaitingLimiter:
    """Rate limiter whose wait advances the source clock instead of sleeping."""

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
    """Dispatch an idp lead, read a lesson, then call bash to observe elapsed time."""
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
    """World `b` (a fact) of an episode whose recording holds ALICE's answer: ALICE takes an oracle turn."""
    est = S.estate(tmp_path)
    ep = S.episode_v2(tmp_path, base_rows=[S.captured("idp", "query", ALICE, EMPTY)])
    return est, S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                                 retry_cap=3, **knobs)


def _bash_refused(main: C.Clocked) -> bool:
    assert len(main.seen) >= 4, f"MAIN stopped before its bash call was answered: {main.seen}"
    return C.refusal_stem() in main.seen[3]


def test_p1_an_oracle_turn_moves_no_visible_time_and_no_elapsed_time(tmp_path):
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
    clock = C.FakeClock(START)
    oracle = WorldTakesTime(S.submit(EMPTY, S.EMPTY_CLAIM), clock=clock, seconds=0,
                            then=S.submit(EMPTY, S.EMPTY_CLAIM))
    est, reg = _counterfactual(tmp_path, clock, oracle)

    run_dir, main = _drive(tmp_path, clock, reg, est, lead_seconds=20 + WORLD_SECONDS)

    assert C.lesson_reads(run_dir, L1) == [C.at(START, 35 + WORLD_SECONDS)], (
        f"the investigator's own seconds did not reach the visible time: {C.lesson_rows(run_dir)}")
    assert _bash_refused(main), "935 s of investigator time against a 600 s limit refused nothing"
    assert "wall-clock" in main.seen[3], "935 s of investigator time against a 600 s limit refused nothing"


def test_p2_a_rate_limit_wait_moves_no_visible_time_and_no_elapsed_time(tmp_path):
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
