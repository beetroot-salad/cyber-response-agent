"""#1235: the run's budget counters and circuit breaker live in the run process's memory. Overwriting or deleting a state file in a live run's folder changes no host decision (call cap, tripped system, wall clock); driven through the real driver with the plant made from the scripted model's own turn."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.hooks.budget_enforcer import (  # noqa: E402
    BUDGET_REFUSAL_MESSAGE,
    DEFAULT_LIMITS,
)
from defender.scripts.adapters.faults import TransportFault  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import DONE, q  # noqa: E402

pytestmark = pytest.mark.e2e

FLAG = "DEFENDER_BUDGET_ENFORCE"
LEAD = "l-001"
BUDGET_FILE = "budget.json"
BREAKER_FILE = "circuit_breaker.json"


@pytest.fixture
def enforced(monkeypatch):
    """The enforcing posture, set the way production sets it: the real environment variable."""
    monkeypatch.setenv(FLAG, "true")


def _refusal_stem() -> str:
    """The literal lead-in of the budget refusal, guarded non-empty so a count of it can never
    pass vacuously on an empty needle."""
    stem = BUDGET_REFUSAL_MESSAGE.split("{", 1)[0].strip()
    assert stem, "BUDGET_REFUSAL_MESSAGE opens with a placeholder; its stem is empty"
    return stem


def _refusals(replay: ReplayFn) -> int:
    """How many tool results in the model's final history carried the budget refusal."""
    return replay.seen[-1].count(_refusal_stem())


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class PlantingReplay(ReplayFn):
    """A scripted model that, when it is asked for turn `at` (0-based), first does `plant()` to
    the run folder — in this process, inside the live run, after the driver opened it."""

    def __init__(self, turns: list[Turn], *, at: int, plant) -> None:
        super().__init__(turns)
        self._at, self._plant = at, plant
        self.planted = False

    def __call__(self, messages, info):  # noqa: ANN001 — the FunctionModel callable protocol
        if self.calls == self._at:
            self._plant()
            self.planted = True
        return super().__call__(messages, info)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


_FOUR_BASH = [
    Turn(tool_calls=[("bash", {"command": "echo ran-one"})]),
    Turn(tool_calls=[("bash", {"command": "echo ran-two"})]),
    Turn(tool_calls=[("bash", {"command": "echo ran-three"})]),
    Turn(tool_calls=[("bash", {"command": "echo ran-four"})]),
    Turn(text="Investigation complete."),
]
_CAP_TWO = {**DEFAULT_LIMITS, "max_tool_calls": 2, "wall_clock_timeout": 3600, "grace_seconds": 600}


def _drive_main(root: Path, main: ReplayFn, *, run_id: str, limits: dict) -> dict:
    """Drive MAIN's script; returns the run's budget snapshot, read off the run's state."""
    run_dir = materialize(root, GOLDEN, run_id=run_id)
    return drive(run_dir, run_id=run_id, main=main, limits=limits)["run_state"].budget_snapshot()


def _zeroed_budget(run_id: str) -> str:
    """A budget record that reads as a fresh, unspent run — what resetting the cap looks like
    on disk."""
    now = _now_iso()
    return json.dumps({"run_id": run_id, "tool_calls": 0, "subagent_spawns": 0,
                       "created_at": now, "started_at": now})


def test_the_call_cap_refuses_at_the_cap(tmp_path, enforced):
    """Positive control for every budget arm below, on the same script and cap:"""
    main = ReplayFn(list(_FOUR_BASH))
    budget = _drive_main(tmp_path / "control", main, run_id="b1235-control", limits=_CAP_TWO)

    assert _refusals(main) == 2, "the cap did not refuse the two calls past it"
    history = main.seen[-1]
    assert "ran-one" in history, "a call under the cap did not run"
    assert "ran-two" in history, "a call under the cap did not run"
    assert "ran-three" not in history, "a call past the cap ran"
    assert "ran-four" not in history, "a call past the cap ran"
    assert budget["tool_calls"] == 2


@pytest.mark.parametrize("plant", ["overwrite", "delete"])
def test_a_reset_budget_file_does_not_reopen_the_cap(tmp_path, enforced, plant):
    """O1:"""
    run_dir_holder: list[Path] = []

    def reset() -> None:
        target = run_dir_holder[0] / BUDGET_FILE
        if plant == "overwrite":
            _write(target, _zeroed_budget("b1235-reset"))
        else:
            target.unlink(missing_ok=True)

    main = PlantingReplay(list(_FOUR_BASH), at=2, plant=reset)
    run_dir = materialize(tmp_path / plant, GOLDEN, run_id='b1235-reset')
    run_dir_holder.append(run_dir)
    state = drive(run_dir, run_id="b1235-reset", main=main, limits=_CAP_TWO)["run_state"]

    assert main.planted, "the plant never ran — this arm measured nothing"
    history = main.seen[-1]
    assert "ran-one" in history
    assert "ran-two" in history
    assert "ran-three" not in history, f"budget.json ({plant}) reopened the cap: a call past it ran"
    assert "ran-four" not in history, f"budget.json ({plant}) reopened the cap: a call past it ran"
    assert _refusals(main) == 2
    assert state.budget_snapshot()["tool_calls"] == 2


def test_a_planted_clock_origin_does_not_trip_the_wall_clock(tmp_path, enforced):
    """O1, the clock limb:"""
    roomy = {**DEFAULT_LIMITS, "max_tool_calls": 100, "wall_clock_timeout": 3600,
             "grace_seconds": 600}
    holder: list[Path] = []

    def ancient() -> None:
        _write(holder[0] / BUDGET_FILE, json.dumps({
            "run_id": "b1235-clock", "tool_calls": 0, "subagent_spawns": 0,
            "created_at": "2000-01-01T00:00:00+00:00",
            "started_at": "2000-01-01T00:00:00+00:00"}))

    main = PlantingReplay(list(_FOUR_BASH), at=0, plant=ancient)
    run_dir = materialize(tmp_path / "ancient", GOLDEN, run_id='b1235-clock')
    holder.append(run_dir)
    summary = drive(run_dir, run_id="b1235-clock", main=main, limits=roomy)

    assert main.planted
    assert summary.get("truncated_by") != "budget", "a planted origin killed the run"
    assert _refusals(main) == 0, "a planted origin tripped the wall clock"
    assert "ran-four" in main.seen[-1]
    assert summary["run_state"].budget_snapshot()["tool_calls"] == 4

    spent = ReplayFn(list(_FOUR_BASH))
    _drive_main(tmp_path / "spent-clock", spent, run_id="b1235-clock-ctl",
                limits={**roomy, "wall_clock_timeout": 0})
    assert _refusals(spent) == 4, "the wall-clock limb never refuses, so the arm above is vacuous"


def _registry(rec: VerbRecorder, *, cmdb_fails: bool) -> FakeVerbs:
    def probe(ctx, *, native_query: str = "FROM logs") -> list[dict]:
        rec.record("probe", ctx, {"native_query": native_query})
        if cmdb_fails:
            raise TransportFault("cmdb unreachable")
        return [{"host": "web-01", "query": native_query}]

    return FakeVerbs({"cmdb": {"probe": probe}})


def _cmdb(n: int) -> Turn:
    return q("cmdb", "probe", {"native_query": f"FROM hosts-{n}"})


def _drive_gather(root: Path, gather: ReplayFn, *, verbs, run_id: str) -> dict:
    """Drive one cmdb lead; returns the run's breaker snapshot, read off the run's state."""
    run_dir = materialize(root, GOLDEN_AB3, run_id=run_id)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "cmdb", "goal": "measure this lead",
            "what_to_summarize": ["host inventory"],
        })]),
        Turn(text="Investigation complete."),
    ])
    return drive(run_dir, run_id=run_id, main=main, gather=gather,
                 verbs=verbs)["run_state"].breaker_snapshot()


def _down(gather: ReplayFn) -> bool:
    seen = gather.seen[-1]
    return "[circuit-breaker]" in seen and "is DOWN" in seen


def test_a_system_tripped_by_two_infra_failures_answers_down(tmp_path):
    """Positive control for the breaker arms:"""
    rec = VerbRecorder()
    gather = ReplayFn([_cmdb(1), _cmdb(2), _cmdb(3), DONE])
    state = _drive_gather(tmp_path / "control", gather,
                          verbs=_registry(rec, cmdb_fails=True), run_id="k1235-control")

    assert len(rec.calls) == 2, "the tripped system was asked again"
    assert _down(gather)
    assert state["systems"]["cmdb"]["failures"] == 2
    assert "tripped_at" in state["systems"]["cmdb"]
    assert state["total_failures"] == 2


@pytest.mark.parametrize("plant", ["blank", "delete"])
def test_a_reset_breaker_file_does_not_untrip_a_system(tmp_path, plant):
    """O1:"""
    holder: list[Path] = []

    def reset() -> None:
        target = holder[0] / BREAKER_FILE
        if plant == "blank":
            _write(target, json.dumps({"systems": {}, "total_failures": 0}))
        else:
            target.unlink(missing_ok=True)

    rec = VerbRecorder()
    gather = PlantingReplay([_cmdb(1), _cmdb(2), _cmdb(3), DONE], at=2, plant=reset)
    run_dir = materialize(tmp_path / plant, GOLDEN_AB3, run_id='k1235-reset')
    holder.append(run_dir)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "cmdb", "goal": "measure this lead",
            "what_to_summarize": ["host inventory"],
        })]),
        Turn(text="Investigation complete."),
    ])
    state = drive(run_dir, run_id="k1235-reset", main=main, gather=gather,
                  verbs=_registry(rec, cmdb_fails=True))["run_state"].breaker_snapshot()

    assert gather.planted, "the plant never ran — this arm measured nothing"
    assert len(rec.calls) == 2, f"circuit_breaker.json ({plant}) untripped cmdb: the verb ran again"
    assert _down(gather)
    assert state["systems"]["cmdb"]["failures"] == 2
    assert state["total_failures"] == 2
