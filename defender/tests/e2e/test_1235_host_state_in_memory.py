"""#1235 — the run's budget counters and circuit breaker live in the run process's memory.

A decision the host makes reads host memory, never a file in the run folder (#1235 decision
D3, comment 6107812099). Before #1235 the call cap, the spawn cap, the wall clock and the
breaker were each re-read from `budget.json` / `circuit_breaker.json` in the run folder on every
call, so whatever wrote those files moved the decision. After it, nothing writes either file
and nothing reads one: the run's own process holds the state — since round 2 (comment
6117481676) on the run's one `RunState`, which `drive()` returns as `["run_state"]`
(`budget_snapshot()`, `breaker_snapshot()`) — and the accounting-failure sidecar that guarded
the file writes retires with them (F3).

What this module pins, each through the real driver (`drive`), with the mid-run write made
in-process from the scripted model's own turn — the seam `test_denial_gather_632`'s
`BreakingReplay` and `test_budget_e2e_631`'s clock-step replay already use. The plant always
lands AFTER the driver started the run's state (the model is first asked after
`RunState(...)`), so it is a write into a live run, never a seed:

  O1 (budget, breaker). Overwriting or deleting the state file in a live run's folder changes
     no refusal: the call cap still refuses at the cap, a tripped system stays tripped, a
     healthy one is not tripped by a planted file, and a planted clock origin does not trip
     the wall clock. Each negative is paired with the same decision reached legitimately.
  O2. A run writes none of the retired files — no `budget.json`, no `circuit_breaker.json`,
     no `<run>.accounting_failures.json` — anywhere; the positive control is that the same run
     did make tool calls, record queries and charge the breaker.

The queries table's live reads (the repeat guard, the rejection budget) and the case pointer
are pinned in the companion module for the second half of #1235.

Since round 3 production's summary carries no state: the harness injects it
(`run_investigation(run_state=…)`) and `drive()` hands it back.
"""
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

#: The retired run-folder state files, by the names they had on disk.
BUDGET_FILE = "budget.json"
BREAKER_FILE = "circuit_breaker.json"
ACCOUNTING_SIDECAR_SUFFIX = ".accounting_failures.json"


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


# ======================================================================================
# O1 — budget. MAIN's `bash` is core-tier, so each call below is metered and refusable. Four
# calls against a cap of two: the first two run, the last two are refused. No `verbs=` is
# injected, so no lead-0 call shares the pool and the counts are this script's alone.
# ======================================================================================

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
    """Positive control for every budget arm below, on the same script and cap: with nothing
    planted, calls one and two run and calls three and four are refused, and the run counts
    exactly two calls (on the run's own state)."""
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
    """O1: with the run AT its cap, a `budget.json` rewritten to zeroed counters (or deleted)
    in the live run's folder does not reopen it — calls three and four are still refused and
    still never run, exactly as in `test_the_call_cap_refuses_at_the_cap`.

    Observed failing by: the cap re-read from the planted file, so call three or four runs."""
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


def test_a_planted_spent_budget_does_not_refuse_a_call_under_the_cap(tmp_path, enforced):
    """O1, the other direction: a `budget.json` planted before the first call claiming the run
    is far past every cap neither refuses nor kills it — calls one and two run, and the cap
    still refuses three and four (the same outcome as the unplanted control).

    Observed failing by: the first call refused, or the run killed on a planted tail count."""
    holder: list[Path] = []

    def spend() -> None:
        now = _now_iso()
        _write(holder[0] / BUDGET_FILE, json.dumps({
            "run_id": "b1235-spent", "tool_calls": 10_000, "subagent_spawns": 10_000,
            "created_at": now, "started_at": now}))

    main = PlantingReplay(list(_FOUR_BASH), at=0, plant=spend)
    run_dir = materialize(tmp_path / "spent", GOLDEN, run_id='b1235-spent')
    holder.append(run_dir)
    summary = drive(run_dir, run_id="b1235-spent", main=main, limits=_CAP_TWO)

    assert main.planted
    assert summary.get("truncated_by") != "budget", "a planted count killed the run"
    history = main.seen[-1]
    assert "ran-one" in history, "a planted budget.json refused a call under the cap"
    assert "ran-two" in history, "a planted budget.json refused a call under the cap"
    assert _refusals(main) == 2
    assert summary["run_state"].budget_snapshot()["tool_calls"] == 2


def test_a_planted_clock_origin_does_not_trip_the_wall_clock(tmp_path, enforced):
    """O1, the clock limb: a `budget.json` planted with an origin decades in the past does not
    make a fresh run read as out of time — every call runs. Positive control on the same
    address: a run whose wall clock IS spent (`wall_clock_timeout` 0) is refused by it.

    Observed failing by: the planted origin read as the run's start, refusing or killing the run."""
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


# ======================================================================================
# O1 — breaker. One gather lead against an injected registry: `cmdb.probe` fails on transport
# (exit 2, an infra failure the breaker counts) or answers, per scenario; `elastic` is never
# asked, so lead-0's own item-1 call (elastic, a verb this registry does not hold) charges
# nothing. Each call varies its `native_query`, so the repeat guard never answers in place of
# the breaker.
# ======================================================================================

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
    """Positive control for the breaker arms: two transport failures on `cmdb` trip it, and the
    third call is answered by the down message without reaching the verb; the run's own breaker
    state records the two failures and the trip."""
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
    """O1: after `cmdb` tripped on two transport failures, a `circuit_breaker.json` rewritten
    blank (or deleted) in the live run's folder does not untrip it — the third call is still
    answered down and never reaches the verb, as in the control above.

    Observed failing by: the breaker re-read from the planted file, so the third call runs."""
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


@pytest.mark.parametrize("plant", ["tripped", "unreadable"])
def test_a_planted_breaker_file_does_not_trip_a_healthy_system(tmp_path, plant):
    """O1, the other direction: a `circuit_breaker.json` planted before the lead's first call —
    one recording `cmdb` as tripped, or bytes that are not a breaker document at all (the
    retired "unreadable state reads as tripped" branch) — does not answer a healthy `cmdb`
    down: the call reaches the verb and its payload comes back. The control
    `test_a_system_tripped_by_two_infra_failures_answers_down` is the same address answered
    down legitimately.

    Observed failing by: the call answered by the down message and the verb never asked."""
    holder: list[Path] = []

    def trip() -> None:
        target = holder[0] / BREAKER_FILE
        if plant == "tripped":
            _write(target, json.dumps({
                "systems": {"cmdb": {"failures": 5, "tripped_at": _now_iso()}},
                "total_failures": 4}))
        else:
            target.write_bytes(b"\xff\xfe not a breaker document")

    rec = VerbRecorder()
    gather = PlantingReplay([_cmdb(1), DONE], at=0, plant=trip)
    run_dir = materialize(tmp_path / plant, GOLDEN_AB3, run_id='k1235-plant')
    holder.append(run_dir)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "cmdb", "goal": "measure this lead",
            "what_to_summarize": ["host inventory"],
        })]),
        Turn(text="Investigation complete."),
    ])
    state = drive(run_dir, run_id="k1235-plant", main=main, gather=gather,
                  verbs=_registry(rec, cmdb_fails=False))["run_state"]

    assert gather.planted
    assert len(rec.calls) == 1, f"a planted ({plant}) breaker file tripped a healthy system"
    assert not _down(gather)
    assert "web-01" in gather.seen[-1], "the healthy call's payload did not come back"
    assert state.breaker_snapshot() == {"systems": {}, "total_failures": 0}


# ======================================================================================
# O2 — the retired files are written nowhere.
# ======================================================================================

def _retired_files(root: Path) -> list[Path]:
    return sorted(
        p for p in root.rglob("*")
        if p.name in (BUDGET_FILE, BREAKER_FILE) or p.name.endswith(ACCOUNTING_SIDECAR_SUFFIX))


@pytest.mark.parametrize("posture", ["enforced", "accounting-only"])
def test_a_run_leaves_none_of_the_retired_state_files(tmp_path, monkeypatch, posture):
    """O2: a run that made tool calls on MAIN and in a gather lead, recorded queries and charged
    the breaker writes no `budget.json`, no `circuit_breaker.json` and no
    `<run>.accounting_failures.json` — not in the run folder, not beside it, nowhere under the
    test's root — under both budget postures (the enforcing `account_call` and the
    accounting-only `count_call`).

    Positive control, same run: the queries table exists and holds the lead's rows, and the
    run's own memory counted the calls and the breaker failure — so the absence is not a run
    that did nothing."""
    if posture == "enforced":
        monkeypatch.setenv(FLAG, "true")
    else:
        monkeypatch.delenv(FLAG, raising=False)
    rec = VerbRecorder()
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='o2-1235')
    main = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo ran-one"})]),
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "cmdb", "goal": "measure this lead",
            "what_to_summarize": ["host inventory"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([_cmdb(1), _cmdb(2), DONE])
    state = drive(run_dir, run_id="o2-1235", main=main, gather=gather,
                  verbs=_registry(rec, cmdb_fails=True))["run_state"]

    assert _retired_files(tmp_path) == [], "a retired host-state file was written"

    from defender._io import read_jsonl_rows
    from defender.run_repository import RunPaths

    table = RunPaths(run_dir).executed_queries
    assert table.is_file(), "the run recorded no queries — the absence above measured nothing"
    own = [r for r in read_jsonl_rows(table) if r.get("lead_id") == LEAD]
    assert [r["exit_code"] for r in own] == [2, 2]
    assert state.budget_snapshot()["tool_calls"] >= 4, "the run's calls were not counted"
    assert state.budget_snapshot()["subagent_spawns"] >= 1
    assert state.breaker_snapshot()["systems"]["cmdb"]["failures"] == 2
