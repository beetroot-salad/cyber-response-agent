"""#631 — the enforced budget's LIBRARY half: the cap table, the run's budget state, the tail band and the validating read."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import pytest

from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    TAIL_ALLOWANCE,
    account_call,
    check_budgets,
    tail_exhausted,
)
from defender.tests import _1255_clock as C
from defender.tests.e2e._replay_harness import GOLDEN_AB3, materialize


def _start(run_dir: Path, run_id: str):
    """A run's state as `run_investigation` starts it (#1235 round 2: one `RunState` per run; imported here..."""
    from defender.runtime.run_state import RunState

    return RunState(run_dir, run_id)


def _count(state, tool_name: str) -> dict:
    """The unenforced posture's count (`count_call`, no cap check)."""
    from defender.hooks.budget_enforcer import count_call

    return count_call(state, tool_name)


def _tight(**over) -> dict:
    return {**DEFAULT_LIMITS, **over}


def _fresh_view(tmp_path: Path) -> dict:
    """A fresh run's budget as the enforcing checks read it (`enforcement_state`) — whatever
    origin the run keeps, named by the production builder rather than by this test (#1255: the
    origin is the run clock's, no longer a pair of fields a test can backdate)."""
    from defender.hooks.budget_enforcer import enforcement_state

    return enforcement_state(_start(tmp_path, "fresh"))


def _reads_as_healthy(state: dict, limits: dict) -> bool:
    """Whether the enforcing read would ADMIT the call — no trip on any limb. The fail-open shape D2/D9 guard..."""
    return not any("Budget exceeded" in m for m in check_budgets(state, limits))


def test_tail_ends_on_count_or_clock(tmp_path):
    """The post-trip tail ends when tool_calls reaches max_tool_calls + 10 OR when
    elapsed exceeds wall_clock_timeout + grace_seconds, whichever comes first — the
    count limb alone does not bound duration.

    F3(b) is what makes the grace limb load-bearing rather than belt-and-braces:
    refusals never advance the count limb, so a model that only re-issues stopped
    tools never reaches N + 10 and the CLOCK is the only thing that ends its tail.

    #1255 ("Time"): this file keeps the COUNT arm. The clock arm used to be driven by handing
    `tail_exhausted` a `started_monotonic` backdated by 119 s and 121 s; elapsed is now measured
    on the run clock alone (`run_investigation(clock=…)`), so that arm is
    `test_the_tail_ends_on_the_run_clocks_grace_not_on_real_time` below, driven through the
    seam. The count states carry no origin on purpose: the count limb must not depend on one."""
    limits = _tight(max_tool_calls=5, wall_clock_timeout=100, grace_seconds=20)

    assert TAIL_ALLOWANCE == 10
    assert not tail_exhausted({"tool_calls": 5 + TAIL_ALLOWANCE - 1}, limits)

    assert tail_exhausted({"tool_calls": 5 + TAIL_ALLOWANCE}, limits)


@pytest.mark.e2e
@pytest.mark.parametrize(("second_step", "killed"), [(2, True), (0, False)],
                         ids=["past-the-grace", "inside-the-grace"])
def test_the_tail_ends_on_the_run_clocks_grace_not_on_real_time(tmp_path, monkeypatch,
                                                                 second_step, killed):
    """#1255 "Time" (the clock arm of `test_tail_ends_on_count_or_clock`, re-expressed through
    the run clock seam): with a 100 s limit and 20 s of grace, a run whose clock reads 119 s
    after its start is refused (past the limit) but alive; at 121 s the next tool call ends the
    run with `truncated_by == "budget"`. Real time is milliseconds either way.

    MAIN's second `bash` call comes after a 119 s step (refused, run alive); its third after
    `second_step` more seconds (121 s: killed; 119 s: refused again, run alive). The two cases
    are each other's control on the same channel, and the refusal in BOTH shows the 119 s step
    really reached the limit limb (so a kill that never fires is not a dead limb).

    Red (class a) until `run_investigation` accepts `clock=`."""
    monkeypatch.setenv(C.FLAG, "true")
    clock = C.FakeClock(C.SOURCE_START)
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id="tail")
    main = C.script(clock, (0, C.bash("echo first")), (119, C.bash("echo second-ran")),
                    (second_step, C.bash("echo third-ran")), (0, C.DONE))

    summary = C.drive_clocked(run_dir, clock=clock, main=main,
                              limits=C.caps(wall_clock_timeout=100, grace_seconds=20,
                                            max_tool_calls=50))

    assert len(main.seen) >= 3, f"the run ended before the 119 s call was answered: {main.seen}"
    assert C.refusal_stem() in main.seen[2], "119 s of run-clock time past a 100 s limit refused nothing — the control failed"
    assert "wall-clock" in main.seen[2], "119 s of run-clock time past a 100 s limit refused nothing — the control failed"
    assert "second-ran" not in main.seen[2]
    assert (summary["truncated_by"] == "budget") is killed, (
        f"{119 + second_step} s of run-clock time against 100 s + 20 s of grace: "
        f"truncated_by={summary['truncated_by']!r}")
    if not killed:
        assert len(main.seen) >= 4
        assert "third-ran" not in main.seen[3]


@pytest.mark.parametrize("bad_origin", [
    {},
    {"created_at": None, "started_at": None},
    {"created_at": "not-a-timestamp", "started_at": "not-a-timestamp"},
    {"created_at": [], "started_at": []},
], ids=["no-origin", "none", "not-a-timestamp", "a-list"])
def test_an_origin_less_state_fails_closed_rather_than_reading_as_healthy(tmp_path, bad_origin):
    """A state that names no readable clock origin does not conclude 'under cap, clock
    unreadable' and admit the call: the enforcing read FAILS CLOSED with a wall_clock trip.

    "No readable origin" is each shape the retired test drove (RC-L2): the origin absent, or
    present and unreadable — `None`, a string that is not a timestamp, a list — in the form a
    budget snapshot carries its origin today (`created_at` and `started_at`, both bad, so
    neither reads).

    #1255 ("Time") RETIRES the rest of what stood here, `test_unreadable_started_at_does_not_
    silently_drop_the_wall_clock_limb`: its four bad-`started_at` cases each carried a valid
    `started_monotonic` past the cap and asserted the limb still fired "off the monotonic
    backup" under `elapsed = max(wall_delta, local_monotonic_delta)`. Monotonic is no longer a
    source: elapsed is measured on the run clock alone, so there is no backup to fire from. What
    survives is the fail-closed half, which does not depend on a source.

    Positive control, same function: a fresh run's own enforcement view is healthy, so the trip
    is the missing origin's, not a limb that always fires."""
    limits = _tight(wall_clock_timeout=100, max_tool_calls=10_000)
    state = {"run_id": "r", "tool_calls": 1, **bad_origin}

    msgs = check_budgets(state, limits)
    assert any("wall_clock" in m and "Budget exceeded" in m for m in msgs), msgs
    assert not _reads_as_healthy(state, limits), (
        f"a state whose origin is {bad_origin!r} admitted the call instead of failing closed"
    )

    assert _reads_as_healthy(_fresh_view(tmp_path), limits), (
        "a fresh run's own enforcement view tripped — the fail-closed assertion above proves "
        "nothing")


# #1255 ("Time") RETIRES `test_elapsed_reads_a_monotonic_source_and_survives_a_backward_clock_
# step`. It pinned `elapsed = max(wall_delta, local_monotonic_delta)`: a monotonic source firing
# the limb "whichever way the wall clock is pushed" (a forward-dated or stepped-back `started_at`
# against a `started_monotonic` backdated by 500 s). The design measures the wall-clock limb on
# the run clock alone — `run_investigation(clock=…)` — so there is no second origin to fire off.
# What the design keeps of it, "a limit trips when the clock has passed it and not before", is
# `tests/test_1255_clock_natural.py::test_n4_the_wall_clock_limb_measures_the_run_clock`
# (past-the-limit / inside-the-limit) and `test_n5_…`; the tail's grace is the test above.

def test_a_counter_failing_validation_trips_rather_than_returning_no_messages(tmp_path):
    """A counter that fails type or range validation TRIPS: a negative or boolean tool_calls does not silently..."""
    limits = _tight(max_tool_calls=200, max_subagent_spawns=40)
    # #1255: the healthy base is a fresh run's own enforcement view, not a state built around a
    # `started_monotonic` field — only the counter under test is hostile.
    view = _fresh_view(tmp_path)
    for bad in (-5, True, False, "9", "not-a-number", [1], {"a": 1}, None, 3.5):
        state = {**view, "run_id": "r", "tool_calls": bad, "subagent_spawns": 0}
        msgs = check_budgets(state, limits)
        assert any("Budget exceeded" in m and "tool_calls" in m for m in msgs), (
            f"tool_calls={bad!r} failed open: {msgs!r}"
        )

    for bad in (-1, True, "2", [], None):
        state = {**view, "run_id": "r", "tool_calls": 0, "subagent_spawns": bad}
        msgs = check_budgets(state, limits)
        assert any("Budget exceeded" in m and "subagent_spawns" in m for m in msgs), (
            f"subagent_spawns={bad!r} failed open: {msgs!r}"
        )

    assert check_budgets(
        {**view, "run_id": "r", "tool_calls": 1, "subagent_spawns": 0}, limits) == []


def test_an_injected_cap_of_zero_trips_immediately_rather_than_disabling(tmp_path):
    """An injected cap of 0 trips immediately rather than reading as 'disabled': a state well past every cap does..."""
    zeroed = {"max_tool_calls": 0, "max_subagent_spawns": 0,
              "wall_clock_timeout": 0, "grace_seconds": 0}
    view = _fresh_view(tmp_path)
    time.sleep(0.01)  # a real, positive elapsed on whatever source the run reads
    state = {**view, "run_id": "r", "tool_calls": 9999, "subagent_spawns": 9999}
    msgs = check_budgets(state, zeroed)
    assert any("tool_calls" in m and "Budget exceeded" in m for m in msgs)
    assert any("subagent_spawns" in m and "Budget exceeded" in m for m in msgs)
    assert any("wall_clock" in m and "Budget exceeded" in m for m in msgs)

    first = {**view, "run_id": "r", "tool_calls": 1, "subagent_spawns": 0}
    assert any("tool_calls" in m for m in check_budgets(first, zeroed))

    nonzero = {"max_tool_calls": 1, "max_subagent_spawns": 1,
               "wall_clock_timeout": 100, "grace_seconds": 0}
    assert check_budgets({**view, "run_id": "r", "tool_calls": 0, "subagent_spawns": 0},
                         nonzero) == []

    assert tail_exhausted({**view, "tool_calls": 1}, zeroed)


def test_no_trip_state_no_reset(tmp_path):
    """The run's own writer persists no trip flag and never resets or decrements a counter: across every..."""
    run = _start(tmp_path, "run-1")
    seen: list[tuple[int, int]] = []
    trip_keys = ("tripped", "trip", "budget_tripped", "stopped", "kill")
    for name in ("bash", "gather", "read_file", "gather", "write_file", "query"):
        state = _count(run, name)
        seen.append((state["tool_calls"], state["subagent_spawns"]))
        for surface in (state, run.budget_snapshot()):
            assert not any(k in surface for k in trip_keys), (
                f"a trip flag was recorded into the run's budget: {surface!r}"
            )

    assert [c for c, _ in seen] == sorted(c for c, _ in seen)
    assert [s for _, s in seen] == sorted(s for _, s in seen)
    assert seen[-1] == (6, 2)


def test_connectivity_failures_spend_the_budget_pool(tmp_path):
    """Accounting is unconditional on call OUTCOME: a call that fails on connectivity still executed, so it still..."""
    run = _start(tmp_path, "run-1")
    limits = _tight(max_tool_calls=100)
    for _ in range(4):
        state = account_call(run, "query", limits=limits, tier="core")
    assert state["tool_calls"] == 4, "a failed-on-connectivity call did not spend the pool"
    assert run.budget_snapshot()["tool_calls"] == 4


def test_a_call_that_finished_after_its_pool_tripped_does_not_land_its_effect(tmp_path):
    """A call that executed after its pool tripped does not land its effect: the increment path re-checks the..."""
    run = _start(tmp_path, "run-1")
    limits = _tight(max_tool_calls=5)
    for _ in range(4):
        _count(run, "bash")
    assert run.budget_snapshot()["tool_calls"] == 4

    barrier = threading.Barrier(200)

    def one_call():
        barrier.wait()
        return account_call(run, "bash", limits=limits, tier="core")

    with ThreadPoolExecutor(max_workers=200) as pool:
        list(pool.map(lambda _: one_call(), range(200)))

    assert run.budget_snapshot()["tool_calls"] == 5, (
        "a 200-call turn overshot a cap of 5 — the commit-time re-check did not fire"
    )


def test_concurrent_increments_to_the_run_budget_are_neither_lost_nor_duplicated_under_contention(
    tmp_path,
):
    """Every increment committed by many concurrently-executing calls across MAIN and its GATHER siblings..."""
    run = _start(tmp_path, "run-1")
    n_workers, per_worker = 12, 40

    def worker(i: int) -> None:
        for _ in range(per_worker):
            _count(run, "gather" if i % 3 == 0 else "bash")

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        list(pool.map(worker, range(n_workers)))

    final = run.budget_snapshot()
    assert final["tool_calls"] == n_workers * per_worker
    assert final["subagent_spawns"] == 4 * per_worker


# #1255 ("Time") RETIRES `test_budget_origin_is_a_wall_clock_the_elapsed_check_honours`. It
# pinned VR1, `elapsed = max(wall_delta, local_monotonic_delta)`: a state whose wall origin was
# 500 s old and whose monotonic origin was fresh still tripped, "the wall origin is what still
# sees the run's real age". Elapsed is now measured on the run clock alone, with one origin (the
# clock's reading at the run's start), so a fresh second origin cannot hide a run's age — there
# is no second origin. The kept half, "an old run trips", is
# `tests/test_1255_clock_natural.py::test_n4_the_wall_clock_limb_measures_the_run_clock`.


def test_a_second_run_state_for_the_folder_starts_a_fresh_budget(tmp_path):
    """A run's state is the run's start (#1235 round 2): a second `RunState(...)` for the SAME folder is a fresh..."""
    first_run = _start(tmp_path, "run-1")
    first = first_run.budget_snapshot()
    assert first["run_id"] == "run-1"
    assert (first["tool_calls"], first["subagent_spawns"]) == (0, 0)
    assert first["created_at"], "the run's state minted no origin"
    # (#1255: the origin is a reading of the run clock, an aware UTC instant — this assertion
    # stood in the retired `test_budget_origin_is_a_wall_clock_the_elapsed_check_honours`.)
    assert datetime.fromisoformat(first["created_at"]).tzinfo is not None, \
        "the origin is not an absolute (tz-aware) wall time"
    assert first["started_at"], "the run's state minted no origin"
    _count(first_run, "bash")
    _count(first_run, "gather")
    accrued = first_run.budget_snapshot()
    assert (accrued["tool_calls"], accrued["subagent_spawns"]) == (2, 1), \
        "the first budget never counted — the fresh start below would prove nothing"

    second = _start(tmp_path, "run-2").budget_snapshot()
    assert second["run_id"] == "run-2", "the second start kept the first run's identity"
    assert (second["tool_calls"], second["subagent_spawns"]) == (0, 0), \
        "a new run's start inherited the previous run's counters"
    assert datetime.fromisoformat(second["created_at"]) >= \
        datetime.fromisoformat(first["created_at"]), "the second origin predates the first"
    assert first_run.budget_snapshot() == accrued, "starting a second run moved the first's"


def test_the_budget_writes_no_file_into_the_run_folder_or_its_container(tmp_path):
    """#1235 D3: the budget is the run process's memory. A whole run's worth of accounting — the open, counted..."""
    runs_base = tmp_path / "runs"
    run_dir = runs_base / "run-1235"
    run_dir.mkdir(parents=True)
    limits = _tight(max_tool_calls=3)

    run = _start(run_dir, "run-1235")
    _count(run, "gather")
    for _ in range(4):
        account_call(run, "bash", limits=limits, tier="core")
    account_call(run, "read_file", limits=limits, tier="tail")

    on_disk = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")
                     if not p.is_dir())
    assert on_disk == [], f"the budget wrote files: {on_disk}"

    state = run.budget_snapshot()
    assert state["tool_calls"] == 4, \
        f"expected the gather, two core calls up to the cap of 3 and one tail call: {state}"
    assert state["subagent_spawns"] == 1, state


def test_a_budget_file_in_the_run_folder_moves_no_count(tmp_path):
    """#1235 D3, at the library: a `budget.json` sitting in a run folder — planted, or left from an older run —..."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "budget.json").write_text(
        '{"run_id": "x", "tool_calls": 7, "subagent_spawns": 0}', encoding="utf-8")
    run = _start(run_dir, "run-1")
    assert run.budget_snapshot()["tool_calls"] == 0, "a planted file was read as a budget"

    limits = _tight(max_tool_calls=2)
    for _ in range(2):
        account_call(run, "bash", limits=limits, tier="core")
    assert run.budget_snapshot()["tool_calls"] == 2, "the state did not count to its cap"
    (run_dir / "budget.json").write_text(
        '{"run_id": "run-1", "tool_calls": 0, "subagent_spawns": 0}', encoding="utf-8")

    state = account_call(run, "bash", limits=limits, tier="core")
    assert state["tool_calls"] == 2, "a planted zero re-opened the capped pool"
    assert run.budget_snapshot()["tool_calls"] == 2, run.budget_snapshot()
