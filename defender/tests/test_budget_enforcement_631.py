"""#631 — the enforced budget's LIBRARY half: the cap table, the run's budget state, the tail band and the validating read."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    TAIL_ALLOWANCE,
    account_call,
    check_budgets,
    tail_exhausted,
)


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


def _reads_as_healthy(state: dict, limits: dict) -> bool:
    """Whether the enforcing read would ADMIT the call — no trip on any limb. The fail-open shape D2/D9 guard..."""
    return not any("Budget exceeded" in m for m in check_budgets(state, limits))


def test_tail_ends_on_count_or_clock(tmp_path):
    """The post-trip tail ends when tool_calls reaches max_tool_calls + 10 OR when elapsed exceeds..."""
    limits = _tight(max_tool_calls=5, wall_clock_timeout=100, grace_seconds=20)
    now = time.monotonic()

    assert TAIL_ALLOWANCE == 10
    assert not tail_exhausted(
        {"tool_calls": 5 + TAIL_ALLOWANCE - 1, "started_monotonic": now - 10}, limits)

    assert tail_exhausted(
        {"tool_calls": 5 + TAIL_ALLOWANCE, "started_monotonic": now - 10}, limits)

    assert not tail_exhausted({"tool_calls": 5, "started_monotonic": now - 119}, limits)
    assert tail_exhausted({"tool_calls": 5, "started_monotonic": now - 121}, limits)


def test_unreadable_started_at_does_not_silently_drop_the_wall_clock_limb(tmp_path):
    """An unreadable or missing started_at does not silently drop the wall-clock limb on the enforcing path:..."""
    limits = _tight(wall_clock_timeout=100, max_tool_calls=10_000)
    past_cap = time.monotonic() - 500
    for bad_origin in ({},
                       {"started_at": None},
                       {"started_at": "not-a-timestamp"},
                       {"started_at": []}):
        state = {"run_id": "r", "tool_calls": 1, "started_monotonic": past_cap,
                 **bad_origin}
        msgs = check_budgets(state, limits)
        assert any("wall_clock" in m and "Budget exceeded" in m for m in msgs), (
            f"the wall-clock limb dropped out silently for started_at={bad_origin!r}"
        )

    assert not _reads_as_healthy({"run_id": "r", "tool_calls": 1}, limits), (
        "an origin-less state admitted the call instead of failing closed"
    )


def test_elapsed_reads_a_monotonic_source_and_survives_a_backward_clock_step(tmp_path):
    """elapsed reads a monotonic source, so a backward system-clock step during the run does not extend it — and..."""
    limits = _tight(wall_clock_timeout=100, max_tool_calls=10_000)
    past_cap = time.monotonic() - 500

    forward = {"run_id": "r", "tool_calls": 1,
               "started_at": (datetime.now(UTC) + timedelta(days=30_000)).isoformat(),
               "started_monotonic": past_cap}
    assert any("wall_clock" in m and "Budget exceeded" in m
               for m in check_budgets(forward, limits)), (
        "a forward-dated started_at suppressed the wall-clock limb"
    )

    backward = {"run_id": "r", "tool_calls": 1,
                "started_at": (datetime.now(UTC) + timedelta(seconds=1000)).isoformat(),
                "started_monotonic": past_cap}
    assert any("wall_clock" in m and "Budget exceeded" in m
               for m in check_budgets(backward, limits)), (
        "a backward system-clock step reset the wall-clock limb and extended the cap"
    )

    fresh = {"run_id": "r", "tool_calls": 1, "started_at": datetime.now(UTC).isoformat(),
             "started_monotonic": time.monotonic()}
    assert not any("wall_clock" in m for m in check_budgets(fresh, limits))


def test_a_counter_failing_validation_trips_rather_than_returning_no_messages(tmp_path):
    """A counter that fails type or range validation TRIPS: a negative or boolean tool_calls does not silently..."""
    limits = _tight(max_tool_calls=200, max_subagent_spawns=40)
    now = time.monotonic()
    for bad in (-5, True, False, "9", "not-a-number", [1], {"a": 1}, None, 3.5):
        state = {"run_id": "r", "tool_calls": bad, "subagent_spawns": 0,
                 "started_monotonic": now}
        msgs = check_budgets(state, limits)
        assert any("Budget exceeded" in m and "tool_calls" in m for m in msgs), (
            f"tool_calls={bad!r} failed open: {msgs!r}"
        )

    for bad in (-1, True, "2", [], None):
        state = {"run_id": "r", "tool_calls": 0, "subagent_spawns": bad,
                 "started_monotonic": now}
        msgs = check_budgets(state, limits)
        assert any("Budget exceeded" in m and "subagent_spawns" in m for m in msgs), (
            f"subagent_spawns={bad!r} failed open: {msgs!r}"
        )

    assert check_budgets(
        {"run_id": "r", "tool_calls": 1, "subagent_spawns": 0,
         "started_monotonic": now}, limits) == []


def test_an_injected_cap_of_zero_trips_immediately_rather_than_disabling(tmp_path):
    """An injected cap of 0 trips immediately rather than reading as 'disabled': a state well past every cap does..."""
    zeroed = {"max_tool_calls": 0, "max_subagent_spawns": 0,
              "wall_clock_timeout": 0, "grace_seconds": 0}
    now = time.monotonic()
    state = {"run_id": "r", "tool_calls": 9999, "subagent_spawns": 9999,
             "started_at": datetime.now(UTC).isoformat(), "started_monotonic": now - 1}
    msgs = check_budgets(state, zeroed)
    assert any("tool_calls" in m and "Budget exceeded" in m for m in msgs)
    assert any("subagent_spawns" in m and "Budget exceeded" in m for m in msgs)
    assert any("wall_clock" in m and "Budget exceeded" in m for m in msgs)

    first = {"run_id": "r", "tool_calls": 1, "subagent_spawns": 0,
             "started_at": datetime.now(UTC).isoformat(), "started_monotonic": now}
    assert any("tool_calls" in m for m in check_budgets(first, zeroed))

    nonzero = {"max_tool_calls": 1, "max_subagent_spawns": 1,
               "wall_clock_timeout": 100, "grace_seconds": 0}
    assert check_budgets(
        {"run_id": "r", "tool_calls": 0, "subagent_spawns": 0,
         "started_at": datetime.now(UTC).isoformat(), "started_monotonic": now},
        nonzero) == []

    assert tail_exhausted({"tool_calls": 1, "started_monotonic": now - 1}, zeroed)


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


def test_budget_origin_is_a_wall_clock_the_elapsed_check_honours(tmp_path):
    """The run's clock origin is a WALL-CLOCK timestamp, not a bare time.monotonic() float, and the elapsed check..."""
    state = _start(tmp_path, "run-1").budget_snapshot()
    created = state["created_at"]
    parsed = datetime.fromisoformat(created)
    assert parsed.tzinfo is not None, "the origin is not an absolute (tz-aware) wall time"

    limits = _tight(wall_clock_timeout=100, max_tool_calls=10_000)
    old_wall = (datetime.now(UTC) - timedelta(seconds=500)).isoformat()
    late_monotonic = {"run_id": "run-1", "tool_calls": 1,
                      "started_at": old_wall, "created_at": old_wall,
                      "started_monotonic": time.monotonic()}
    assert any("wall_clock" in m and "Budget exceeded" in m
               for m in check_budgets(late_monotonic, limits)), (
        "a fresh monotonic origin hid the run's true age from the wall origin — the "
        "wall-clock cap is defeated by a late-started clock"
    )


def test_a_second_run_state_for_the_folder_starts_a_fresh_budget(tmp_path):
    """A run's state is the run's start (#1235 round 2): a second `RunState(...)` for the SAME folder is a fresh..."""
    first_run = _start(tmp_path, "run-1")
    first = first_run.budget_snapshot()
    assert first["run_id"] == "run-1"
    assert (first["tool_calls"], first["subagent_spawns"]) == (0, 0)
    assert first["created_at"], "the run's state minted no origin"
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
