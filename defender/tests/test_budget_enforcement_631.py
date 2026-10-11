"""#631 — the enforced budget's LIBRARY half: the cap table, the run's budget state, the
tail band and the validating read.

This module drives `defender.hooks.budget_enforcer` directly — the functions the driver's
hooks call (`open_budget`, `update_budget_locked`, `account_call`, `check_budgets`) plus the
surface #631 adds around them. The run-level demands (the refusal seam, the kill, the report
tail) live in `tests/test_budget_e2e_631.py`, which drives the real `run_investigation`
through the replay harness.

#1235 moved the state into the run's own process: the counters are an in-memory record keyed
by the run folder, read back through `read_budget`, and no `budget.json` is written or read.
The tests whose subject was the file — a counter authored on disk, a torn cross-process read,
a failed accounting write and the accounting-failure sidecar that counted it — retired with
it. The concurrency demands stay, now over the in-memory state's one lock.

Faults are induced down the hierarchy: every failure in this module is real input through
the real primitive — a forward-dated `started_at`, a hostile counter shape handed to the
validating read, real concurrent threads on one budget. No fault here is invented; each names
the executed claim that observed it.
"""
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
    open_budget,
    read_budget,
    tail_exhausted,
    update_budget_locked,
)


def _budget(run_dir: Path) -> dict:
    """The run's budget as the process holds it (#1235: memory, not a file)."""
    return read_budget(run_dir)


def _tight(**over) -> dict:
    return {**DEFAULT_LIMITS, **over}


def _reads_as_healthy(state: dict, limits: dict) -> bool:
    """Whether the enforcing read would ADMIT the call — no trip on any limb. The
    fail-open shape D2/D9 guard against: a state that reads as an under-cap fresh run."""
    return not any("Budget exceeded" in m for m in check_budgets(state, limits))



def test_default_limits_values():
    """DEFAULT_LIMITS carries wall_clock_timeout 1200 seconds — O4's ~20 minutes of
    WALL CLOCK FROM RUN START (not tool-calling time), down from the incumbent 1800 —
    max_tool_calls 200 held at the incumbent value, and max_subagent_spawns 40."""
    assert DEFAULT_LIMITS["wall_clock_timeout"] == 1200
    assert DEFAULT_LIMITS["max_tool_calls"] == 200
    assert DEFAULT_LIMITS["max_subagent_spawns"] == 40


def test_grace_seconds_value():
    """grace_seconds is 120, matching _BASH_TIMEOUT_S's order of magnitude, so M6's
    stated worst case is ~24 minutes."""
    assert DEFAULT_LIMITS["grace_seconds"] == 120



def test_tail_ends_on_count_or_clock(tmp_path):
    """The post-trip tail ends when tool_calls reaches max_tool_calls + 10 OR when
    elapsed exceeds wall_clock_timeout + grace_seconds, whichever comes first — the
    count limb alone does not bound duration.

    F3(b) is what makes the grace limb load-bearing rather than belt-and-braces:
    refusals never advance the count limb, so a model that only re-issues stopped
    tools never reaches N + 10 and the CLOCK is the only thing that ends its tail.
    That arm is driven explicitly below."""
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
    """An unreadable or missing started_at does not silently drop the wall-clock limb
    on the enforcing path: check_budgets' existing (KeyError, ValueError) swallow must
    not let the enforcing read conclude 'under cap, clock unreadable' and admit the
    call.

    The positive control is test_elapsed_reads_a_monotonic_source_and_survives_a_
    backward_clock_step: a READABLE origin past its cap still produces the wall_clock
    message, so this negative cannot pass by the limb being dead for everyone.

    SC24: this EXTENDS test_budget_enforcer.py's fixtures rather than contradicting
    them — that module's own case asserts the tool-call arms still report, which they
    do here too.

    Blind reader R12: each state carries the field NOT under test — a valid
    `started_monotonic` showing the run is well past its wall cap — so the four cases
    do not collapse into "an implementation that trips whenever started_monotonic is
    absent". The wall origin (started_at) is the only variable, and under VR1's
    `elapsed = max(wall_delta, local_monotonic_delta)` the limb must still fire off the
    monotonic backup despite the unreadable origin."""
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
    """elapsed reads a monotonic source, so a backward system-clock step during the
    run does not extend it — and a forward-dated started_at does not permanently
    suppress the wall-clock limb.

    PB8 (executed) is the fault: an authored `started_at` of 2100-01-01 survives
    update_budget_locked untouched, so a wall-clock limb computed from the system
    clock alone is switched off for the rest of the run by one write_file call. VR1:
    `elapsed = max(wall_delta, local_monotonic_delta)`, so the per-process monotonic
    delta fires the limb whichever way the wall clock is pushed."""
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
    """A counter that fails type or range validation TRIPS: a negative or boolean
    tool_calls does not silently suppress the budget message, and a string, list or
    null does not raise a TypeError the driver's `except Exception` swallows as
    'budget accounting skipped'.

    PB8 executed every one of these shapes against the incumbent check_budgets:
    `tool_calls: -5` and `tool_calls: true` return [] (no message, no exception, no
    log — enforcement suppressed silently), and a string or list raises TypeError.
    EVERY HOSTILE SHAPE FAILS OPEN today. Under the enforcing posture that is the
    bypass, so each one must come back as a trip."""
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
    """An injected cap of 0 trips immediately rather than reading as 'disabled': a
    state well past every cap does not come back with an empty message list because
    _ratio_warning returned None.

    PB6 executed the incumbent behaviour — check_budgets(9999 calls, all caps 0) ->
    [], because _ratio_warning returns None when cap <= 0 — against a cap=1 control
    that fires, so the empty list is the DISABLE path and not a broken probe. THIS IS
    WHAT STOPS test_replay_run_crosses_budget_and_still_reports PASSING VACUOUSLY: a
    harness that injects 0 and observes 'no report tail needed' would go green having
    driven no enforcement at all."""
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
    """The run's own writer persists no trip flag and never resets or decrements a
    counter: across every update_budget_locked call, tool_calls and subagent_spawns
    move monotonically, so two concurrent gathers observing the same trip cannot race
    a reset.

    The positive control is test_main_and_gather_share_one_budget (e2e), which shows
    the counters DO move on the one budget MAIN and gather share — without it 'never
    reset' is satisfied by a writer that never writes."""
    open_budget(tmp_path, "run-1")
    limits = _tight(max_tool_calls=1000, max_subagent_spawns=1000)
    seen: list[tuple[int, int]] = []
    trip_keys = ("tripped", "trip", "budget_tripped", "stopped", "kill")
    for name in ("bash", "gather", "read_file", "gather", "write_file", "query"):
        state = update_budget_locked(tmp_path, "run-1", name, limits=limits)
        seen.append((state["tool_calls"], state["subagent_spawns"]))
        for surface in (state, _budget(tmp_path)):
            assert not any(k in surface for k in trip_keys), (
                f"a trip flag was recorded into the run's budget: {surface!r}"
            )

    assert [c for c, _ in seen] == sorted(c for c, _ in seen)
    assert [s for _, s in seen] == sorted(s for _, s in seen)
    assert seen[-1] == (6, 2)


def test_new_spawn_arm_assertions_coexist_with_the_retired_name_assertion(tmp_path):
    """The live spawn counter's new deny behaviour is asserted over the SAME fixtures
    test_budget_enforcer.py's test_only_gather_counts_as_a_spawn already uses: the
    retired "Task"/"Agent" dispatch names still contribute nothing to
    subagent_spawns, and `gather` alone crosses max_subagent_spawns and produces the
    exceeded message.

    SC24/X8, both executed: the counter is live for "gather" ONLY — Task/Agent
    increment tool_calls but not subagent_spawns, exactly as budget_enforcer.py's own
    comment describes. New assertions EXTEND those fixtures, never contradict them."""
    open_budget(tmp_path, "run-1")
    limits = _tight(max_tool_calls=1000, max_subagent_spawns=2)
    for name in ("Task", "Agent", "bash", "read_file"):
        state = update_budget_locked(tmp_path, "run-1", name, limits=limits)
    assert state["tool_calls"] == 4
    assert state["subagent_spawns"] == 0
    assert check_budgets(state, limits) == []

    for _ in range(2):
        state = update_budget_locked(tmp_path, "run-1", "gather", limits=limits)
    assert state["subagent_spawns"] == 2
    assert any("subagent_spawns at 2/2" in m for m in check_budgets(state, limits))


def test_connectivity_failures_spend_the_budget_pool(tmp_path):
    """Accounting is unconditional on call OUTCOME: a call that fails on connectivity
    still executed, so it still increments tool_calls and lands its effect,
    accumulating toward the budget cap at the same time the circuit breaker
    accumulates toward its own threshold.

    This pins what "executed" MEANS in accounting_stays_unconditional's narrowed
    quantifier, and it is the positive control for
    test_a_call_that_finished_after_its_pool_tripped_does_not_land_its_effect:
    without it, "refuses to commit" is satisfied by an implementation that commits
    nothing."""
    open_budget(tmp_path, "run-1")
    limits = _tight(max_tool_calls=100)
    for _ in range(4):
        state = account_call(tmp_path, "run-1", "query", limits=limits, tier="core",
                             exit_code=2)
    assert state["tool_calls"] == 4, "a failed-on-connectivity call did not spend the pool"
    assert _budget(tmp_path)["tool_calls"] == 4


def test_a_call_that_finished_after_its_pool_tripped_does_not_land_its_effect(tmp_path):
    """A call that executed after its pool tripped does not land its effect: the
    increment path re-checks the pool at commit time and refuses to commit, so a turn
    that dispatched two hundred core-tier calls against a pool one short of its cap
    lands exactly one and refuses the other 199.

    PD1 (executed) is why this replaced D1's round-3 answer: pydantic-ai creates one
    asyncio task per ToolCallPart with no chunking and no cap
    (_agent_graph.py:1902-1945) — peak concurrent in-flight = 200, all started inside
    a 6 ms window — so THERE IS NO BOUND to state as a number and the tool-call cap
    was defeatable in a single turn. Overshoot is now bounded by the concurrency
    genuinely in flight at the moment of the trip. Accepted cost, recorded so it is
    not read as a defect: the call RAN and its result is discarded."""
    open_budget(tmp_path, "run-1")
    limits = _tight(max_tool_calls=5)
    for _ in range(4):
        update_budget_locked(tmp_path, "run-1", "bash", limits=limits)
    assert _budget(tmp_path)["tool_calls"] == 4

    barrier = threading.Barrier(200)

    def one_call():
        barrier.wait()
        return account_call(tmp_path, "run-1", "bash", limits=limits, tier="core")

    with ThreadPoolExecutor(max_workers=200) as pool:
        list(pool.map(lambda _: one_call(), range(200)))

    assert _budget(tmp_path)["tool_calls"] == 5, (
        "a 200-call turn overshot a cap of 5 — the commit-time re-check did not fire"
    )


def test_concurrent_increments_to_the_run_budget_are_neither_lost_nor_duplicated_under_contention(
    tmp_path,
):
    """Every increment committed by many concurrently-executing calls across MAIN and
    its GATHER siblings survives intact under real thread contention on the one
    in-memory budget: the final tool_calls equals the number of calls that committed,
    with none lost and none double-counted.

    Bound at the COMPOSITION frame that fans the writers, not at a leg: a single-leg
    test cannot see the cross-leg collision the demand exists for. #1235: the budget is
    the run process's own state (MAIN, gather and lead-0 share it, keyed by the run
    folder), so the conservation this pins is the read-check-increment under its one
    lock; the cross-PROCESS arm retired with the file it shared."""
    open_budget(tmp_path, "run-1")
    limits = _tight(max_tool_calls=10_000, max_subagent_spawns=10_000)
    n_workers, per_worker = 12, 40

    def worker(i: int) -> None:
        for _ in range(per_worker):
            update_budget_locked(tmp_path, "run-1",
                                 "gather" if i % 3 == 0 else "bash", limits=limits)

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        list(pool.map(worker, range(n_workers)))

    final = _budget(tmp_path)
    assert final["tool_calls"] == n_workers * per_worker
    assert final["subagent_spawns"] == 4 * per_worker


def test_budget_origin_is_a_wall_clock_the_elapsed_check_honours(tmp_path):
    """The run's clock origin is a WALL-CLOCK timestamp, not a bare time.monotonic()
    float, and the elapsed check still measures the run's true age from it when the
    monotonic origin it is handed is fresher than the run.

    VR1 (§7 round 6): `elapsed = max(wall_delta, local_monotonic_delta)`. #1235 keeps
    the state in the run's process, so the cross-process reader this once guarded is
    gone, but the hazard is still in-process: a deps object built with a fresh
    `budget_started_monotonic` (`bind`'s default, which `lead_zero._items` names) would
    hand the check a clock that started late, and the wall origin is what still sees
    the run's real age."""
    state = open_budget(tmp_path, "run-1")
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


def test_a_second_open_budget_starts_a_fresh_budget_for_the_folder(tmp_path):
    """`open_budget` is the run's start (#1235): it starts a FRESH in-memory budget for
    the run folder — counters at zero, a new origin no earlier than the first, the new
    run id — replacing whatever this process held for that folder. A run folder is
    resumed only before any run used it (`run_common._setup_state`), so there is no
    re-entrant open to preserve counters across; a stale budget surviving a new run's
    start is the failure.

    Positive control: before the second open, the first budget DID accrue a call, so
    the zero after it is a reset, not a writer that never counted."""
    first = open_budget(tmp_path, "run-1")
    assert first["run_id"] == "run-1"
    assert (first["tool_calls"], first["subagent_spawns"]) == (0, 0)
    assert first["created_at"], "open_budget minted no origin"
    assert first["started_at"], "open_budget minted no origin"
    update_budget_locked(tmp_path, "run-1", "bash", limits=DEFAULT_LIMITS)
    update_budget_locked(tmp_path, "run-1", "gather", limits=DEFAULT_LIMITS)
    accrued = _budget(tmp_path)
    assert (accrued["tool_calls"], accrued["subagent_spawns"]) == (2, 1), \
        "the first budget never counted — the reset below would prove nothing"

    second = open_budget(tmp_path, "run-2")
    assert second["run_id"] == "run-2", "the second open kept the first run's identity"
    assert (second["tool_calls"], second["subagent_spawns"]) == (0, 0), \
        "a new run's start inherited the previous run's counters"
    assert datetime.fromisoformat(second["created_at"]) >= \
        datetime.fromisoformat(first["created_at"]), "the second origin predates the first"
    assert _budget(tmp_path) == second, "read_budget does not answer the budget just opened"


def test_the_budget_writes_no_file_into_the_run_folder_or_its_container(tmp_path):
    """#1235 D3: the budget is the run process's memory. A whole run's worth of
    accounting — the open, counted calls, calls at the cap and past it, on both tiers —
    leaves nothing on disk: no `budget.json` in the run folder, no sidecar beside it,
    no file anywhere under the runs base.

    Positive control: the same sequence DID count, so the empty tree is not a writer
    that never ran — `read_budget` shows the calls it took and the cap it held."""
    runs_base = tmp_path / "runs"
    run_dir = runs_base / "run-1235"
    run_dir.mkdir(parents=True)
    limits = _tight(max_tool_calls=3)

    open_budget(run_dir, "run-1235")
    update_budget_locked(run_dir, "run-1235", "gather", limits=limits)
    for _ in range(4):
        account_call(run_dir, "run-1235", "bash", limits=limits, tier="core")
    account_call(run_dir, "run-1235", "read_file", limits=limits, tier="tail")

    on_disk = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")
                     if not p.is_dir())
    assert on_disk == [], f"the budget wrote files: {on_disk}"

    state = _budget(run_dir)
    assert state["tool_calls"] == 4, \
        f"expected the gather, two core calls up to the cap of 3 and one tail call: {state}"
    assert state["subagent_spawns"] == 1, state


def test_a_budget_file_in_the_run_folder_moves_no_count(tmp_path):
    """#1235 D3, at the library: a `budget.json` sitting in a run folder — planted, or
    left from an older run — is not the run's budget. A folder no budget was opened for
    reads `{}` and has no clock for an oracle turn to pause, whatever file sits there;
    an opened folder's counts and cap answer from memory, so a planted file claiming
    zero calls does not re-open a capped pool.

    Positive control on the same folder: the budget opened for it is the one read, and
    it has a clock."""
    from defender.hooks import budget_enforcer as be

    never_opened = tmp_path / "never-opened"
    never_opened.mkdir()
    (never_opened / "budget.json").write_text(
        '{"run_id": "x", "tool_calls": 7, "subagent_spawns": 0}', encoding="utf-8")
    assert be.read_budget(never_opened) == {}, "a planted file was read as a budget"
    assert be._has_clock(never_opened) is False, "a planted file gave the folder a clock"

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    limits = _tight(max_tool_calls=2)
    open_budget(run_dir, "run-1")
    assert be._has_clock(run_dir) is True, "an opened budget has no clock"
    for _ in range(2):
        account_call(run_dir, "run-1", "bash", limits=limits, tier="core")
    (run_dir / "budget.json").write_text(
        '{"run_id": "run-1", "tool_calls": 0, "subagent_spawns": 0}', encoding="utf-8")

    state = account_call(run_dir, "run-1", "bash", limits=limits, tier="core")
    assert state["tool_calls"] == 2, "a planted zero re-opened the capped pool"
    assert be.read_budget(run_dir)["tool_calls"] == 2, be.read_budget(run_dir)
