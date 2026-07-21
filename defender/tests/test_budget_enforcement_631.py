"""#631 — the enforced budget's LIBRARY half: the cap table, the state file, the
tail band, the validating read, and the accounting-failure detection state.

This module drives `defender.hooks.budget_enforcer` directly — the two functions the
driver's hooks call (`update_budget_locked`, `check_budgets`) plus the surface #631
adds around them. The run-level demands (the refusal seam, the kill, the report tail)
live in `tests/e2e/test_budget_enforcement_631.py`, which drives the real
`run_investigation` through the replay harness.

RED AGAINST HEAD IS THE EXPECTED STATE. At `483b5809` the module is warning-only:
`BudgetKill`, `tier`, `tail_exhausted`, `account_call`, `open_budget`,
`accounting_failure_state` and `grace_seconds` do not exist, `wall_clock_timeout` is
1800, and `check_budgets` fails open on every hostile counter shape (PB8, executed).
Each of those is the demanded CORRECTION, pinned here; none is the ambient string.

Faults are induced down the hierarchy: every failure in this module is real input
through the real primitive — an unwritable run dir, a counter authored on disk, a
forward-dated `started_at`, real concurrent threads and processes on one flock. No
fault here is invented; each names the executed claim that observed it.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    TAIL_ALLOWANCE,
    BudgetKill,
    accounting_failure_state,
    account_call,
    check_budgets,
    open_budget,
    tail_exhausted,
    update_budget_locked,
)

REPO_ROOT = Path(__file__).resolve().parents[2]



def _budget(run_dir: Path) -> dict:
    return json.loads((run_dir / "budget.json").read_text())


def _author_budget(run_dir: Path, **fields) -> None:
    """Author budget.json exactly as the model's own `write_file` grant would.

    This is the fault primitive PO51/PB8 (both executed) established: MAIN's compiled
    write scope admits `budget.json`, so an authored counter is a REAL input to the
    enforcing read, not an imagined one."""
    (run_dir / "budget.json").write_text(json.dumps(fields))


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



def test_missing_started_at_does_not_restart_the_clock(tmp_path):
    """A budget.json missing started_at does not get a fresh timestamp backfilled on
    the enforcing path: a recreated budget file must not silently restart the wall
    clock and void the cap.

    D2 supersedes the `setdefault` backfill as the EVIDENCE this rests on, and VR1
    refines it: the cross-process origin is `created_at`, a WALL-CLOCK timestamp
    written at open (time.monotonic() is not comparable across the six writer processes
    budget.json is shared by). The run opened with that origin, so a file that comes
    back without it is a replacement, not a cold start, and the run's own writer must
    not silently mint a FRESH origin later than the run's real start."""
    open_budget(tmp_path, "run-1")
    original = _budget(tmp_path)
    assert original["run_id"] == "run-1"
    origin = original.get("created_at")
    assert origin, "open_budget wrote no cross-process wall-clock origin (VR1)"

    _author_budget(tmp_path, run_id="run-1", tool_calls=0, subagent_spawns=0)
    after_write = update_budget_locked(tmp_path, "run-1", "bash", limits=DEFAULT_LIMITS)
    after = _budget(tmp_path)

    new_origin = after.get("created_at")
    assert new_origin in (None, origin), (
        "the run's writer re-minted a fresh clock origin over a replaced budget.json, "
        "restarting the wall clock and voiding the cap"
    )
    assert not _reads_as_healthy(after_write, DEFAULT_LIMITS), (
        "a budget.json replaced mid-run read as a cold start and admitted the call"
    )


def test_budget_state_carries_a_run_scoped_sentinel_from_before_the_first_call(tmp_path):
    """budget.json carries {run_id, created_at} written before the first tool call, and
    a file whose run_id is not this run's is detected as a replacement rather than
    accepted as reset counters.

    The comparison lives at update_budget_locked, which holds the AUTHORITATIVE run_id
    — blind reader R13: check_budgets(dict) has no run history and no channel to tell
    "absent after present" from "absent at cold start", so the detection cannot be
    asserted through that seam. Driven through the seam that DOES carry the run_id: the
    model authors a file with reset counters under a different run_id, and the run's own
    writer must not let the enforcing read then admit the call. (Recorded fork VR3-F1:
    whether "absent-after-present" — the model wiping the whole sentinel while keeping
    THIS run's id — is separable through any seam is a design question this pass does
    not settle.)"""
    state = open_budget(tmp_path, "run-abc")
    assert state["run_id"] == "run-abc"
    assert state["created_at"], "no cross-process wall-clock origin written at open (VR1)"
    assert state["tool_calls"] == 0
    on_disk = _budget(tmp_path)
    assert on_disk["run_id"] == "run-abc"
    assert on_disk["created_at"] == state["created_at"]

    _author_budget(tmp_path, run_id="not-this-run", created_at="2020-01-01T00:00:00+00:00",
                   tool_calls=0, subagent_spawns=0)
    after = update_budget_locked(tmp_path, "run-abc", "bash", limits=DEFAULT_LIMITS)
    assert not _reads_as_healthy(after, DEFAULT_LIMITS), (
        "a budget.json bearing a foreign run_id was accepted as this run's reset counters"
    )


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
    the counters DO move on the one shared budget.json — without it 'never reset' is
    satisfied by a writer that never writes."""
    open_budget(tmp_path, "run-1")
    limits = _tight(max_tool_calls=1000, max_subagent_spawns=1000)
    seen: list[tuple[int, int]] = []
    trip_keys = ("tripped", "trip", "budget_tripped", "stopped", "kill")
    for name in ("bash", "gather", "read_file", "gather", "write_file", "query"):
        state = update_budget_locked(tmp_path, "run-1", name, limits=limits)
        seen.append((state["tool_calls"], state["subagent_spawns"]))
        for surface in (state, _budget(tmp_path)):
            assert not any(k in surface for k in trip_keys), (
                f"a trip flag was persisted into budget.json: {surface!r}"
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


def test_concurrent_increments_to_budget_json_are_neither_lost_nor_duplicated_under_contention(
    tmp_path,
):
    """Every increment committed by many concurrently-executing calls across MAIN and
    its GATHER siblings survives intact under real contention on the one flock: the
    final tool_calls equals the number of calls that committed, with none lost and
    none double-counted.

    Bound at the COMPOSITION frame that fans the writers, not at a leg: a single-leg
    test cannot see the cross-leg collision the demand exists for. This arm drives
    real THREAD contention on the one flock; the cross-PROCESS lost-update conservation
    (six real writer processes, P5's shape) is asserted in
    test_the_enforcing_read_of_budget_json_is_never_torn, which reads the final count
    back after 6 × 150 committed increments (blind reader R17 flagged the mismatch
    between this docstring's process argument and its thread drive)."""
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


def test_the_enforcing_read_of_budget_json_is_never_torn(tmp_path):
    """The enforcement-side read of budget.json is consistent under concurrent
    writers — it never observes the truncate-then-write window — so the trip decision
    is taken over a whole record rather than an empty one.

    P5 (executed) against six real concurrent writer PROCESSES: the naive
    `json.loads` reader saw the window in 1745 of 4000 reads (43.6%); the same reader
    routed through the lock was 0 of 4000. The failure is SILENT and FAILS OPEN — a
    torn read yields {}, check_budgets({}) returns [], and the enforcing read then
    ADMITS the call. This test re-probes reality with real processes rather than
    pinning the taxonomy once."""
    from defender.hooks import budget_enforcer

    open_budget(tmp_path, "run-1")
    writer_src = (
        "import sys;"
        f"sys.path.insert(0, {str(REPO_ROOT)!r});"
        "from defender.hooks.budget_enforcer import update_budget_locked, DEFAULT_LIMITS;"
        "from pathlib import Path;"
        f"rd = Path({str(tmp_path)!r});"
        "[update_budget_locked(rd, 'run-1', 'bash', limits={**DEFAULT_LIMITS,"
        " 'max_tool_calls': 10**6}) for _ in range(150)]"
    )
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    procs = [subprocess.Popen([sys.executable, "-c", writer_src], env=env)
             for _ in range(6)]
    try:
        torn = 0
        reads = 0
        live_reads = 0
        started = False
        while any(p.poll() is None for p in procs) and reads < 4000:
            state = budget_enforcer.read_budget(tmp_path)
            reads += 1
            if state.get("tool_calls"):
                started = True
            if not started:
                continue
            live_reads += 1
            if not state or "tool_calls" not in state or state.get("tool_calls") == 0:
                torn += 1
    finally:
        for p in procs:
            p.wait()
    assert all(p.returncode == 0 for p in procs), "a writer subprocess crashed"
    assert reads > 0, "the read loop never ran against a live writer"
    assert live_reads > 0, "the read loop never observed a live (post-first-increment) writer"
    assert _budget(tmp_path)["tool_calls"] == 6 * 150, (
        "cross-process increments were lost or double-counted under contention"
    )
    assert torn == 0, f"the enforcing read observed {torn} torn states in {live_reads} live reads"



def _seal(run_dir: Path) -> None:
    run_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)


def _unseal(run_dir: Path) -> None:
    run_dir.chmod(stat.S_IRWXU)


def test_one_failed_accounting_write_costs_one_call_of_overshoot(tmp_path):
    """A single failed accounting write does not stop the run and costs exactly one
    call of overshoot: the counter is monotonic, so the next call re-crosses the cap
    and trips.

    The healthy state is the falsy member bound at its own address — zero consecutive
    failures and no first-failure stamp — and an implementation that cannot tell
    "zero failures" from "no state" reads a fresh run as a standing fault or a
    standing fault as fresh."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    open_budget(run_dir, "run-1")
    limits = _tight(max_tool_calls=3, accounting_failure_max_consecutive=3,
                    accounting_failure_max_elapsed=3600)

    assert accounting_failure_state(run_dir)["consecutive_failures"] == 0
    assert accounting_failure_state(run_dir)["first_failure_at"] is None

    for _ in range(2):
        account_call(run_dir, "run-1", "bash", limits=limits, tier="core")
    assert _budget(run_dir)["tool_calls"] == 2

    _seal(run_dir)
    try:
        account_call(run_dir, "run-1", "bash", limits=limits, tier="core")
    finally:
        _unseal(run_dir)
    assert _budget(run_dir)["tool_calls"] == 2, "the failed write landed anyway"
    assert accounting_failure_state(run_dir)["consecutive_failures"] == 1

    state = account_call(run_dir, "run-1", "bash", limits=limits, tier="core")
    assert state["tool_calls"] == 3
    assert any("tool_calls at 3/3" in m for m in check_budgets(state, limits))
    assert accounting_failure_state(run_dir)["consecutive_failures"] == 0


def test_consecutive_accounting_write_failures_stop_or_mark_the_run(tmp_path):
    """A STANDING accounting-write failure is an environment fault, not slack: once
    consecutive failures reach the count's own threshold the run stops with the
    budget kill, because enforcement has silently left the run.

    The count RESETS ON SUCCESS, which is what keeps it from firing on an
    intermittent fault — and is exactly why it cannot be the only mechanism; its
    sibling, test_an_intermittent_accounting_failure_trips_the_first_failure_stamp,
    covers the gap it leaves."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    open_budget(run_dir, "run-1")
    limits = _tight(max_tool_calls=1000, accounting_failure_max_consecutive=3,
                    accounting_failure_max_elapsed=3600)

    _seal(run_dir)
    try:
        account_call(run_dir, "run-1", "bash", limits=limits, tier="core")
        account_call(run_dir, "run-1", "bash", limits=limits, tier="core")
        with pytest.raises(BudgetKill):
            account_call(run_dir, "run-1", "bash", limits=limits, tier="core")
    finally:
        _unseal(run_dir)
    assert accounting_failure_state(run_dir)["consecutive_failures"] >= 3

    fresh = tmp_path / "run2"
    fresh.mkdir()
    open_budget(fresh, "run-2")
    _seal(fresh)
    try:
        account_call(fresh, "run-2", "bash", limits=limits, tier="core")
    finally:
        _unseal(fresh)
    account_call(fresh, "run-2", "bash", limits=limits, tier="core")
    assert accounting_failure_state(fresh)["consecutive_failures"] == 0


def test_an_intermittent_accounting_failure_trips_the_first_failure_stamp(tmp_path):
    """An accounting write that fails INTERMITTENTLY — every other call, so the
    consecutive count never advances past one — still trips: the first-failure stamp
    does not reset on success, so once the elapsed time since the first failure
    passes the stamp's own separate threshold the run stops with the budget kill.

    THE DISCRIMINATING SEQUENCE IS ALTERNATING, and it is what the count limb cannot
    catch by construction: a test that drove only consecutive failures would pass
    against an implementation that shipped the count and skipped the stamp."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    open_budget(run_dir, "run-1")
    limits = _tight(max_tool_calls=1000, accounting_failure_max_consecutive=3,
                    accounting_failure_max_elapsed=0.2)

    def alternating_call(fail: bool):
        if fail:
            _seal(run_dir)
            try:
                return account_call(run_dir, "run-1", "bash", limits=limits, tier="core")
            finally:
                _unseal(run_dir)
        return account_call(run_dir, "run-1", "bash", limits=limits, tier="core")

    alternating_call(fail=True)
    stamp = accounting_failure_state(run_dir)["first_failure_at"]
    assert stamp is not None

    with pytest.raises(BudgetKill):  # noqa: PT012 — the alternating drive must run inside the block until the stamp trips
        deadline = time.monotonic() + 5
        fail = False
        while time.monotonic() < deadline:
            alternating_call(fail=fail)
            fail = not fail
            assert accounting_failure_state(run_dir)["consecutive_failures"] < 3
            time.sleep(0.02)
        pytest.fail("the first-failure stamp never tripped on an alternating fault")

    assert accounting_failure_state(run_dir)["first_failure_at"] == stamp, (
        "the stamp reset on success — it must measure elapsed degradation"
    )



def test_budget_origin_is_a_cross_process_wall_clock(tmp_path):
    """The run's clock origin is a WALL-CLOCK timestamp — the shared, cross-process-
    comparable anchor — not a bare time.monotonic() float, and a reader in a DIFFERENT
    process (with its own, unrelated monotonic clock) still measures the run's true age
    from it.

    VR1 (§7 round 6) refines D12: budget.json is a cross-process shared file (M8: one
    pool for MAIN and every GATHER subagent; the torn-read test drives six writer
    PROCESSES), and time.monotonic() is NOT comparable across processes. So `created_at`
    is persisted as wall clock and each process uses its own monotonic source only for a
    within-process delta: `elapsed = max(wall_delta, local_monotonic_delta)`. This is
    R27's first-raised correctness hole, pinned as a demand rather than left to
    assumption — a wall origin defeated by a fresh-monotonic reader in another process is
    exactly the cap-evasion VR1 closes."""
    state = open_budget(tmp_path, "run-1")
    created = state["created_at"]
    parsed = datetime.fromisoformat(created)
    assert parsed.tzinfo is not None, "the origin is not an absolute (tz-aware) wall time"

    limits = _tight(wall_clock_timeout=100, max_tool_calls=10_000)
    old_wall = (datetime.now(UTC) - timedelta(seconds=500)).isoformat()
    cross_process = {"run_id": "run-1", "tool_calls": 1,
                     "started_at": old_wall, "created_at": old_wall,
                     "started_monotonic": time.monotonic()}
    assert any("wall_clock" in m and "Budget exceeded" in m
               for m in check_budgets(cross_process, limits)), (
        "a reader with a fresh monotonic clock could not see the run's true age from the "
        "wall origin — the wall-clock cap is defeated by reading from another process"
    )


def test_a_second_open_budget_preserves_the_origin_and_counters(tmp_path):
    """open_budget is idempotent on the origin: a second call against an existing
    budget.json (a re-entrant setup, a retried invocation) preserves created_at and
    does NOT zero the counters a real run has already accrued.

    R27: B4 makes the origin's stability load-bearing but nothing pins it, and
    re-originating on a second open is exactly the silent wall-clock restart D2
    forbids."""
    first = open_budget(tmp_path, "run-1")
    created, origin = first.get("created_at"), first.get("started_at")
    assert created, "open_budget wrote no cross-process origin"
    update_budget_locked(tmp_path, "run-1", "bash", limits=DEFAULT_LIMITS)

    second = open_budget(tmp_path, "run-1")
    assert second.get("created_at") == created, "a second open_budget re-minted the origin"
    assert second.get("started_at") == origin, "a second open_budget re-minted started_at"
    assert _budget(tmp_path)["tool_calls"] == 1, "a second open_budget reset the counters"


def test_accounting_failure_state_persists_outside_the_sealed_run_dir(tmp_path):
    """The accounting-failure detection state is read WHILE the run dir is sealed — the
    very condition it exists to detect — so it cannot live in the run dir. A failure
    recorded against a sealed run dir is still readable, and the count still advances.

    R27: B16-B18 silently require this (they seal the run dir, then read
    accounting_failure_state); here it is made explicit. If the state lived in the
    sealed run dir it could be neither written nor read, and the count would never
    advance past zero — enforcement would leave the run undetectably."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    open_budget(run_dir, "run-1")
    limits = _tight(accounting_failure_max_consecutive=3,
                    accounting_failure_max_elapsed=3600)
    _seal(run_dir)
    try:
        account_call(run_dir, "run-1", "bash", limits=limits, tier="core")
        recorded = accounting_failure_state(run_dir)
    finally:
        _unseal(run_dir)
    assert recorded["consecutive_failures"] == 1, (
        "the failure count did not advance — the detection state cannot live inside the "
        "sealed run dir whose sealing it is meant to detect"
    )
