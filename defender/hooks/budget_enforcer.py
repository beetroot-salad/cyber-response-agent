"""Per-run tool-call budget logic — a LIBRARY, not a hook.

Counts tool calls and subagent spawns per run, produces stderr warnings when usage
crosses 75% / 100% of the configured caps, and — under the enforcing posture (#631)
— refuses the over-budget tool at the execute seam, opens a bounded report tail, and
kills the run when the tail is exhausted. **The flag governs posture, never tuning:**
the caps stay inline and single-default; a test seam threads a `limits` dict in, and
that is the only via. This module reads NO environment variable and NO config file
(`test_caps_are_not_operator_configurable` pins that structurally — the source may not
even contain a file-opening primitive), so the flock'd read lives in `_run_dir`.

The consumers are `runtime/driver.py`'s in-process budget hooks: the `tool_execute`
short-circuit (refuse / kill) reads `read_budget` + `tail_exhausted`, and the
accounting after a successful call goes through `account_call` (enforced, commit-time
re-checked, accounting-failure aware) or `update_budget_locked` (unenforced, plain).

Counters live in `{run_dir}/budget.json`, incremented under an exclusive `flock` so
concurrent gather subagents don't race. The clock origin is a cross-process WALL-CLOCK
timestamp (`created_at`); each process additionally reads its own `time.monotonic`
delta, and `elapsed = max(wall_delta, local_monotonic_delta)` so neither a
cross-process read nor a system-clock step can void the wall cap (VR1).
"""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from defender._io import write_atomic
from defender.hooks._run_dir import read_json_locked, update_json_locked
from defender.runtime.agent_role import AgentRole

# Caps are intentionally inline + single-default: the flag governs POSTURE, not tuning
# (N1). There is no operator overlay, so there is nothing to layer — tune here.
DEFAULT_LIMITS = {
    "max_tool_calls": 200,
    # O4: ~20 min of WALL CLOCK from run start (down from the incumbent 1800). N held
    # at 200 (a deliberate hold at the incumbent value, not a measurement — M3).
    "wall_clock_timeout": 1200,
    "max_subagent_spawns": 40,
    # M6: the post-trip grace, matching _BASH_TIMEOUT_S's order of magnitude, so the
    # stated worst case is ~24 min.
    "grace_seconds": 120,
    # D4/NF4: a STANDING accounting-write failure means enforcement has silently left
    # the run (an unwritable run dir), so the run stops rather than run on unaccounted.
    # Two limbs, because the consecutive count resets on success and so cannot catch an
    # intermittent fault; the first-failure stamp does.
    "accounting_failure_max_consecutive": 5,
    "accounting_failure_max_elapsed": 300,
}
WARNING_THRESHOLD = 0.75

# The post-trip tail band: the tail-tier tools (MAIN's file I/O) keep running for this
# many calls past the cap so MAIN can write its report, then the run is killed.
TAIL_ALLOWANCE = 10

# M1b: the model's ONLY notice of the stop is this text (check_budgets warnings go to
# stderr, which the model never sees). It must say the stop is PERMANENT, name what
# REMAINS available, and tell the model to write its report NOW — a message that reads
# transient invites the retry storm withdrawal was rejected to avoid. It carries an
# interpolated field so the model is told WHICH tool/limb, and a non-empty literal
# lead-in so a delivery check on its stem cannot pass vacuously.
BUDGET_REFUSAL_MESSAGE = (
    "Budget stop: the {tool} tool is now PERMANENTLY withdrawn for the rest of this "
    "run (the {limb} cap is reached and will not reset). Writing your report — "
    "write_file / edit_file to report.md and investigation.md — is still available. "
    "Do not retry this tool; write your report now from the evidence you already have."
)


class BudgetKill(Exception):
    """The budget's own run-ending exception: the report tail is exhausted (count or
    grace clock), or the accounting write is standing-failed. Raised from the budget
    hook, caught at `run_investigation` — which writes the partial trace exactly like
    the request-limit path. Deliberately NOT `RunAborted` (whose constructor builds a
    connectivity-flavoured message) and deliberately absent from
    `query_tool.CONTROL_FLOW_EXCEPTIONS`, so it kills the run rather than being recorded
    as a query fault."""


# --- fresh state + the clock origin -----------------------------------------

def make_budget_state(run_id: str) -> dict:
    """A fresh, genuinely-new budget state. `created_at` is the cross-process wall
    origin (VR1); `started_at` is kept as the legacy field name, same value."""
    now = datetime.now(UTC).isoformat()
    return {
        "run_id": run_id,
        "tool_calls": 0,
        "subagent_spawns": 0,
        "created_at": now,
        "started_at": now,
    }


def open_budget(run_dir: Path, run_id: str) -> dict:
    """Write `budget.json` before the first tool call, idempotently. A second call
    against an existing file (a re-entrant setup, a retried invocation) PRESERVES the
    origin and the accrued counters rather than re-minting a fresh clock (which would
    silently restart the wall cap — the D2 hazard) or zeroing a real run's counts."""
    def _mutate(state: dict) -> None:
        now = datetime.now(UTC).isoformat()
        state.setdefault("run_id", run_id)
        state.setdefault("tool_calls", 0)
        state.setdefault("subagent_spawns", 0)
        state.setdefault("created_at", now)
        state.setdefault("started_at", now)

    return update_json_locked(run_dir / "budget.json", _mutate, default=dict)


def read_budget(run_dir: Path) -> dict:
    """The enforcement-side read of `budget.json`, consistent under concurrent writers
    (a shared `flock`, so it never observes the truncate-then-write window). `{}` when
    absent/torn — the caller fails closed on it."""
    return read_json_locked(run_dir / "budget.json")


# --- counting ----------------------------------------------------------------

def _valid_count(value: object) -> int | None:
    """`value` as a counter iff it is a non-negative int (a bool is NOT — an authored
    `true`/`false` is a forged counter, not the number 1/0). None otherwise, which the
    enforcing read treats as a trip (fail closed)."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


def update_budget_locked(
    run_dir: Path, run_id: str, tool_name: str, *, limits: dict = DEFAULT_LIMITS
) -> dict:
    """Plain, unconditional read-modify-write of `budget.json` under an exclusive lock
    — the UNENFORCED accounting path (and the tests' pre-trip primitive). Increments
    monotonically; persists no trip flag and never resets a counter, so two concurrent
    gathers cannot race a reset.

    Does NOT backfill the clock origin (D2): a `budget.json` that comes back without a
    `created_at` is a replacement, not a cold start, and re-minting one here would
    silently restart the wall clock and void the cap. `limits` is accepted for a
    uniform signature; the plain path does not read it."""
    def _mutate(state: dict) -> None:
        state["tool_calls"] = (_valid_count(state.get("tool_calls")) or 0) + 1
        if tool_name == "gather":
            state["subagent_spawns"] = (_valid_count(state.get("subagent_spawns")) or 0) + 1

    return update_json_locked(
        run_dir / "budget.json", _mutate, default=lambda: make_budget_state(run_id)
    )


# The enforced accounting write is ATOMIC (temp + os.replace), so an unwritable run dir
# (the D4/NF4 fault) fails the write — an in-place r+ would silently succeed on a sealed
# directory. The commit-time re-check must be race-free across concurrent tasks, so the
# whole read-check-write runs under one in-process lock (the enforced runtime is a single
# process; `update_budget_locked`'s flock covers the cross-process readers).
_ACCOUNT_LOCK = threading.Lock()


def _write_budget_atomic(run_dir: Path, state: dict) -> None:
    write_atomic(run_dir / "budget.json", json.dumps(state, indent=2))


def account_call(
    run_dir: Path, run_id: str, tool_name: str, *,
    limits: dict, tier: str, exit_code: int = 0,
) -> dict:
    """Account one EXECUTED call under the enforcing posture: increment the pool with a
    COMMIT-TIME re-check, and treat a failed accounting write as an environment fault.

    Accounting is unconditional on OUTCOME — a call that failed on connectivity
    (`exit_code != 0`) still executed, so it still spends the pool. The commit-time
    re-check bounds TOCTOU overshoot: a call that finished after its pool tripped does
    not land its effect (the increment is skipped when `tool_calls` has already reached
    the tier's limit), so a turn that dispatched N parallel calls against a pool one
    short of its cap lands exactly one.

    On a failed accounting write (an unwritable run dir), the failure is recorded
    OUTSIDE the run dir and the run is stopped with `BudgetKill` once the consecutive
    count or the first-failure elapsed clock crosses its threshold — otherwise
    enforcement would leave the run silently."""
    limit = limits["max_tool_calls"] + (TAIL_ALLOWANCE if tier == "tail" else 0)
    with _ACCOUNT_LOCK:
        state = read_budget(run_dir) or make_budget_state(run_id)
        current = _valid_count(state.get("tool_calls")) or 0
        if current >= limit:
            # Commit-time re-check: the pool tripped since this call was admitted; do
            # not land its effect. Not a write, so not an accounting failure.
            _reset_accounting_failure(run_dir)
            return state
        state["tool_calls"] = current + 1
        if tool_name == "gather":
            state["subagent_spawns"] = (_valid_count(state.get("subagent_spawns")) or 0) + 1
        try:
            _write_budget_atomic(run_dir, state)
        except OSError:
            # The accounting write itself failed — the run dir is unwritable. The
            # increment did not land (monotonic; the next call re-crosses and trips).
            _record_accounting_failure(run_dir, limits)  # may raise BudgetKill
            return read_budget(run_dir) or state
    _reset_accounting_failure(run_dir)
    return state


# --- the accounting-failure detection state (D4/NF4) ------------------------
# Lives OUTSIDE the run dir — the condition it detects is a SEALED run dir, so a state
# inside it could be neither written nor read. A sibling of the run dir (the runs base,
# which stays writable) carries it.

def _accounting_failure_path(run_dir: Path) -> Path:
    run_dir = Path(run_dir)
    return run_dir.parent / f"{run_dir.name}.accounting_failures.json"


def accounting_failure_state(run_dir: Path) -> dict:
    """The accounting-failure detection state: `consecutive_failures` (resets on a
    successful write) and `first_failure_at` (a monotonic stamp that does NOT reset, so
    it measures elapsed degradation across an intermittent fault). The healthy default
    — zero failures, no stamp — is distinguishable from "no state" so a fresh run does
    not read as a standing fault."""
    state = read_json_locked(_accounting_failure_path(run_dir))
    return {
        "consecutive_failures": int(state.get("consecutive_failures", 0) or 0),
        "first_failure_at": state.get("first_failure_at"),
    }


def _record_accounting_failure(run_dir: Path, limits: dict) -> None:
    state = accounting_failure_state(run_dir)
    state["consecutive_failures"] += 1
    if state["first_failure_at"] is None:
        state["first_failure_at"] = time.monotonic()
    _write_accounting_failure(run_dir, state)
    if state["consecutive_failures"] >= limits["accounting_failure_max_consecutive"]:
        raise BudgetKill(
            f"budget accounting write failed {state['consecutive_failures']}x "
            "consecutively — the run dir is unwritable; enforcement has left the run"
        )
    if time.monotonic() - state["first_failure_at"] >= limits["accounting_failure_max_elapsed"]:
        raise BudgetKill(
            "budget accounting has been failing intermittently past the elapsed "
            "threshold — the run dir is degraded; enforcement cannot be trusted"
        )


def _reset_accounting_failure(run_dir: Path) -> None:
    """Reset the consecutive count on a successful write, preserving the first-failure
    stamp. A no-op when nothing is recorded, so the happy path writes no sibling file."""
    state = accounting_failure_state(run_dir)
    if state["consecutive_failures"] == 0:
        return
    state["consecutive_failures"] = 0
    _write_accounting_failure(run_dir, state)


def _write_accounting_failure(run_dir: Path, state: dict) -> None:
    write_atomic(_accounting_failure_path(run_dir), json.dumps(state))


# --- elapsed, the tail band, and the enforcing read -------------------------

def _wall_origin(state: dict) -> datetime | None:
    """The run's wall-clock origin — `created_at` (the authoritative cross-process one),
    else the legacy `started_at`. None when neither is a parseable timestamp."""
    for key in ("created_at", "started_at"):
        raw = state.get(key)
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw)
            except ValueError:
                continue
    return None


def _elapsed(state: dict) -> float | None:
    """The run's age, `max(wall_delta, local_monotonic_delta)` over whichever sources
    are readable (VR1). None when NEITHER a wall origin nor a monotonic origin is
    present — the enforcing read fails closed on that."""
    deltas: list[float] = []
    origin = _wall_origin(state)
    if origin is not None:
        deltas.append((datetime.now(UTC) - origin).total_seconds())
    mono = state.get("started_monotonic")
    if isinstance(mono, (int, float)) and not isinstance(mono, bool):
        deltas.append(time.monotonic() - mono)
    return max(deltas) if deltas else None


def tail_exhausted(state: dict, limits: dict) -> bool:
    """Whether the post-trip report tail has ended — `tool_calls >= max_tool_calls +
    TAIL_ALLOWANCE` OR `elapsed > wall_clock_timeout + grace_seconds`, whichever comes
    first. The clock limb is load-bearing, not belt-and-braces: refusals never advance
    the count, so a model that only re-issues stopped tools never reaches the count
    limit and the clock is the only thing that ends its tail."""
    count = _valid_count(state.get("tool_calls"))
    if count is not None and count >= limits["max_tool_calls"] + TAIL_ALLOWANCE:
        return True
    elapsed = _elapsed(state)
    return elapsed is not None and elapsed > limits["wall_clock_timeout"] + limits["grace_seconds"]


def tier(tool_name: str, role: AgentRole) -> str:
    """The tool's cap tier — `"tail"` for MAIN's file I/O (read_file / write_file /
    edit_file), `"core"` for everything else, including every GATHER tool. TOTAL by
    construction: the default arm is `core` (the restrictive one), so an unknown or
    newly-added tool inherits the tight cap rather than raising a KeyError on the
    enforcement path. Keyed on the (tool, agent) pair — `read_file` is tail on MAIN and
    core on GATHER, so parallel subagents cannot drain MAIN's report window."""
    if role is AgentRole.MAIN and tool_name in ("read_file", "write_file", "edit_file"):
        return "tail"
    return "core"


def should_refuse(state: dict, tool_name: str, call_tier: str, limits: dict) -> bool:
    """Whether the enforcing seam refuses this call. A tail-tier tool is never refused —
    it runs inside the band until `tail_exhausted` kills the run. A core-tier tool is
    refused once any limb it is governed by has crossed: the tool-call cap, the spawn
    cap (for `gather`), or the wall clock. An unreadable counter fails closed."""
    if call_tier == "tail":
        return False
    # `.get(key, 0)` so an ABSENT counter (a run whose budget was never opened) reads as
    # a fresh 0 — not a trip — while a PRESENT but invalid counter (a hostile `-5`/`true`)
    # still fails closed. read_budget is torn-free, so `{}` here means genuinely absent.
    count = _valid_count(state.get("tool_calls", 0))
    if count is None or count >= limits["max_tool_calls"]:
        return True
    if tool_name == "gather":
        spawns = _valid_count(state.get("subagent_spawns", 0))
        if spawns is None or spawns >= limits["max_subagent_spawns"]:
            return True
    elapsed = _elapsed(state)
    return elapsed is not None and elapsed >= limits["wall_clock_timeout"]


def refusal_message(state: dict, tool_name: str, limits: dict) -> str:
    """The model-facing refusal text (M1b), naming the tool and the limb that tripped."""
    return BUDGET_REFUSAL_MESSAGE.format(tool=tool_name, limb=_tripped_limb(state, tool_name, limits))


def _tripped_limb(state: dict, tool_name: str, limits: dict) -> str:
    count = _valid_count(state.get("tool_calls", 0))
    elapsed = _elapsed(state)
    if elapsed is not None and elapsed >= limits["wall_clock_timeout"]:
        return "wall-clock"
    if tool_name == "gather":
        spawns = _valid_count(state.get("subagent_spawns", 0))
        if spawns is None or spawns >= limits["max_subagent_spawns"]:
            return "subagent-spawn"
    if count is None or count >= limits["max_tool_calls"]:
        return "tool-call"
    return "budget"


# --- the warning strings (accounting; goes to stderr) -----------------------

def _ratio_warning(label: str, current: float, cap: float, unit: str = "") -> str | None:
    cur_s = f"{int(current)}{unit}"
    cap_s = f"{int(cap)}{unit}"
    if cap <= 0:
        # An injected cap of 0 is "no budget", not "disabled" — it trips, it does not
        # read as absent (PB6: the incumbent returned None here and suppressed silently).
        return (
            f"Budget exceeded: {label} at {cur_s}/{cap_s}. "
            "Investigation should conclude with current evidence."
        )
    ratio = current / cap
    if ratio >= 1.0:
        return (
            f"Budget exceeded: {label} at {cur_s}/{cap_s}. "
            "Investigation should conclude with current evidence."
        )
    if ratio >= WARNING_THRESHOLD:
        return (
            f"Budget warning: {label} at {cur_s}/{cap_s} "
            f"({int(ratio * 100)}%). Consider wrapping up."
        )
    return None


def _counter_warning(label: str, value: object, cap: float) -> list[str]:
    """The tool-call / spawn arm, with a VALIDATING read (D9): a counter that fails type
    or range validation TRIPS rather than silently suppressing the message (the
    incumbent `-5`/`true`/string shapes returned `[]` or raised a TypeError the driver's
    `except Exception` swallowed as 'budget accounting skipped')."""
    count = _valid_count(value)
    if count is None:
        return [
            f"Budget exceeded: {label} failed validation (got {value!r}) — failing "
            "closed. Investigation should conclude with current evidence."
        ]
    w = _ratio_warning(label, count, cap)
    return [w] if w else []


def check_budgets(budget: dict, limits: dict) -> list[str]:
    """The accounting/warning read — PURE, no per-run memory. Returns the stderr
    warning/exceeded lines for the wall clock and the two counters. Fails CLOSED on an
    unreadable clock origin and on a hostile counter shape, so the enforcing read that
    keys on it (`"Budget exceeded" in ...`) cannot be fooled into admitting the call."""
    warnings: list[str] = []
    elapsed = _elapsed(budget)
    if elapsed is None:
        warnings.append(
            "Budget exceeded: wall_clock origin is unreadable — failing closed. "
            "Investigation should conclude with current evidence."
        )
    else:
        w = _ratio_warning("wall_clock", elapsed, limits["wall_clock_timeout"], "s")
        if w:
            warnings.append(w)
    warnings += _counter_warning("tool_calls", budget.get("tool_calls"), limits["max_tool_calls"])
    warnings += _counter_warning(
        "subagent_spawns", budget.get("subagent_spawns"), limits["max_subagent_spawns"]
    )
    return warnings
