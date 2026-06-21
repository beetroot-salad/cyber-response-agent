"""Per-run, per-system circuit breaker for data-source access.

Counts connectivity/auth failures per *system* within a run and trips a breaker
so the runtime stops hammering — and stops re-dispatching — a system that is
down, plus a run-wide kill switch that aborts the whole investigation once the
environment looks broadly unreachable. This is the harness-level half of the
fast-fail guardrail; the agent-protocol half lives in the SKILLs ("exit 2 →
escalate immediately").

**What counts as a failure.** A system-of-record call that exits with the
connectivity/auth code (2 — the contract shared by every adapter's `execution.md`
and the gather exit-code protocol) or times out (124, synthesized by
`record_query.capture`). Exit 1 is a *query* error (bad syntax, zero results) —
normal investigative iteration, deliberately NOT counted. A usage error (a bad
flag/subcommand the agent passed) is exit 64, not 2 — adapters parse argv with
`_stub_transport.AdapterArgumentParser`, which reserves 64 for argparse errors so
the agent's own CLI typos can't trip the breaker and hide a working system. The
exit code alone is the signal; no stderr inspection.

**Two enforcement points share this state** (both in runtime/tools.py):
  - the gather *dispatch* gate — a tripped system is not dispatched and its
    reference SKILL is never injected/read, so the block is transparent to the
    main loop (it gets a measurement-shaped "system down" return, not an error);
  - the in-gather *adapter* gate — a call to an already-tripped system is denied
    before it runs, so a single dispatch can't keep hammering a dead source.

**Transport-agnostic by design.** State is keyed on the logical system name, not
the CLI mechanism, so when adapters move to MCP servers the same record/trip/kill
logic applies: record the MCP tool result's failure against its system, gate
whether that system's MCP toolset is attached, and (optionally) detach it on trip.

State lives in `{run_dir}/circuit_breaker.json`, mutated under an exclusive flock
via the shared `_run_dir.update_json_locked` helper (the same primitive behind
`budget.json`) so concurrent gather subagents don't race.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

# Shared locked-JSON helper. The workspace root is on sys.path via the
# entry-point bootstrap (run.py) / pytest's `pythonpath = [".."]`.
from defender.hooks._run_dir import update_json_locked

# A system trips after this many connectivity/auth failures; the run aborts after
# this many across all systems. With the per-system block at 2, reaching 5 total
# means ~3 distinct systems are unreachable (or one keeps failing through retries)
# — i.e. the environment, not one source, is broken. Tune here.
PER_SYSTEM_FAIL_LIMIT = 2
RUN_FAIL_KILL_LIMIT = 5

# Adapter exit codes that mean "the system is down", not "the query was wrong".
# 2 = connectivity/auth/config (every adapter's contract); 124 = adapter timeout
# (record_query.capture synthesizes it on a hung call). A usage error (the agent's
# bad flag/subcommand) is exit 64 (_stub_transport.AdapterArgumentParser), and a
# query error is exit 1 — neither is in this set, so neither trips the breaker.
# The exit code IS the signal: no stderr-phrase sniffing needed to separate the
# agent's CLI typos from a real down system.
INFRA_EXIT_CODES = frozenset({2, 124})


def is_infra_failure(exit_code: int) -> bool:
    """True iff this outcome counts against the breaker: a connectivity/auth/config
    failure (2) or a timeout (124). A usage error (64) and a query error (1) are the
    agent's own mistakes to reason about, and never count."""
    return exit_code in INFRA_EXIT_CODES


class RunAborted(Exception):
    """The run-wide kill switch tripped: too many connectivity/auth failures
    across the environment. Propagates out of the agent loop; the driver catches
    it, writes the partial trace, and exits like the request-limit path."""

    def __init__(self, total_failures: int, systems: list[str]):
        self.total_failures = total_failures
        self.systems = sorted(set(systems))
        super().__init__(
            f"run aborted by circuit breaker: {total_failures} connectivity/auth "
            f"failures across systems {self.systems} — the environment appears "
            f"unreachable. Escalate with the visibility gap named."
        )


def _path(run_dir: Path) -> Path:
    return Path(run_dir) / "circuit_breaker.json"


def _blank() -> dict:
    return {"systems": {}, "total_failures": 0}


def _load(run_dir: Path) -> dict:
    p = _path(run_dir)
    if not p.is_file():
        return _blank()
    try:
        return json.loads(p.read_text() or "{}") or _blank()
    except (json.JSONDecodeError, OSError):
        return _blank()


def record_outcome(run_dir: Path, system: str, exit_code: int) -> dict:
    """Record one system-call outcome under an exclusive lock. Increments the
    system's failure counter (and the run total) only on an infra failure (see
    `is_infra_failure`). Returns the updated state. Raises `RunAborted` when the
    run-wide kill threshold is crossed — callers let it propagate. Returns `{}`
    (no state change to report) on the no-op path — the common success case — so a
    clean query doesn't pay a file read; callers don't use the return there."""
    if not system or not is_infra_failure(exit_code):
        return {}

    def _mutate(state: dict) -> None:
        state.setdefault("systems", {})
        sysrec = state["systems"].setdefault(system, {"failures": 0})
        sysrec["failures"] += 1
        state["total_failures"] = state.get("total_failures", 0) + 1
        if sysrec["failures"] >= PER_SYSTEM_FAIL_LIMIT and "tripped_at" not in sysrec:
            sysrec["tripped_at"] = datetime.now(UTC).isoformat(timespec="seconds")

    state = update_json_locked(_path(run_dir), _mutate, default=_blank)

    # Run-wide kill switch — checked after the locked update (a redundant raise
    # from a racing subagent is harmless; the driver catches the first).
    if state.get("total_failures", 0) >= RUN_FAIL_KILL_LIMIT:
        # RunAborted already de-dups + sorts, so pass the distinct system names.
        raise RunAborted(state["total_failures"], list(state["systems"]))
    return state


def is_tripped(run_dir: Path, system: str) -> bool:
    """True iff `system`'s breaker has tripped this run (>= PER_SYSTEM_FAIL_LIMIT
    infra failures). Best-effort read (no lock) — gates tolerate slight staleness."""
    if not system:
        return False
    rec = _load(run_dir).get("systems", {}).get(system)
    return bool(rec) and rec.get("failures", 0) >= PER_SYSTEM_FAIL_LIMIT


def down_message(run_dir: Path, system: str) -> str:
    """The transparent 'system is down' summary returned to the agent in place of
    a gather result (dispatch gate) or as a denial (adapter gate)."""
    rec = _load(run_dir).get("systems", {}).get(system, {})
    n = rec.get("failures", PER_SYSTEM_FAIL_LIMIT)
    return (
        f"[circuit-breaker] System '{system}' is DOWN for this run: {n} "
        f"connectivity/auth failures or timeouts (adapter exit 2 / 124) tripped the "
        f"breaker, so this dispatch did not run and {system}'s reference skill was "
        f"not loaded. This "
        f"is a visibility gap, not a query result. Do NOT re-dispatch {system}; "
        f"name the missing evidence in your analysis and escalate (inconclusive) "
        f"if it blocks disposition."
    )
