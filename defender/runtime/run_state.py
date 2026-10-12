"""One run's live decision state, held by the run's own process (#1235).

`run_investigation` starts one `RunState` before lead-0 and before any tool call, and carries it
by reference: on MAIN's `AgentDeps` (every gather lead's deps hold the same object), on lead-0's
capture deps, and on each `VerbContext` the query tool and lead-0 build. It holds what the run
decides on while it runs:

  * the budget — the tool-call and spawn counters and the clock's two origins;
  * the circuit breaker — each system's failures and when it tripped;
  * the queries table's rows, by lead, in append order — the rows the host wrote, or seeding
    handed over for a branch sibling, never rows read back from the file;
  * the oracle clock — the seconds an oracle turn held the world, and the turn open now.

No file is read into it and none is written from it. The run folder is the box's writable mount,
so a decision answered from there is one the model can move; and a run folder is only ever used
by one run (`run_common._setup_state`), so nothing needs to outlive the process.

The behaviour stays with each concern's own module, which takes the state first:
`budget_enforcer` (counting, the oracle clock), `circuit_breaker` (charging, the trip) and
`record_query` (the row append, the seq, the repeat note). Each does its read-modify-write under
the state's one `lock`, and outside readers take the snapshots, which are copies. Nothing
process-wide refers to a state, so it lives exactly as long as the run that holds it.
"""
from __future__ import annotations

import copy
import threading
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class RunState:
    """The live state of the run started on `run_dir` as `run_id` (see the module docstring).

    The fields below `lock` belong to the modules named beside them and change only under the
    lock; read them through the snapshots."""

    def __init__(self, run_dir: Path, run_id: str) -> None:
        #: The folder the run was started on, as spelled.
        self.run_dir = Path(run_dir)
        self.run_id = run_id
        #: Serialises every read-modify-write: a cap check and its increment, a breaker charge,
        #: a row append (its seq, payload, table line and record). Reentrant, because the row
        #: append allocates its seq through the same reader everything else uses.
        self.lock = threading.RLock()
        now = datetime.now(UTC).isoformat()
        #: `budget_enforcer`: the counters and the wall-clock origin.
        self.budget: dict = {
            "run_id": run_id,
            "tool_calls": 0,
            "subagent_spawns": 0,
            "created_at": now,
            "started_at": now,
        }
        #: `budget_enforcer`: the monotonic origin `_elapsed` measures alongside the wall one.
        self.started_monotonic = time.monotonic()
        #: `circuit_breaker`: `{"systems": {name: {"failures": n, "tripped_at"?: iso}},
        #: "total_failures": n}`.
        self.breaker: dict = {"systems": {}, "total_failures": 0}
        #: `record_query`: each lead's rows, in append order (an inherited prefix first).
        self.rows: dict[str, list[dict]] = {}
        #: `budget_enforcer`: the seconds closed oracle turns held the world, and the
        #: `time.monotonic()` start of the turn open now.
        self.oracle_credited = 0.0
        self.oracle_opened: float | None = None

    @classmethod
    def start(cls, run_dir: Path, run_id: str) -> RunState:
        """A run's state at its start: zero counts, a wall-clock and a monotonic origin of now,
        a blank breaker, no rows, no oracle credit and no open turn."""
        return cls(run_dir, run_id)

    def budget_snapshot(self) -> dict:
        """A copy of the budget: `run_id`, `tool_calls`, `subagent_spawns`, `created_at`,
        `started_at`."""
        with self.lock:
            return dict(self.budget)

    def breaker_snapshot(self) -> dict:
        """A deep copy of the breaker, `{"systems": {}, "total_failures": 0}` until a failure is
        charged."""
        with self.lock:
            return copy.deepcopy(self.breaker)

    def lead_rows(self, lead: str) -> list[dict]:
        """Copies of `lead`'s rows, in append order."""
        with self.lock:
            return copy.deepcopy(self.rows.get(lead, []))

    def inherit_rows(self, rows: Iterable[dict]) -> None:
        """Record rows this run did not write: a branch sibling's inherited prefix, handed over
        by seeding as it writes them into the sibling's table. Grouped by their `lead_id`; a row
        with no lead id names no lead any reader asks about, so it is not held."""
        with self.lock:
            for row in rows:
                lead = row.get("lead_id")
                if isinstance(lead, str):
                    self.rows.setdefault(lead, []).append(copy.deepcopy(row))


def run_state_of(holder: Any) -> RunState:
    """The run's state `holder` (a role's deps) carries. `TypeError` when it carries none: a
    live operation — a queries row, a breaker screen — reached from deps no run started has no
    state to act on, and starting one here would be a second run's state, counted nowhere the
    run's own decisions look."""
    state = holder.run_state
    if state is None:
        raise TypeError(
            f"{type(holder).__name__} carries no RunState: a live operation needs the run's "
            "own state, which `run_investigation` starts and hands to its deps")
    return state
