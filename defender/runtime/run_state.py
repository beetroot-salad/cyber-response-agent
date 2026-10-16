"""One run's live decision state, held by the run's own process (#1235).

`run_investigation` resolves one `RunState` at its boundary — the one its caller hands it, or a
new one for its own folder and run id — before lead-0 and before any tool call, and carries it
by reference: on MAIN's `AgentDeps` (every gather lead's deps hold the same object), on lead-0's
capture deps, and on each `VerbContext` the query tool and lead-0 build. It holds what the run
decides on while it runs:

  * the budget — the tool-call and spawn counters and the clock's two origins;
  * the circuit breaker — each system's failures and when it tripped;
  * the queries table's rows, by lead, in append order — the record of every call the run
    made (the table file is the model's view of it), or the rows seeding handed over for a
    branch sibling, never rows read back from the file;
  * the oracle clock — the seconds an oracle turn held the world, and the turn open now.

No file is read into it and none is written from it. The run folder is the box's writable mount,
so a decision answered from there is one the model can move; and a run folder is only ever used
by one run (`run_common._setup_state`), so nothing needs to outlive the process.

The behaviour stays with each concern's own module, which takes the state first:
`budget_enforcer` (counting, the oracle clock), `circuit_breaker` (charging, the trip) and
`record_query` (the row append, the seq, the repeat note). Each does its read-modify-write under
the state's one `lock`. Outside readers take the budget and breaker snapshots, which are copies,
and the row accessors (`lead_rows`, `row_count`, `last_row`), which hand out the stored rows:
a row is never changed once recorded. Nothing process-wide refers to a state, so it lives
exactly as long as the run that holds it.
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
    lock; read them through the snapshots and the read accessors."""

    def __init__(self, run_dir: Path, run_id: str) -> None:
        #: The folder the run was started on, as spelled.
        self.run_dir = Path(run_dir)
        self.run_id = run_id
        #: Serialises every read-modify-write: a cap check and its increment, a breaker charge,
        #: a row append (its seq, payload sidecar, record and table line). Reentrant, because
        #: the row append allocates its seq through the same reader everything else uses.
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
        #: `record_query`: call identity and the next number, owned by this run alone.
        self.call_run = run_id
        self.call_number = 0
        #: `budget_enforcer`: the seconds closed oracle turns held the world, and the
        #: `time.monotonic()` start of the turn open now.
        self.oracle_credited = 0.0
        self.oracle_opened: float | None = None

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

    def breaker_failures(self, system: str) -> int:
        """The failures charged to `system`'s breaker; 0 before any."""
        with self.lock:
            rec = self.breaker["systems"].get(system)
            return rec["failures"] if rec else 0

    def lead_rows(self, lead: str) -> tuple[dict, ...]:
        """`lead`'s rows as they stand, in append order; `()` for a lead with none.

        The stored rows themselves, not copies: a row is never changed once recorded (the
        writer records its own parsed copy, `inherit_rows` a copy of what it is handed), so a
        reader holds them read-only and one that needs a changed row copies it. The tuple is
        the rows as of this call; a later append does not reach it."""
        with self.lock:
            return tuple(self.rows.get(lead, ()))

    def row_count(self, lead: str) -> int:
        """How many rows `lead` holds, inherited ones included."""
        with self.lock:
            return len(self.rows.get(lead, ()))

    def last_row(self, lead: str) -> dict | None:
        """`lead`'s latest row (read-only, as `lead_rows`), or `None` when it holds none."""
        with self.lock:
            rows = self.rows.get(lead)
            return rows[-1] if rows else None

    def fork_counters(self) -> dict:
        """What a fork snapshot records of this state (#1255 P2, D2): the counters the model can
        feel — the budget's tool-call and spawn counts and the circuit breaker — as one
        JSON-shaped copy. `restore_fork_counters` is its inverse.

        @owns fork_counters"""
        with self.lock:
            return {"tool_calls": self.budget["tool_calls"],
                    "subagent_spawns": self.budget["subagent_spawns"],
                    "breaker": copy.deepcopy(self.breaker)}

    def restore_fork_counters(self, counters: dict) -> None:
        """Start a branch arm's state where its source's stood at the branch point: the
        counters `fork_counters` recorded there. A key missing from `counters` is a
        `KeyError` — a snapshot that does not carry a counter cannot restore it."""
        with self.lock:
            self.budget["tool_calls"] = int(counters["tool_calls"])
            self.budget["subagent_spawns"] = int(counters["subagent_spawns"])
            self.breaker = copy.deepcopy(counters["breaker"])

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
