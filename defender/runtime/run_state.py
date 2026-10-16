"""One run's live decision state, held by the run's own process (#1235).

`run_investigation` resolves one `RunState` at its boundary — the one its caller hands it, or a
new one for its own folder and run id — before lead-0 and before any tool call, and carries it
by reference: on MAIN's `AgentDeps` (every gather lead's deps hold the same object), on lead-0's
capture deps, and on each `VerbContext` the query tool and lead-0 build. It holds what the run
decides on while it runs:

  * the run clock (#1255) — the host-owned source every model-visible time is read from
    (`run_clock.RunClock`), its origin, and the reading `now()` the run's stamps take;
  * the budget — the tool-call and spawn counters and the clock's origin;
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
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .._clock import now_iso
from .run_clock import ClockSource, RunClock


class RunState:
    """The live state of the run started on `run_dir` as `run_id` (see the module docstring).

    The fields below `lock` belong to the modules named beside them and change only under the
    lock; read them through the snapshots and the read accessors."""

    def __init__(self, run_dir: Path, run_id: str, *, clock: ClockSource | None = None) -> None:
        #: The folder the run was started on, as spelled.
        self.run_dir = Path(run_dir)
        self.run_id = run_id
        #: Serialises every read-modify-write: a cap check and its increment, a breaker charge,
        #: a row append (its seq, payload sidecar, record and table line). Reentrant, because
        #: the row append allocates its seq through the same reader everything else uses.
        self.lock = threading.RLock()
        #: The run clock's source (#1255): the host's (wall anchor, monotonic progress) unless
        #: one is injected (`clock=`, or `attach_clock` at `run_investigation`'s boundary).
        self.clock = RunClock(clock)
        #: `budget_enforcer`: the counters. `created_at`/`started_at` name the run clock's
        #: reading at the run's start (its origin), as ISO text.
        self.budget: dict = {
            "run_id": run_id,
            "tool_calls": 0,
            "subagent_spawns": 0,
        }
        #: The run clock's tick at which the run's elapsed time is zero (`elapsed`), in the
        #: clock's own tick domain (`RunClock.ticks`: `time.monotonic()` for the host's clock).
        self.started_monotonic = 0.0
        #: The run clock's reading at elapsed zero (aware UTC); set with the tick origin.
        self.origin: datetime
        #: `budget_enforcer`: the seconds closed oracle turns held the world, and the run
        #: clock's tick (`clock.ticks()`) at the start of the turn open now. The run clock is
        #: paused for both: they are subtracted from every reading (`elapsed`, `now`).
        self.oracle_credited = 0.0
        self.oracle_opened: float | None = None
        self._start_at(self.clock.ticks(), elapsed=0.0)
        #: `circuit_breaker`: `{"systems": {name: {"failures": n, "tripped_at"?: iso}},
        #: "total_failures": n}`.
        self.breaker: dict = {"systems": {}, "total_failures": 0}
        #: `record_query`: each lead's rows, in append order (an inherited prefix first).
        self.rows: dict[str, list[dict]] = {}
        #: `record_query`: call identity and the next number, owned by this run alone.
        self.call_run = run_id
        self.call_number = 0

    # -- the run clock (#1255) -------------------------------------------------------------

    def _start_at(self, tick: float, *, elapsed: float, reading: datetime | None = None) -> None:
        """Put elapsed time at `elapsed` as of the clock's `tick`, with no oracle credit, the
        clock reading `reading` there (default: the source's own reading at `tick`), and stamp
        the origin that implies. Call under `lock` (or from `__init__`)."""
        self.started_monotonic = tick - elapsed
        self.oracle_credited = 0.0
        self.oracle_opened = None
        at = self.clock.at(tick) if reading is None else reading
        self.origin = at - timedelta(seconds=elapsed)
        stamp = self.origin.isoformat()
        self.budget["created_at"] = self.budget["started_at"] = stamp

    def attach_clock(self, source: ClockSource) -> None:
        """Run on `source` from now: the run clock's source injected at `run_investigation`'s
        boundary, before anything has read the clock. Elapsed restarts at zero at the source's
        current reading. `ValueError` once a source has been injected: two sources for one run
        would give it two times."""
        with self.lock:
            if self.clock.injected:
                raise ValueError(f"run {self.run_id!r} already runs on an injected clock")
            self.clock = RunClock(source)
            self._start_at(self.clock.ticks(), elapsed=0.0)

    def resume_clock(self, reading: datetime, elapsed: float) -> None:
        """Continue a run clock that stood at `reading` having measured `elapsed` seconds — an
        arm's start from its source's fork snapshot (#1255 P2: "on an arm it starts at the
        source's reading in the fork snapshot"). From here the clock advances by this run's own
        source; its origin is `reading - elapsed`, so the budget's wall-clock limb counts on
        from where the source stood (D2)."""
        if reading.utcoffset() is None:
            raise ValueError(f"a run clock reading must be aware UTC: {reading!r}")
        if elapsed < 0:
            raise ValueError(f"a run clock's elapsed time cannot be negative: {elapsed!r}")
        with self.lock:
            self._start_at(self.clock.ticks(), elapsed=elapsed, reading=reading.astimezone(UTC))

    def oracle_held_at(self, tick: float) -> float:
        """The seconds oracle turns held the world as of the clock's `tick`: the closed turns'
        credit plus the turn open now. Call under `lock`.

        @owns oracle_held"""
        held = self.oracle_credited
        if self.oracle_opened is not None:
            held += max(0.0, tick - self.oracle_opened)
        return held

    def elapsed(self) -> float:
        """The run's elapsed seconds on its run clock: the clock's progress since the origin,
        less the seconds oracle turns held the world. Never decreases: the clock's ticks never
        do, and a held second is subtracted exactly as the tick that counted it.

        @owns elapsed"""
        with self.lock:
            tick = self.clock.ticks()
            return tick - self.started_monotonic - self.oracle_held_at(tick)

    def now(self) -> datetime:
        """The run clock's reading (aware UTC): the origin plus `elapsed`. Every time the
        model can see is one of these."""
        with self.lock:
            return self.origin + timedelta(seconds=self.elapsed())

    def now_iso(self) -> str:
        """`now()` as ISO-8601 text, whole seconds (the `_clock.now_iso` spelling)."""
        return self.now().isoformat(timespec="seconds")

    # -- read accessors ----------------------------------------------------------------------

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


def run_time_iso(holder: Any) -> str:
    """The time a record written for `holder` (a role's deps) is stamped with, as ISO-8601
    whole seconds: the run clock's reading (`RunState.now_iso`) when the deps belong to a run;
    the host's wall clock when they carry no run state — a writer reached outside any run has
    no run clock (#1255 rev 5 C4)."""
    state = getattr(holder, "run_state", None)
    return state.now_iso() if state is not None else now_iso()
