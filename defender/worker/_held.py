"""What a worker keeps for each row it holds, and what it writes last (#1343)."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Held:
    """One row this worker holds, from its claim until its last write has landed (B-P2).

    `fenced`: a renewal that succeeded omitted the row, so it was cancelled, taken over or
    deleted. `signalled`: a deliberate stop signalled this row's child while it was alive.
    `cost_so_far`: the last figure the cost task read for the row; the renewal copies it.
    `lease_until`: when the row's lease runs out by this worker's own clock, counted from the start
    of the last store call that extended it. `lease_lost`: that time passed with no renewal landing,
    so the row's child was stopped; its row is handed back once the store answers."""

    record: Any
    lease_until: float = 0.0
    proc: asyncio.subprocess.Process | None = None
    fenced: bool = False
    signalled: bool = False
    lease_lost: bool = False
    cost_so_far: float | None = None
    #: The fence's ender tasks, held so the event loop's weak reference is not their only one.
    enders: list[asyncio.Task[None]] = field(default_factory=list)


@dataclass(frozen=True)
class Ending:
    """The terminal write for one row."""

    stage: str
    disposition: str | None = None
    failure_reason: str | None = None
    failure_message: str | None = None
    #: The run's own job-end record decided this ending (a report committed and scrubbed, or setup
    #: refused): a stop that lands meanwhile cannot have caused it, so it is recorded, not handed back.
    decided_by_run: bool = False


@dataclass(frozen=True)
class End:
    """What a row's holder writes last: the decided ending (`ending`), or the row handed back
    (`ending` None) when a deliberate stop ended its child. Either way carries the final cost
    (None when unknown) and knowledge."""

    ending: Ending | None
    cost: float | None
    knowledge: dict | None
