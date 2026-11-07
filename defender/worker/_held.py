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
    `cost_so_far`: the last figure the cost task read for the row; the renewal copies it."""

    record: Any
    proc: asyncio.subprocess.Process | None = None
    fenced: bool = False
    signalled: bool = False
    cost_so_far: float | None = None
    #: Set only by the final read after the child ended: that read found the run's cost exact (its
    #: job-end record says no spend write failed, or the run never opened its store). Everything
    #: else a child leaves behind is "at least" (#1377 S2); `Held.lower_limit` is the one rule.
    read_exact: bool = False
    #: The fence's ender tasks, held so the event loop's weak reference is not their only one.
    enders: list[asyncio.Task[None]] = field(default_factory=list)

    def lower_limit(self, cost: float | None) -> bool:
        """Whether the figure the holder writes is only a lower limit (#1377 S2): a child ran, the
        figure is known, and the final read did not find it exact. A row nothing launched is
        exactly 0, and an unknown cost is never marked (S4)."""
        return self.proc is not None and cost is not None and not self.read_exact


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

