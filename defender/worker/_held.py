"""What a worker keeps for each row it holds, and what it writes last (#1343)."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any


#: What a held entry runs: an investigation, a learning job's family step, or the post-step that
#: follows one (#1344). A post-step holds no row: it has no lease to renew and nothing to fence.
INVESTIGATION, LEARNING, POST_STEP = "investigation", "learning", "post_step"


@dataclass
class Held:
    """One entry of the worker's one supervision registry: a row this worker holds, from its claim
    until its last write has landed (B-P2), or a post-step child (#1344 O8, O9).

    `fenced`: a renewal that succeeded omitted the row, so it was cancelled, taken over or
    deleted. `signalled`: a deliberate stop signalled this entry's child while it was alive.
    `cost_so_far`: the last figure the cost task read for an investigation; `progress`: the last
    progress record read for a learning job. The renewal copies either. A post-step's
    `check_holder` is renewed with the rows' leases, and a renewal that omits it fences it too.
    `group_left`: a wait for the child's killed group ran out with a member still running; no
    later cleanup waits for that group again (the stop stays bounded by one grace)."""

    record: Any
    kind: str = INVESTIGATION
    proc: asyncio.subprocess.Process | None = None
    fenced: bool = False
    signalled: bool = False
    cost_so_far: float | None = None
    #: Set only by the final read after the child ended: that read found the run's cost exact (its
    #: ledger read complete, or the run never opened its store; #1377 r7.3 T2). Everything else a
    #: child leaves behind is "at least" (#1377 S2); `Held.lower_limit` is the one rule.
    read_exact: bool = False
    progress: Any = None
    #: A post-step's hold on its tenant's check clock (#1344 amendment 3): the token the
    #: renewal extends it by. None for a row, and for a post-step that holds nothing yet.
    check_holder: str | None = None
    group_left: bool = False
    #: The fence's ender tasks, held so the event loop's weak reference is not their only one.
    enders: list[asyncio.Task[None]] = field(default_factory=list)

    def lower_limit(self, cost: float | None) -> bool:
        """Whether the figure the holder writes is only a lower limit (#1377 S2): a child ran, the
        figure is known, and the final read did not find it exact. A row nothing launched is
        exactly 0, and an unknown cost is never marked (S4)."""
        return self.proc is not None and cost is not None and not self.read_exact

    @property
    def leased(self) -> bool:
        """Whether a row's lease is this entry's to renew."""
        return self.kind != POST_STEP


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


@dataclass(frozen=True)
class LearningOutcome:
    """What a learning job's holder writes last (#1344): the terminal `status` with its `reason`
    and `message`, or, `status` None, the row handed back. `progress` is the final fork pick,
    stage and sibling cost (None keeps what the row was last given)."""

    status: str | None
    reason: str | None = None
    message: str | None = None
    progress: Any = None
    findings_count: int = 0
