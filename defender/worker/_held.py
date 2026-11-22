"""What a worker keeps for each row it holds (#1343)."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any


#: What a held entry runs: an investigation, a learning job's family step, or the post-step that
#: follows one (#1344). A post-step holds no row: it has no lease to renew and nothing to fence.
INVESTIGATION, LEARNING, POST_STEP = "investigation", "learning", "post_step"
#: A host request (#1471, #1546 D7): a readiness check, an adoption or a drain, claimed from its own pool
#: (`host_request_slots`).
HOST_REQUEST = "host_request"


@dataclass
class Held:
    """One entry of the worker's one supervision registry: a row this worker holds, from its claim
    until its last write has landed (B-P2), or a post-step child (#1344 O8, O9).

    `token`: the claim's token, minted by the store in the claim's own transaction (#1546 PR7): the child is handed it
    (`box.CLAIM_ENV`), its folders are named by it, and the row's end is decided from what its helper staged under it.
    `fenced`: a renewal that succeeded omitted the row, so it was cancelled, taken over or
    deleted. `signalled`: a deliberate stop signalled this entry's child while it was alive.
    `cost_so_far`: the cost of the last `progress` its helper staged, for an investigation; `progress`: a learning
    job's last staged progress. The renewal copies either. A post-step's
    `check_holder` is renewed with the rows' leases, and a renewal that omits it fences it too.
    `group_left`: a wait for the child's killed group ran out with a member still running; no
    later cleanup waits for that group again (the stop stays bounded by one grace)."""

    record: Any
    kind: str = INVESTIGATION
    token: str | None = None
    proc: asyncio.subprocess.Process | None = None
    fenced: bool = False
    signalled: bool = False
    cost_so_far: float | None = None
    progress: Any = None
    #: A post-step's hold on its tenant's check clock (#1344 amendment 3): the token the
    #: renewal extends it by (the post-step's claim token, #1546 PR7). None for a row.
    check_holder: str | None = None
    #: A post-step the worker ended because it ran past `post_step_limit` (#1487 Amendment r5.4).
    overran: bool = False
    group_left: bool = False
    #: The fence's ender tasks, held so the event loop's weak reference is not their only one.
    enders: list[asyncio.Task[None]] = field(default_factory=list)

    @property
    def leased(self) -> bool:
        """Whether a row's lease is this entry's to renew."""
        return self.kind != POST_STEP


@dataclass(frozen=True)
class StagedProgress:
    """A learning job's last staged `progress` fact (#1546 PR2: the helper typed it), as the renewal copies it onto the
    running row (`jobs.LearningProgress`)."""

    fork_message_id: str | None
    stage: str | None
    sibling_cost_usd: float
