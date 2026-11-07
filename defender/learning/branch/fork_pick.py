"""Where a learning job forks its source (#1344 O3): the candidates, and the pick among them.

A candidate is a response on the source run's MAIN path that called `gather`, and that the
branch admission an operator's launch applies (`branch.validate`, as the launcher's own branch
point check calls it) admits. Anything else MAIN did (an `append_block`, an `echo`) was a legal
operator fork point but is none for a job: a job's family varies what a gather reads. The
automatic correlation lead is no MAIN response, so it is never a candidate.

A candidate the admission refuses (nothing open in the frontier, no fork snapshot, a snapshot
current code cannot read) is dropped on its own; the rest stay. The last refusal's text is kept
for the job's `no_fork_point` message, which a person reads.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.investigation import branch
from defender.records import Run, session_store

__all__ = ["ForkCandidates", "fork_candidates", "pick_fork"]


@dataclass(frozen=True)
class ForkCandidates:
    """The admitted fork points, in MAIN's path order, and the last refusal of a dropped one."""

    ids: list[int] = field(default_factory=list)
    last_refusal: str | None = None


def _calls_gather(message: Any) -> bool:
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    return isinstance(message, ModelResponse) and any(
        isinstance(part, ToolCallPart) and part.tool_name == "gather" for part in message.parts)


def fork_candidates(store: Any, run: Run) -> ForkCandidates:
    """Every response on `run`'s MAIN path in `store` that called `gather` and that the launcher's
    branch admission admits. A store-format refusal is not caught: it is the job's
    `history_unreadable`, decided by the caller."""
    run_dir = Path(run.run_dir)
    session = branch.session_for_run(store, run_dir, source_run=run)
    ids = session_store.path_row_ids(store, session)
    messages = session_store.hydrate(store, session, role="analysis")
    admitted: list[int] = []
    last_refusal: str | None = None
    for row_id, message in zip(ids, messages, strict=True):
        if not _calls_gather(message):
            continue
        try:
            as_of = branch.branch_point_time(store, run_dir, row_id, source_run=run)
            branch.validate(store, branch.BranchSpec(
                source_run_dir=run_dir, branch_message_id=row_id, as_of=as_of),
                source_run=run, require_capture=False)
        except branch.BranchError as refused:
            last_refusal = f"message {row_id}: {refused}"
            continue
        admitted.append(row_id)
    return ForkCandidates(admitted, last_refusal)


def pick_fork(ids: list[int], *, rng: random.Random | None = None) -> int:
    """One of `ids`, uniformly. `ids` must not be empty: no candidate is the caller's
    `no_fork_point`."""
    if not ids:
        raise ValueError("no fork candidate to pick from")
    return (rng if rng is not None else random.SystemRandom()).choice(list(ids))
