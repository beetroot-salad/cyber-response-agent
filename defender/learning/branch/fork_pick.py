"""Where a learning job forks its source (#1344 O3): the candidates, and the pick among them.

A candidate is a response on the source run's MAIN path that called `gather`, and that the
branch admission each sibling run applies (`branch.admitted_points`: the capture required)
admits, so the pick never lands on a point the family cannot run from. Anything else MAIN did
(an `append_block`, an `echo`) was a legal operator fork point but is none for a job: a job's
family varies what a gather reads. The automatic correlation lead is no MAIN response, so it is
never a candidate.

A candidate the admission refuses (nothing open in the frontier, no fork snapshot, no query
captured by then, a snapshot current code cannot read) is dropped on its own; the rest stay.
The refusals' kinds are kept, each once (`BranchError.kind`: a fixed name in our own words, never the refusal's text, which carries
host paths), for the job's `no_fork_point` message, which a person reads.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.investigation import branch
from defender.records import Run

__all__ = ["UNNAMED_REFUSAL", "ForkCandidates", "fork_candidates", "pick_fork"]


#: The kind of an admission refusal raised without one (`BranchError.kind` is `None`).
UNNAMED_REFUSAL = "a refusal with no kind"


@dataclass(frozen=True)
class ForkCandidates:
    """The admitted fork points, in MAIN's path order, and the distinct kinds of the dropped
    ones' refusals, in the order first met."""

    ids: list[int] = field(default_factory=list)
    refusal_kinds: tuple[str, ...] = ()


def _calls_gather(message: Any) -> bool:
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    return isinstance(message, ModelResponse) and any(
        isinstance(part, ToolCallPart) and part.tool_name == "gather" for part in message.parts)


def fork_candidates(store: Any, run: Run) -> ForkCandidates:
    """Every response on `run`'s MAIN path in `store` that called `gather` and that a sibling's
    own branch admission admits (`branch.admitted_points`: a point with no captured query is
    refused, as each sibling refuses it), the session read once for all of them. A store-format
    refusal is not caught: it is the job's `history_unreadable`, decided by the caller."""
    run_dir = Path(run.run_dir)
    main = branch.MainRead(store, run_dir, source_run=run)
    gathers = [row_id for row_id, message in zip(main.path, main.prefix, strict=True) if _calls_gather(message)]
    admitted: list[int] = []
    kinds: dict[str, None] = {}
    for row_id, refused in branch.admitted_points(main, run_dir, gathers, source_run=run):
        if refused is not None:
            kinds.setdefault(refused.kind or UNNAMED_REFUSAL)
            continue
        admitted.append(row_id)
    return ForkCandidates(admitted, tuple(kinds))


def pick_fork(ids: list[int], *, rng: random.Random | None = None) -> int:
    """One of `ids`, uniformly. `ids` must not be empty: no candidate is the caller's
    `no_fork_point`."""
    if not ids:
        raise ValueError("no fork candidate to pick from")
    return (rng if rng is not None else random.SystemRandom()).choice(list(ids))
